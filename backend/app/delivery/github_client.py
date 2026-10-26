"""Canonical shared GitHub HTTP client and transport for RepoLens delivery and review publication.

Centralizes:
- Fixed trusted origin (https://api.github.com) preventing SSRF and arbitrary host injection.
- Secret redaction and credential handling with zero token exposure in logs or exceptions.
- Standard GitHub API version headers (2022-11-28).
- Bounded exponential backoff retries on read requests (max 3 attempts).
- ZERO blind retries on state-modifying write requests (max 1 attempt).
- Bounded timeout policies and normalized network/API error handling.
"""

import asyncio
import logging
from typing import Any, Dict, Optional
import httpx

from app.core.config import Settings, get_settings
from app.delivery.schemas import GitHubAPIError

logger = logging.getLogger(__name__)

# Fixed trusted GitHub API origin
GITHUB_API_BASE_URL = "https://api.github.com"


class GitHubHttpTransport:
    """Canonical HTTP transport for GitHub REST API interactions."""

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = GITHUB_API_BASE_URL,
        user_agent: str = "RepoLens-Delivery-Engine/1.0",
        settings: Optional[Settings] = None,
        client: Optional[httpx.AsyncClient] = None,
        timeout_seconds: float = 30.0,
        connect_timeout_seconds: float = 15.0,
    ):
        app_settings = settings or get_settings()
        self._token = token if token is not None else getattr(app_settings, "GITHUB_TOKEN", "")
        cleaned_url = (base_url or GITHUB_API_BASE_URL).rstrip("/")
        if cleaned_url != GITHUB_API_BASE_URL:
            raise ValueError(f"Untrusted API origin '{base_url}'. Only '{GITHUB_API_BASE_URL}' is supported.")
        self.base_url = GITHUB_API_BASE_URL
        self.user_agent = user_agent
        self._client = client
        self._timeout = httpx.Timeout(timeout_seconds, connect=connect_timeout_seconds)

    @property
    def token(self) -> str:
        """Return configured GitHub token."""
        return self._token or ""

    @property
    def has_credentials(self) -> bool:
        """Return True if non-empty GitHub token is configured."""
        return bool(self._token and len(self._token.strip()) > 0)

    def get_headers(self) -> Dict[str, str]:
        """Build safe HTTP headers for GitHub API requests without exposing tokens."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": self.user_agent,
        }
        if self._token and len(self._token.strip()) > 0:
            headers["Authorization"] = f"Bearer {self._token.strip()}"
        return headers

    async def request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        is_write: bool = False,
    ) -> Any:
        """Execute an HTTP request to the GitHub API with bounded read retries and zero write retries."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = self.get_headers()
        max_attempts = 1 if is_write else 3

        for attempt in range(1, max_attempts + 1):
            try:
                if self._client is not None:
                    if hasattr(self._client, "request"):
                        response = await self._client.request(
                            method=method,
                            url=url,
                            headers=headers,
                            json=json_data,
                            params=params,
                            timeout=self._timeout,
                        )
                    else:
                        method_lower = method.lower()
                        client_fn = getattr(self._client, method_lower, None)
                        if client_fn is not None:
                            kwargs = {"headers": headers, "timeout": self._timeout}
                            if params is not None:
                                kwargs["params"] = params
                            if json_data is not None and method_lower in ("post", "put", "patch"):
                                kwargs["json"] = json_data
                            response = await client_fn(url, **kwargs)
                        else:
                            raise RuntimeError(f"Client object does not support method '{method}' or 'request'")
                else:
                    async with httpx.AsyncClient(timeout=self._timeout) as client:
                        response = await client.request(
                            method=method,
                            url=url,
                            headers=headers,
                            json=json_data,
                            params=params,
                        )

                # Bounded exponential backoff retry on read rate limits / 5xx errors
                if not is_write and attempt < max_attempts and response.status_code in (429, 500, 502, 503, 504):
                    retry_after = response.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after and retry_after.isdigit() else (0.5 * (2 ** (attempt - 1)))
                    logger.warning(
                        f"GitHub API {method} {path} returned {response.status_code}. "
                        f"Retrying in {delay}s (attempt {attempt}/{max_attempts})"
                    )
                    await asyncio.sleep(min(delay, 5.0))
                    continue

                is_err = False
                status_code = getattr(response, "status_code", 200)
                if isinstance(status_code, int) and status_code >= 400:
                    is_err = True
                elif getattr(response, "is_error", False) is True:
                    is_err = True

                if is_err:
                    # GitHub/provider responses can echo caller-supplied secret
                    # text in arbitrary nested JSON fields. HTTP status is
                    # sufficient for error routing; never retain raw payloads
                    # or messages on an exception that reaches logs or clients.
                    # 403 rate-limit replies must remain distinguishable from
                    # authorization errors, but echoing the raw response is
                    # never needed to classify them.
                    rate_limited = response.status_code == 429
                    if response.status_code == 403:
                        remaining = response.headers.get("x-ratelimit-remaining")
                        rate_limited = remaining == "0"
                        if not rate_limited:
                            try:
                                data = response.json()
                                provider_message = data.get("message", "") if isinstance(data, dict) else ""
                                rate_limited = (
                                    isinstance(provider_message, str)
                                    and "rate limit" in provider_message.lower()
                                )
                            except (ValueError, TypeError):
                                rate_limited = False
                    message = (
                        "GitHub API rate limit exceeded."
                        if rate_limited
                        else f"GitHub API returned HTTP {response.status_code}."
                    )
                    raise GitHubAPIError(
                        message=message,
                        status_code=response.status_code,
                        response_data={},
                    )

                if response.status_code == 204:
                    return {}
                try:
                    return response.json()
                except ValueError:
                    raise GitHubAPIError(
                        "GitHub API returned invalid JSON.",
                        status_code=502,
                    ) from None

            except (httpx.TimeoutException, TimeoutError):
                if not is_write and attempt < max_attempts:
                    delay = 0.5 * (2 ** (attempt - 1))
                    logger.warning(
                        "GitHub API read timed out; retrying attempt %s/%s.",
                        attempt, max_attempts,
                    )
                    await asyncio.sleep(min(delay, 5.0))
                    continue
                raise GitHubAPIError(
                    "GitHub API request timed out.",
                    status_code=504,
                ) from None

            except httpx.RequestError:
                # Protocol errors (e.g. truncated HTTP responses) are request
                # failures too, not just NetworkError subclasses.
                if not is_write and attempt < max_attempts:
                    delay = 0.5 * (2 ** (attempt - 1))
                    logger.warning(
                        "GitHub API read transport failure; retrying attempt %s/%s.",
                        attempt, max_attempts,
                    )
                    await asyncio.sleep(min(delay, 5.0))
                    continue
                raise GitHubAPIError(
                    "GitHub API transport failure.",
                    status_code=502,
                ) from None
