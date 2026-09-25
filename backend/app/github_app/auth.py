"""Short-lived GitHub App credentials and OAuth PKCE helpers.

Tokens are returned to a single caller and are never written to RepoLens storage.
Installation tokens are scoped to one repository and an explicit minimal permission
map before they enter the bounded in-process cache.
"""

from __future__ import annotations

import asyncio
import base64
from collections import OrderedDict
from datetime import datetime, timezone
import re
import secrets
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt

from app.core.config import Settings, get_settings

API_ROOT = "https://api.github.com"
OAUTH_ROOT = "https://github.com"
API_VERSION = "2022-11-28"
_ID_RE = re.compile(r"^[1-9][0-9]{0,18}$")
_ALLOWED_PERMISSIONS = {
    "contents": {"read"},
    "pull_requests": {"read", "write"},
}
PERMISSION_PROFILES: dict[str, dict[str, str]] = {
    "contents_read": {"contents": "read"},
    "pull_requests_read": {"pull_requests": "read"},
    "pull_requests_write": {"pull_requests": "write"},
}


class GitHubAppError(RuntimeError):
    """Safe, non-sensitive GitHub App integration failure."""


def permission_requirements(permission_profile: str) -> dict[str, str]:
    """Return the closed minimum grant required by an operation profile."""
    requirements = PERMISSION_PROFILES.get(permission_profile)
    if requirements is None:
        raise GitHubAppError("Requested GitHub App permission profile is outside RepoLens policy.")
    return dict(requirements)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _positive_id(value: str | int, label: str) -> str:
    normalized = str(value)
    if not _ID_RE.fullmatch(normalized) or int(normalized) > 9_223_372_036_854_775_807:
        raise GitHubAppError(f"Invalid {label}.")
    return normalized


def create_app_jwt(settings: Settings | None = None, *, now: int | None = None) -> str:
    """Create an RS256 app JWT with the short lifetime required by GitHub."""
    cfg = settings or get_settings()
    if not cfg.GITHUB_APP_ENABLED:
        raise GitHubAppError("GitHub App integration is disabled.")
    issued = int(time.time()) if now is None else int(now)
    claims = {"iat": issued - 60, "exp": issued + 540, "iss": cfg.GITHUB_APP_ID}
    try:
        token = jwt.encode(
            claims,
            cfg.GITHUB_APP_PRIVATE_KEY_PEM,
            algorithm="RS256",
            headers={"typ": "JWT"},
        )
    except Exception as exc:
        raise GitHubAppError("Could not create GitHub App authentication.") from exc
    return token


def encrypt_oauth_verifier(verifier: str, settings: Settings | None = None) -> str:
    cfg = settings or get_settings()
    try:
        key = bytes.fromhex(cfg.GITHUB_APP_STATE_ENCRYPTION_KEY)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, verifier.encode("ascii"), b"repolens-github-app-oauth-v1")
        return _b64url(nonce + ciphertext)
    except Exception as exc:
        raise GitHubAppError("Could not protect the OAuth transaction state.") from exc


def decrypt_oauth_verifier(ciphertext: str, settings: Settings | None = None) -> str:
    cfg = settings or get_settings()
    try:
        packed = base64.urlsafe_b64decode(ciphertext + "=" * (-len(ciphertext) % 4))
        if len(packed) < 29:
            raise ValueError("ciphertext too short")
        key = bytes.fromhex(cfg.GITHUB_APP_STATE_ENCRYPTION_KEY)
        return AESGCM(key).decrypt(packed[:12], packed[12:], b"repolens-github-app-oauth-v1").decode("ascii")
    except Exception as exc:
        raise GitHubAppError("OAuth transaction state is invalid or expired.") from exc


class GitHubAppTokenService:
    """Bounded process-local installation token cache and OAuth exchange client."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        cache_limit: int = 128,
    ) -> None:
        self.settings = settings or get_settings()
        self.client = client
        self.cache_limit = max(1, min(int(cache_limit), 512))
        self._cache: OrderedDict[tuple[str, str, tuple[tuple[str, str], ...]], tuple[str, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    def invalidate_installation(self, installation_id: str | int) -> None:
        """Drop cached credentials after a signed suspend/delete/repository-removal event."""
        normalized = str(installation_id)
        for key in tuple(self._cache):
            if key[0] == normalized:
                self._cache.pop(key, None)

    def invalidate_repository(self, installation_id: str | int, repository_id: str | int) -> None:
        normalized_installation = str(installation_id)
        normalized_repository = str(repository_id)
        for key in tuple(self._cache):
            if key[0] == normalized_installation and key[1] == normalized_repository:
                self._cache.pop(key, None)

    async def installation_token(
        self,
        installation_id: str | int,
        repository_id: str | int,
        *,
        permission_profile: str = "contents_read",
    ) -> str:
        installation = _positive_id(installation_id, "installation ID")
        repository = _positive_id(repository_id, "repository ID")
        permissions = permission_requirements(permission_profile)
        key = (installation, repository, tuple(sorted(permissions.items())))
        async with self._lock:
            cached = self._cache.get(key)
            if cached and cached[1] > time.monotonic() + 60:
                self._cache.move_to_end(key)
                return cached[0]
            token, expires_in = await self._create_installation_token(installation, repository, permissions)
            self._cache[key] = (token, time.monotonic() + expires_in)
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_limit:
                self._cache.popitem(last=False)
            return token

    async def _create_installation_token(
        self,
        installation_id: str,
        repository_id: str,
        permissions: dict[str, str],
    ) -> tuple[str, float]:
        if not self.settings.GITHUB_APP_ENABLED:
            raise GitHubAppError("GitHub App integration is disabled.")
        if any(name not in _ALLOWED_PERMISSIONS or level not in _ALLOWED_PERMISSIONS[name] for name, level in permissions.items()):
            raise GitHubAppError("Requested GitHub App permission is outside RepoLens policy.")
        jwt = create_app_jwt(self.settings)
        path = f"/app/installations/{installation_id}/access_tokens"
        request = {
            "repository_ids": [int(repository_id)],
            "permissions": permissions,
        }
        owns_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=self.settings.GITHUB_APP_TOKEN_TIMEOUT_SECONDS)
        try:
            response = await client.post(
                API_ROOT + path,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {jwt}",
                    "X-GitHub-Api-Version": API_VERSION,
                    "User-Agent": "RepoLens-GitHub-App/1.0",
                },
                json=request,
            )
            if response.status_code != 201:
                raise GitHubAppError("GitHub installation token request was rejected.")
            try:
                data = response.json()
                token = data["token"]
                expires_at = datetime.fromisoformat(str(data["expires_at"]).replace("Z", "+00:00"))
                granted_permissions = data["permissions"]
                granted_repositories = data.get("repositories")
            except Exception as exc:
                raise GitHubAppError("GitHub returned an invalid installation token response.") from exc
            if not isinstance(token, str) or not token or any(ch in token for ch in "\r\n\x00"):
                raise GitHubAppError("GitHub returned an invalid installation token.")
            expected_permissions = dict(permissions)
            with_metadata = {**expected_permissions, "metadata": "read"}
            if not isinstance(granted_permissions, dict) or granted_permissions not in (expected_permissions, with_metadata):
                raise GitHubAppError("GitHub returned an unexpected installation permission profile.")
            if (
                not isinstance(granted_repositories, list)
                or len(granted_repositories) != 1
                or not isinstance(granted_repositories[0], dict)
                or str(granted_repositories[0].get("id")) != repository_id
            ):
                raise GitHubAppError("GitHub token is not scoped to the authorized repository.")
            seconds = (expires_at - datetime.now(timezone.utc)).total_seconds()
            if seconds <= 60 or seconds > 3700:
                raise GitHubAppError("GitHub returned an invalid installation token lifetime.")
            return token, seconds
        except httpx.HTTPError as exc:
            raise GitHubAppError("GitHub installation token service is unavailable.") from exc
        finally:
            if owns_client:
                await client.aclose()

    async def exchange_oauth_code(self, code: str, verifier: str) -> str:
        if not self.settings.GITHUB_APP_ENABLED:
            raise GitHubAppError("GitHub App integration is disabled.")
        if not isinstance(code, str) or not 1 <= len(code) <= 512 or any(c in code for c in "\r\n\x00"):
            raise GitHubAppError("OAuth authorization code is invalid.")
        owns_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=self.settings.GITHUB_APP_TOKEN_TIMEOUT_SECONDS)
        try:
            response = await client.post(
                OAUTH_ROOT + "/login/oauth/access_token",
                headers={"Accept": "application/json", "User-Agent": "RepoLens-GitHub-App/1.0"},
                data={
                    "client_id": self.settings.GITHUB_APP_CLIENT_ID,
                    "client_secret": self.settings.GITHUB_APP_CLIENT_SECRET,
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": self.settings.GITHUB_APP_CALLBACK_URL,
                },
            )
            if response.status_code != 200:
                raise GitHubAppError("GitHub OAuth exchange failed.")
            payload = response.json()
            token = payload.get("access_token") if isinstance(payload, dict) else None
            if not isinstance(token, str) or not token or any(ch in token for ch in "\r\n\x00"):
                raise GitHubAppError("GitHub OAuth response did not contain a valid access token.")
            return token
        except (httpx.HTTPError, ValueError) as exc:
            raise GitHubAppError("GitHub OAuth service is unavailable or returned invalid data.") from exc
        finally:
            if owns_client:
                await client.aclose()

    async def list_user_installations(self, user_token: str) -> list[dict[str, Any]]:
        """Read a bounded list of installations visible to the authenticated user."""
        owns_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=self.settings.GITHUB_APP_TOKEN_TIMEOUT_SECONDS)
        results: list[dict[str, Any]] = []
        try:
            for page in range(1, 11):
                response = await client.get(
                    API_ROOT + "/user/installations",
                    headers={
                        "Accept": "application/vnd.github+json",
                        "Authorization": f"Bearer {user_token}",
                        "X-GitHub-Api-Version": API_VERSION,
                        "User-Agent": "RepoLens-GitHub-App/1.0",
                    },
                    params={"per_page": 100, "page": page},
                )
                if response.status_code != 200:
                    raise GitHubAppError("Could not validate GitHub installation access for this user.")
                payload = response.json()
                rows = payload.get("installations") if isinstance(payload, dict) else None
                if not isinstance(rows, list):
                    raise GitHubAppError("GitHub returned an invalid installation list.")
                results.extend(row for row in rows if isinstance(row, dict))
                if len(rows) < 100:
                    return results
            raise GitHubAppError("The GitHub account has too many installations to validate safely.")
        except (httpx.HTTPError, ValueError) as exc:
            raise GitHubAppError("GitHub installation lookup failed.") from exc
        finally:
            if owns_client:
                await client.aclose()


_default_service: GitHubAppTokenService | None = None


def get_github_app_token_service() -> GitHubAppTokenService:
    global _default_service
    if _default_service is None:
        _default_service = GitHubAppTokenService()
    return _default_service
