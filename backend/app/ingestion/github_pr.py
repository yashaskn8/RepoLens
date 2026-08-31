"""Canonical provider-neutral Public GitHub Pull Request Resolver.

Guarantees:
- Fixed trusted API origin (https://api.github.com) rejecting SSRF and host injection.
- Zero writes: strictly read-only HTTP GET operations (no reviews, comments, labels, branches, merges).
- No request-supplied tokens or URLs (uses server environment config only).
- Resolves exact, immutable 40-character commit SHAs for base and head revisions.
- Maps API error status codes into clear, typed domain exceptions.
"""

from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
import httpx

from app.core.config import Settings, get_settings
from app.schemas.change_analysis import ResolvedPullRequest, _normalize_and_validate_github_pr_url

logger = logging.getLogger(__name__)

# Fixed trusted GitHub API origin
GITHUB_API_BASE_URL = "https://api.github.com"


class GitHubPRError(Exception):
    """Base exception class for all GitHub PR resolution errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class InvalidPullRequestURLError(GitHubPRError):
    """Raised when pull request URL syntax or host is invalid."""

    def __init__(self, message: str):
        super().__init__(message, status_code=400)


class GitHubPRNotFoundError(GitHubPRError):
    """Raised when pull request is not found or repository is private (HTTP 404)."""

    def __init__(self, message: str):
        super().__init__(message, status_code=404)


class GitHubPRForbiddenError(GitHubPRError):
    """Raised when access to pull request is forbidden (HTTP 401/403)."""

    def __init__(self, message: str):
        super().__init__(message, status_code=403)


class GitHubPRRateLimitError(GitHubPRError):
    """Raised when GitHub API rate limits are exceeded (HTTP 429)."""

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class GitHubPRAPIError(GitHubPRError):
    """Raised when GitHub API returns unexpected 5xx or server errors."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message, status_code=status_code)


class GitHubPRTimeoutError(GitHubPRError):
    """Raised when GitHub API request times out."""

    def __init__(self, message: str):
        super().__init__(message, status_code=504)


class GitHubPRResolver:
    """Canonical read-only GitHub Pull Request metadata resolver."""

    def __init__(
        self,
        token: Optional[str] = None,
        settings: Optional[Settings] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        app_settings = settings or get_settings()
        self._token = token if token is not None else getattr(app_settings, "GITHUB_TOKEN", None)
        self._client = client
        self._timeout = httpx.Timeout(20.0, connect=10.0)

    def parse_pr_url(self, pr_url: str) -> Tuple[str, str, str, int]:
        """Validate and parse a GitHub PR URL into (canonical_url, owner, repo, pr_number)."""
        try:
            return _normalize_and_validate_github_pr_url(pr_url)
        except ValueError as exc:
            raise InvalidPullRequestURLError(str(exc))

    async def resolve_pr(self, pr_url: str) -> ResolvedPullRequest:
        """Fetch and resolve pull request metadata from public GitHub API.
        
        Guarantees strictly read-only GET operation and resolves immutable SHAs.
        """
        canonical_pr_url, owner, repo, pr_number = self.parse_pr_url(pr_url)
        api_endpoint = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}"

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RepoLens-ChangeAnalysis/0.1.0",
        }
        if self._token and len(self._token.strip()) > 0:
            headers["Authorization"] = f"Bearer {self._token.strip()}"

        try:
            if self._client:
                response = await self._client.get(api_endpoint, headers=headers, timeout=self._timeout)
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.get(api_endpoint, headers=headers)

        except (httpx.TimeoutException, TimeoutError) as exc:
            logger.warning(f"GitHub PR API timeout for {owner}/{repo}#{pr_number}: {str(exc)}")
            raise GitHubPRTimeoutError(f"GitHub API request timed out while resolving pull request #{pr_number} on {owner}/{repo}")
        except Exception as exc:
            logger.error(f"Network error resolving GitHub PR {owner}/{repo}#{pr_number}: {str(exc)}")
            raise GitHubPRAPIError(f"Network error communicating with GitHub API: {str(exc)}")

        # Handle HTTP error statuses
        status_code = response.status_code
        if status_code == 404:
            raise GitHubPRNotFoundError(
                f"Pull request #{pr_number} on '{owner}/{repo}' not found, or repository is private."
            )
        elif status_code in (401, 403):
            err_msg = self._extract_error_message(response)
            if "rate limit" in err_msg.lower():
                raise GitHubPRRateLimitError(f"GitHub API rate limit exceeded: {err_msg}")
            raise GitHubPRForbiddenError(f"Access to GitHub PR #{pr_number} on '{owner}/{repo}' forbidden: {err_msg}")
        elif status_code == 429:
            retry_after = response.headers.get("retry-after")
            sec = float(retry_after) if retry_after and retry_after.isdigit() else None
            raise GitHubPRRateLimitError(f"GitHub API rate limit exceeded", retry_after=sec)
        elif status_code >= 500:
            raise GitHubPRAPIError(
                f"GitHub API server error ({status_code}) while resolving PR #{pr_number} on '{owner}/{repo}'",
                status_code=status_code,
            )
        elif status_code != 200:
            err_msg = self._extract_error_message(response)
            raise GitHubPRAPIError(f"GitHub API error ({status_code}): {err_msg}", status_code=status_code)

        try:
            data = response.json()
        except Exception as exc:
            raise GitHubPRAPIError(f"Malformed JSON returned by GitHub API: {str(exc)}")

        # Extract and validate required immutable fields
        base_info = data.get("base", {})
        head_info = data.get("head", {})

        base_branch_raw = base_info.get("ref")
        if not base_branch_raw or not str(base_branch_raw).strip():
            raise GitHubPRAPIError(f"Missing or empty base branch ref in GitHub PR #{pr_number} response")
        base_branch = str(base_branch_raw).strip()
        base_sha = str(base_info.get("sha") or "").strip().lower()

        head_branch_raw = head_info.get("ref")
        if not head_branch_raw or not str(head_branch_raw).strip():
            raise GitHubPRAPIError(f"Missing or empty head branch ref in GitHub PR #{pr_number} response")
        head_branch = str(head_branch_raw).strip()
        head_sha = str(head_info.get("sha") or "").strip().lower()

        title = str(data.get("title") or f"Pull Request #{pr_number}")
        state = str(data.get("state") or "open")

        head_repo = head_info.get("repo")
        head_repo_url = head_repo.get("html_url") if head_repo else None
        is_fork = bool(head_repo and head_repo.get("fork", False))

        canonical_repo_url = f"https://github.com/{owner}/{repo}"

        if not re.match(r"^[0-9a-fA-F]{40}$", base_sha):
            raise GitHubPRAPIError(f"Invalid or missing base commit SHA in GitHub PR response: '{base_sha}'")
        if not re.match(r"^[0-9a-fA-F]{40}$", head_sha):
            raise GitHubPRAPIError(f"Invalid or missing head commit SHA in GitHub PR response: '{head_sha}'")

        return ResolvedPullRequest(
            repository_url=canonical_repo_url,
            repository_owner=owner,
            repository_name=repo,
            pr_number=pr_number,
            title=title,
            base_branch=base_branch,
            base_commit_sha=base_sha,
            head_branch=head_branch,
            head_commit_sha=head_sha,
            head_repo_url=head_repo_url,
            is_fork=is_fork,
            state=state,
        )

    def _extract_error_message(self, response: httpx.Response) -> str:
        try:
            body = response.json()
            return body.get("message") or response.text[:200]
        except Exception:
            return response.text[:200]


_default_github_pr_resolver: Optional[GitHubPRResolver] = None


def get_github_pr_resolver() -> GitHubPRResolver:
    """Return singleton GitHubPRResolver instance."""
    global _default_github_pr_resolver
    if _default_github_pr_resolver is None:
        _default_github_pr_resolver = GitHubPRResolver()
    return _default_github_pr_resolver
