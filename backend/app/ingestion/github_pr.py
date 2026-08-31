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
from app.delivery.github_client import GitHubAPIError, GitHubHttpTransport
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
    """Canonical read-only GitHub Pull Request metadata resolver composing GitHubHttpTransport."""

    def __init__(
        self,
        token: Optional[str] = None,
        settings: Optional[Settings] = None,
        client: Optional[httpx.AsyncClient] = None,
        transport: Optional[GitHubHttpTransport] = None,
    ):
        # Confused-deputy defense: Public PR reads are credential-free by default (token="")
        # and MUST NOT fall back to server ambient GITHUB_TOKEN.
        self._token = token if token is not None else ""
        if transport is not None:
            self.transport = transport
        else:
            self.transport = GitHubHttpTransport(
                token=self._token,
                settings=settings,
                client=client,
                user_agent="RepoLens-ChangeAnalysis/1.0.1",
            )

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
        path = f"repos/{owner}/{repo}/pulls/{pr_number}"

        try:
            data = await self.transport.request(method="GET", path=path, is_write=False)
        except GitHubAPIError as exc:
            status_code = exc.status_code
            msg = exc.message
            if status_code == 404:
                raise GitHubPRNotFoundError(
                    f"Pull request #{pr_number} on '{owner}/{repo}' not found, or repository is private."
                ) from exc
            elif status_code in (401, 403):
                if "rate limit" in msg.lower():
                    raise GitHubPRRateLimitError(f"GitHub API rate limit exceeded: {msg}") from exc
                raise GitHubPRForbiddenError(f"Access to GitHub PR #{pr_number} on '{owner}/{repo}' forbidden: {msg}") from exc
            elif status_code == 429:
                raise GitHubPRRateLimitError("GitHub API rate limit exceeded") from exc
            elif status_code == 504:
                raise GitHubPRTimeoutError(f"GitHub API request timed out while resolving pull request #{pr_number} on {owner}/{repo}") from exc
            elif status_code and status_code >= 500:
                raise GitHubPRAPIError(
                    f"GitHub API server error ({status_code}) while resolving PR #{pr_number} on '{owner}/{repo}'",
                    status_code=status_code,
                ) from exc
            else:
                raise GitHubPRAPIError(f"GitHub API error: {msg}", status_code=status_code or 502) from exc
        except Exception as exc:
            logger.error(f"Network error resolving GitHub PR {owner}/{repo}#{pr_number}: {str(exc)}")
            raise GitHubPRAPIError(f"Network error communicating with GitHub API: {str(exc)}") from exc

        if not isinstance(data, dict):
            raise GitHubPRAPIError(f"Malformed non-dictionary response returned by GitHub API for PR #{pr_number}")

        # 1. State validation (strict, no default "open")
        raw_state = data.get("state")
        if not raw_state or not str(raw_state).strip():
            raise GitHubPRAPIError(f"Missing state in GitHub PR #{pr_number} response")
        state = str(raw_state).strip().lower()
        if state not in ("open", "closed"):
            raise GitHubPRAPIError(f"Invalid state '{state}' in GitHub PR #{pr_number} response")

        # 2. Base and head info
        base_info = data.get("base")
        head_info = data.get("head")
        if not base_info or not isinstance(base_info, dict):
            raise GitHubPRAPIError(f"Missing base metadata in GitHub PR #{pr_number} response")
        if not head_info or not isinstance(head_info, dict):
            raise GitHubPRAPIError(f"Missing head metadata in GitHub PR #{pr_number} response")

        # Base and head repo dictionaries
        base_repo = base_info.get("repo")
        head_repo = head_info.get("repo")
        if not base_repo or not isinstance(base_repo, dict):
            raise GitHubPRAPIError(f"Missing base repository metadata in GitHub PR #{pr_number} response")
        if not head_repo or not isinstance(head_repo, dict):
            raise GitHubPRAPIError(f"Missing head repository metadata in GitHub PR #{pr_number} response")

        base_full_name = str(base_repo.get("full_name") or "").strip().lower()
        if not base_full_name and base_repo.get("html_url"):
            base_full_name = str(base_repo.get("html_url")).replace("https://github.com/", "").strip("/").lower()

        head_full_name = str(head_repo.get("full_name") or "").strip().lower()
        if not head_full_name and head_repo.get("html_url"):
            head_full_name = str(head_repo.get("html_url")).replace("https://github.com/", "").strip("/").lower()

        if not base_full_name:
            raise GitHubPRAPIError(f"Missing base repository full_name in GitHub PR #{pr_number} response")
        if not head_full_name:
            raise GitHubPRAPIError(f"Missing head repository full_name in GitHub PR #{pr_number} response")

        expected_base = f"{owner}/{repo}".lower()
        if base_full_name != expected_base:
            raise GitHubPRAPIError(f"Base repository full_name '{base_full_name}' does not match requested '{expected_base}'")

        is_fork = (head_full_name != base_full_name) or bool(head_repo.get("fork", False))
        head_repo_url = head_repo.get("html_url")

        # 3. Branch refs
        base_branch_raw = base_info.get("ref")
        if not base_branch_raw or not str(base_branch_raw).strip():
            raise GitHubPRAPIError(f"Missing or empty base branch ref in GitHub PR #{pr_number} response")
        base_branch = str(base_branch_raw).strip()

        head_branch_raw = head_info.get("ref")
        if not head_branch_raw or not str(head_branch_raw).strip():
            raise GitHubPRAPIError(f"Missing or empty head branch ref in GitHub PR #{pr_number} response")
        head_branch = str(head_branch_raw).strip()

        # 4. Commit SHAs
        base_sha = str(base_info.get("sha") or "").strip().lower()
        head_sha = str(head_info.get("sha") or "").strip().lower()
        if not re.match(r"^[0-9a-f]{40}$", base_sha):
            raise GitHubPRAPIError(f"Invalid or missing base commit SHA in GitHub PR response: '{base_sha}'")
        if not re.match(r"^[0-9a-f]{40}$", head_sha):
            raise GitHubPRAPIError(f"Invalid or missing head commit SHA in GitHub PR response: '{head_sha}'")

        title = str(data.get("title") or f"Pull Request #{pr_number}")
        canonical_repo_url = f"https://github.com/{owner}/{repo}"

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


_default_github_pr_resolver: Optional[GitHubPRResolver] = None


def get_github_pr_resolver() -> GitHubPRResolver:
    """Return singleton GitHubPRResolver instance."""
    global _default_github_pr_resolver
    if _default_github_pr_resolver is None:
        _default_github_pr_resolver = GitHubPRResolver()
    return _default_github_pr_resolver
