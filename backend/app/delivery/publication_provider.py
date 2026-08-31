"""Provider abstraction for safe GitHub Pull Request Review publication.

Reuses canonical Phase 5 GitHub infrastructure:
- Fixed trusted origin (https://api.github.com) rejecting SSRF and arbitrary host injection.
- Secure token handling with zero persistence and log redaction.
- Standard GitHub API version headers.
- Zero blind retries on writes (max_attempts = 1).
- Bounded retries on reads.
- Strictly hardcoded review event = COMMENT.
"""

from abc import ABC, abstractmethod
import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import Settings, get_settings
from app.delivery.diff_mapper import GitHubDiffFile
from app.schemas.change_analysis import ResolvedPullRequest
from app.schemas.review_publication import (
    GitHubAuthFailedError,
    GitHubPRMetadataInvalidError,
    GitHubRateLimitedError,
    GitHubReviewCreateFailedError,
    GitHubReviewStateUncertainError,
    GitHubReviewWriteDisabledError,
    InlineReviewComment,
    PRClosedError,
    PRMergedError,
    PRNotFoundError,
    ReconciliationFailedError,
)
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)

# Fixed trusted GitHub API origin
GITHUB_API_BASE_URL = "https://api.github.com"


class PullRequestReviewPublicationProvider(ABC):
    """Abstract interface defining operations required for safe PR review publication."""

    @abstractmethod
    async def get_current_pull_request(self, owner: str, repo: str, pr_number: int) -> ResolvedPullRequest:
        """Fetch current pull request state and immutable commit SHAs from GitHub."""
        pass

    @abstractmethod
    async def get_pull_request_diff_files(self, owner: str, repo: str, pr_number: int) -> List[GitHubDiffFile]:
        """Fetch changed files and patch hunks for a pull request."""
        pass

    @abstractmethod
    async def create_comment_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        body: str,
        comments: Optional[List[InlineReviewComment]] = None,
    ) -> Dict[str, Any]:
        """Submit a COMMENT review to GitHub (strictly event='COMMENT', no approvals or request_changes)."""
        pass

    @abstractmethod
    async def list_pull_request_reviews(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        max_pages: int = 3,
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        """List pull request reviews with bounded pagination for deterministic reconciliation."""
        pass


class GitHubReviewPublicationProvider(PullRequestReviewPublicationProvider):
    """Concrete implementation communicating with GitHub REST API for review publication."""

    def __init__(
        self,
        token: Optional[str] = None,
        write_enabled: Optional[bool] = None,
        base_url: str = GITHUB_API_BASE_URL,
        settings: Optional[Settings] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        app_settings = settings or get_settings()
        self._token = token if token is not None else getattr(app_settings, "GITHUB_TOKEN", "")
        self._write_enabled = (
            write_enabled
            if write_enabled is not None
            else getattr(app_settings, "GITHUB_PR_REVIEW_WRITE_ENABLED", False)
        )
        cleaned_url = (base_url or GITHUB_API_BASE_URL).rstrip("/")
        if cleaned_url != GITHUB_API_BASE_URL:
            raise ValueError(f"Untrusted API origin '{base_url}'. Only '{GITHUB_API_BASE_URL}' is supported.")
        self.base_url = GITHUB_API_BASE_URL
        self._client = client
        self._timeout = httpx.Timeout(30.0, connect=15.0)

    @property
    def write_enabled(self) -> bool:
        """Return True if GitHub review writing is administratively enabled."""
        return bool(self._write_enabled)

    def _get_headers(self) -> Dict[str, str]:
        """Build safe HTTP headers without leaking tokens in logs."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "RepoLens-ReviewPublication-Engine/1.0",
        }
        if self._token and len(self._token.strip()) > 0:
            headers["Authorization"] = f"Bearer {self._token.strip()}"
        return headers

    def _redact_error(self, message: str) -> str:
        """Redact tokens and secrets from error messages."""
        return redact_secrets(message)

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        is_write: bool = False,
    ) -> Any:
        """Execute HTTP request to GitHub API with bounded read retries and ZERO write retries."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = self._get_headers()
        max_attempts = 1 if is_write else 3

        for attempt in range(1, max_attempts + 1):
            try:
                if self._client is not None:
                    response = await self._client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        json=json_data,
                        params=params,
                        timeout=self._timeout,
                    )
                else:
                    async with httpx.AsyncClient(timeout=self._timeout) as client:
                        response = await client.request(
                            method=method,
                            url=url,
                            headers=headers,
                            json=json_data,
                            params=params,
                        )

            except (httpx.TimeoutException, TimeoutError) as exc:
                if is_write:
                    # Outcome uncertain: GitHub may or may not have received and processed write
                    raise GitHubReviewStateUncertainError(
                        f"Network timeout during write operation on {path}. Outcome uncertain; reconciliation required."
                    )
                if attempt == max_attempts:
                    raise GitHubReviewCreateFailedError(f"GitHub API read timeout on {path}")
                await asyncio.sleep(0.5 * (2 ** (attempt - 1)))
                continue

            except Exception as exc:
                err_clean = self._redact_error(str(exc))
                if is_write:
                    raise GitHubReviewStateUncertainError(
                        f"Network exception during write operation on {path}: {err_clean}. Outcome uncertain; reconciliation required."
                    )
                if attempt == max_attempts:
                    raise GitHubReviewCreateFailedError(f"Network error communicating with GitHub API: {err_clean}")
                await asyncio.sleep(0.5 * (2 ** (attempt - 1)))
                continue

            # Handle HTTP status codes
            status = response.status_code
            if status in (200, 201):
                return response.json()
            elif status == 404:
                raise PRNotFoundError(f"Resource not found on GitHub: {path}")
            elif status in (401, 403):
                err_msg = self._redact_error(response.text)
                if "rate limit" in err_msg.lower():
                    raise GitHubRateLimitedError(f"GitHub API rate limit exceeded: {err_msg}")
                raise GitHubAuthFailedError(f"GitHub authentication or authorization failed: {err_msg}")
            elif status == 429:
                raise GitHubRateLimitedError("GitHub API rate limit exceeded")
            else:
                err_msg = self._redact_error(response.text)
                raise GitHubReviewCreateFailedError(
                    f"GitHub API returned error ({status}) on {path}: {err_msg}"
                )

    async def get_current_pull_request(self, owner: str, repo: str, pr_number: int) -> ResolvedPullRequest:
        """Fetch current pull request state and immutable commit SHAs from GitHub."""
        data = await self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}", is_write=False)
        head_data = data.get("head") if isinstance(data.get("head"), dict) else {}
        base_data = data.get("base") if isinstance(data.get("base"), dict) else {}

        # Validate base.ref
        base_ref = base_data.get("ref")
        if not base_ref or not isinstance(base_ref, str) or not base_ref.strip():
            raise GitHubPRMetadataInvalidError(f"GitHub PR response missing valid base.ref on PR #{pr_number}")

        # Validate head.ref
        head_ref = head_data.get("ref")
        if not head_ref or not isinstance(head_ref, str) or not head_ref.strip():
            raise GitHubPRMetadataInvalidError(f"GitHub PR response missing valid head.ref on PR #{pr_number}")

        # Validate base.sha (must be 40-char hex)
        base_sha = base_data.get("sha")
        if not base_sha or not isinstance(base_sha, str) or len(base_sha) != 40 or not all(c in "0123456789abcdefABCDEF" for c in base_sha):
            raise GitHubPRMetadataInvalidError(f"GitHub PR response missing valid 40-char base.sha on PR #{pr_number}")

        # Validate head.sha (must be 40-char hex)
        head_sha = head_data.get("sha")
        if not head_sha or not isinstance(head_sha, str) or len(head_sha) != 40 or not all(c in "0123456789abcdefABCDEF" for c in head_sha):
            raise GitHubPRMetadataInvalidError(f"GitHub PR response missing valid 40-char head.sha on PR #{pr_number}")

        is_fork = False
        head_repo = head_data.get("repo")
        base_repo = base_data.get("repo")
        if head_repo and base_repo:
            is_fork = head_repo.get("full_name") != base_repo.get("full_name")

        return ResolvedPullRequest(
            repository_url=f"https://github.com/{owner}/{repo}",
            repository_owner=owner,
            repository_name=repo,
            pr_number=pr_number,
            title=data.get("title", ""),
            base_branch=base_ref.strip(),
            base_commit_sha=base_sha.lower(),
            head_branch=head_ref.strip(),
            head_commit_sha=head_sha.lower(),
            is_fork=is_fork,
            state="merged" if data.get("merged") else data.get("state", "open"),
        )

    async def get_pull_request_diff_files(self, owner: str, repo: str, pr_number: int) -> List[GitHubDiffFile]:
        """Fetch changed files and patch hunks for a pull request (bounded to 3 pages)."""
        diff_files: List[GitHubDiffFile] = []
        for page in range(1, 4):  # max 3 pages (up to 300 changed files)
            files_data = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
                params={"per_page": 100, "page": page},
                is_write=False,
            )
            if not isinstance(files_data, list) or not files_data:
                break
            for f in files_data:
                diff_files.append(
                    GitHubDiffFile(
                        filename=f.get("filename", ""),
                        status=f.get("status", "modified"),
                        patch=f.get("patch", ""),
                        previous_filename=f.get("previous_filename"),
                    )
                )
            if len(files_data) < 100:
                break

        return diff_files

    async def create_comment_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        body: str,
        comments: Optional[List[InlineReviewComment]] = None,
    ) -> Dict[str, Any]:
        """Submit a COMMENT review to GitHub (strictly event='COMMENT', no approvals or request_changes)."""
        if not self.write_enabled:
            raise GitHubReviewWriteDisabledError()

        comments_payload = []
        if comments:
            for c in comments:
                comments_payload.append({
                    "path": c.path,
                    "line": c.line,
                    "side": c.side,
                    "body": c.body,
                })

        # STRICT INVARIANT: event is ALWAYS hardcoded to "COMMENT"
        payload = {
            "commit_id": commit_sha,
            "body": body,
            "event": "COMMENT",
        }
        if comments_payload:
            payload["comments"] = comments_payload

        data = await self._request(
            "POST",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
            json_data=payload,
            is_write=True,
        )
        return data

    async def list_pull_request_reviews(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        max_pages: int = 3,
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        """List pull request reviews with bounded pagination for deterministic reconciliation."""
        all_reviews: List[Dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            reviews_data = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
                params={"per_page": min(100, per_page), "page": page},
                is_write=False,
            )
            if not isinstance(reviews_data, list) or not reviews_data:
                break
            all_reviews.extend(reviews_data)
            if len(reviews_data) < per_page:
                break

        return all_reviews
