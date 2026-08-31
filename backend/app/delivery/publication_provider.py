"""Provider abstraction for safe GitHub Pull Request Review publication.

Reuses canonical shared GitHubHttpTransport infrastructure:
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
from app.delivery.github_client import GITHUB_API_BASE_URL, GitHubHttpTransport
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
    """Concrete implementation communicating with GitHub REST API for review publication.

    Delegates all HTTP transport to canonical GitHubHttpTransport, adding
    domain-specific error mapping for publication operations.
    """

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
        self.transport = GitHubHttpTransport(
            token=self._token,
            base_url=base_url,
            user_agent="RepoLens-ReviewPublication-Engine/1.0",
            settings=app_settings,
            client=client,
        )
        self.base_url = self.transport.base_url
        self._client = client
        self._timeout = self.transport._timeout

    @property
    def write_enabled(self) -> bool:
        """Return True if GitHub review writing is administratively enabled."""
        return bool(self._write_enabled)

    def _get_headers(self) -> Dict[str, str]:
        """Build safe HTTP headers without leaking tokens in logs."""
        return self.transport.get_headers()

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
        """Execute HTTP request to GitHub API with domain-specific error mapping.

        Delegates transport to GitHubHttpTransport, then maps GitHubAPIError
        to publication-specific exceptions for proper HTTP status propagation.
        """
        from app.delivery.schemas import GitHubAPIError

        try:
            return await self.transport.request(
                method=method,
                path=path,
                json_data=json_data,
                params=params,
                is_write=is_write,
            )
        except GitHubAPIError as exc:
            # Map transport errors to publication-domain exceptions
            status = exc.status_code
            err_msg = self._redact_error(str(exc))

            if status == 404:
                raise PRNotFoundError(f"Resource not found on GitHub: {path}") from exc
            elif status in (401, 403):
                if "rate limit" in err_msg.lower():
                    raise GitHubRateLimitedError(f"GitHub API rate limit exceeded: {err_msg}") from exc
                raise GitHubAuthFailedError(f"GitHub authentication or authorization failed: {err_msg}") from exc
            elif status == 429:
                raise GitHubRateLimitedError("GitHub API rate limit exceeded") from exc
            elif status in (504, 502) and is_write:
                # Outcome uncertain for write operations on timeout/network errors
                raise GitHubReviewStateUncertainError(
                    f"Network error during write operation on {path}. Outcome uncertain; reconciliation required."
                ) from exc
            else:
                raise GitHubReviewCreateFailedError(
                    f"GitHub API returned error ({status}) on {path}: {err_msg}"
                ) from exc

    async def get_current_pull_request(self, owner: str, repo: str, pr_number: int) -> ResolvedPullRequest:
        """Fetch current pull request state and immutable commit SHAs from GitHub.

        Fail-closed validation:
        - base.repo.full_name and head.repo.full_name MUST be present and match expected owner/repo.
        - Explicit state from GitHub response (no default 'open').
        - base.ref, head.ref, base.sha, head.sha all validated.
        """
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

        # FIX 6: Fail-closed validation of base.repo.full_name and head.repo.full_name
        expected_full_name = f"{owner}/{repo}"
        base_repo = base_data.get("repo")
        if not isinstance(base_repo, dict) or not base_repo.get("full_name"):
            raise GitHubPRMetadataInvalidError(
                f"GitHub PR response missing base.repo.full_name on PR #{pr_number}"
            )
        base_repo_full_name = str(base_repo["full_name"])
        if base_repo_full_name != expected_full_name:
            raise GitHubPRMetadataInvalidError(
                f"GitHub PR base.repo.full_name '{base_repo_full_name}' does not match expected '{expected_full_name}' on PR #{pr_number}"
            )

        head_repo = head_data.get("repo")
        if not isinstance(head_repo, dict) or not head_repo.get("full_name"):
            raise GitHubPRMetadataInvalidError(
                f"GitHub PR response missing head.repo.full_name on PR #{pr_number}"
            )
        head_repo_full_name = str(head_repo["full_name"])

        # Determine is_fork by comparing full_name (no default False assumption)
        is_fork = head_repo_full_name != base_repo_full_name

        # FIX 6: Fail-closed explicit state — no default 'open'
        raw_state = data.get("state")
        if not raw_state or not isinstance(raw_state, str) or raw_state.strip() not in ("open", "closed"):
            raise GitHubPRMetadataInvalidError(
                f"GitHub PR response missing or invalid explicit state on PR #{pr_number} (got '{raw_state}')"
            )
        pr_state = "merged" if data.get("merged") else raw_state.strip()

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
            state=pr_state,
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
        """Submit a COMMENT review to GitHub (strictly event='COMMENT', no approvals or request_changes).

        FIX 10: Validates response contains a valid positive integer 'id' before returning.
        Missing or malformed 'id' raises GitHubReviewCreateFailedError to trigger reconciliation.
        """
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

        # FIX 10: Validate response contains valid positive integer ID
        review_id = data.get("id") if isinstance(data, dict) else None
        if not isinstance(review_id, int) or review_id <= 0:
            logger.error(
                f"GitHub create-review response missing valid positive integer 'id' "
                f"(got {type(review_id).__name__}: {review_id}). Treating as uncertain write."
            )
            raise GitHubReviewStateUncertainError(
                f"GitHub create-review response missing valid 'id' field on PR #{pr_number}. "
                f"Review may have been created; reconciliation required."
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
