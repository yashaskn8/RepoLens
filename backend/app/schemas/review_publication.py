"""Pydantic schemas and typed domain errors for Safe Pull Request Review Publication."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class ReviewPublicationStatus(str, Enum):
    """Explicit lifecycle states for Pull Request Review Publication."""

    PENDING = "PENDING"
    PREVIEW_READY = "PREVIEW_READY"
    APPROVED = "APPROVED"
    PUBLISHING = "PUBLISHING"
    PUBLISHED = "PUBLISHED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class InlineReviewComment(BaseModel):
    """Exact inline comment representation submitted to GitHub API."""

    path: str = Field(..., description="Relative file path in repository")
    line: int = Field(..., description="Line number on the head/right side of the PR diff")
    side: str = Field(default="RIGHT", description="Diff side for comment (strictly RIGHT for head)")
    body: str = Field(..., description="Markdown comment body")

    model_config = ConfigDict(extra="forbid")


class InlineReviewCommentPreview(BaseModel):
    """Detailed preview of an inline comment before human authorization."""

    path: str
    line: int
    side: str = "RIGHT"
    body: str
    finding_id: Optional[str] = None
    finding_title: Optional[str] = None
    severity: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class ReviewPublicationPreviewResponse(BaseModel):
    """Deterministic preview representation for human review and digest computation."""

    publication_id: UUID
    analysis_id: UUID
    status: ReviewPublicationStatus
    repository_owner: str
    repository_name: str
    pr_number: int
    base_commit_sha: str
    head_commit_sha: str
    body_markdown: str
    preview_digest: str
    inline_comments: List[InlineReviewCommentPreview] = Field(default_factory=list)
    review_event: str = Field(default="COMMENT", description="Hardcoded review event (strictly COMMENT)")
    is_truncated: bool = False
    truncation_reason: Optional[str] = None
    approved_at: Optional[datetime] = None
    published_at: Optional[datetime] = None
    github_review_id: Optional[int] = None
    github_review_url: Optional[str] = None
    reconciliation_occurred: bool = False
    failure_code: Optional[str] = None
    failure_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReviewPublicationApproveRequest(BaseModel):
    """Explicit human approval request bound to exact preview digest."""

    expected_preview_digest: str = Field(..., description="SHA-256 preview digest the human reviewed and approved")


class ReviewPublicationPublishRequest(BaseModel):
    """Explicit human publish request bound to exact preview digest."""

    expected_preview_digest: str = Field(..., description="SHA-256 preview digest verified before publication")


class ReviewPublicationPublishResponse(BaseModel):
    """Response returned upon successful review publication to GitHub."""

    publication_id: UUID
    analysis_id: UUID
    status: ReviewPublicationStatus
    github_review_id: Optional[int] = None
    github_review_url: Optional[str] = None
    published_at: Optional[datetime] = None
    inline_comments_count: int = 0
    reconciliation_occurred: bool = False

    model_config = ConfigDict(from_attributes=True)


class ReviewPublicationReportSnapshot(BaseModel):
    """Publication summary embedded in change analysis reports and telemetry."""

    publication_status: ReviewPublicationStatus = ReviewPublicationStatus.PENDING
    github_review_id: Optional[int] = None
    github_review_url: Optional[str] = None
    published_at: Optional[datetime] = None
    inline_comments_count: int = 0
    base_commit_sha: Optional[str] = None
    head_commit_sha: Optional[str] = None
    reconciliation_occurred: bool = False
    failure_code: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# Typed Domain Exceptions
# =============================================================================

class ReviewPublicationError(Exception):
    """Base domain exception for review publication errors."""

    def __init__(self, message: str, error_code: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


class AnalysisNotCompletedError(ReviewPublicationError):
    def __init__(self, message: str = "Change analysis must be COMPLETED before generating review publication"):
        super().__init__(message, error_code="ANALYSIS_NOT_COMPLETED", status_code=400)


class NotPRAnalysisError(ReviewPublicationError):
    def __init__(self, message: str = "Change analysis did not originate from a valid pull request (/from-pr)"):
        super().__init__(message, error_code="NOT_PR_ANALYSIS", status_code=400)


class ForkPRUnsupportedError(ReviewPublicationError):
    def __init__(self, message: str = "Review publication is not supported for fork pull requests"):
        super().__init__(message, error_code="FORK_PR_UNSUPPORTED", status_code=400)


class PRNotFoundError(ReviewPublicationError):
    def __init__(self, message: str = "Pull request not found on GitHub"):
        super().__init__(message, error_code="PR_NOT_FOUND", status_code=404)


class PRClosedError(ReviewPublicationError):
    def __init__(self, message: str = "Pull request is closed"):
        super().__init__(message, error_code="PR_CLOSED", status_code=409)


class PRMergedError(ReviewPublicationError):
    def __init__(self, message: str = "Pull request has already been merged"):
        super().__init__(message, error_code="PR_MERGED", status_code=409)


class PRBaseDriftError(ReviewPublicationError):
    def __init__(self, message: str = "Pull request base commit SHA has drifted from analyzed revision"):
        super().__init__(message, error_code="PR_BASE_DRIFT", status_code=409)


class PRHeadDriftError(ReviewPublicationError):
    def __init__(self, message: str = "Pull request head commit SHA has drifted from analyzed revision"):
        super().__init__(message, error_code="PR_HEAD_DRIFT", status_code=409)


class PreviewDigestMismatchError(ReviewPublicationError):
    def __init__(self, message: str = "Provided preview digest does not match the active publication digest"):
        super().__init__(message, error_code="PREVIEW_DIGEST_MISMATCH", status_code=409)


class PublicationNotApprovedError(ReviewPublicationError):
    def __init__(self, message: str = "Publication must be in APPROVED state before publishing"):
        super().__init__(message, error_code="PUBLICATION_NOT_APPROVED", status_code=409)


class GitHubReviewWriteDisabledError(ReviewPublicationError):
    def __init__(self, message: str = "GitHub PR review writing is disabled by configuration (GITHUB_PR_REVIEW_WRITE_ENABLED=false)"):
        super().__init__(message, error_code="GITHUB_REVIEW_WRITE_DISABLED", status_code=403)


class GitHubAuthFailedError(ReviewPublicationError):
    def __init__(self, message: str = "GitHub authentication failed or credentials missing"):
        super().__init__(message, error_code="GITHUB_AUTH_FAILED", status_code=401)


class GitHubRateLimitedError(ReviewPublicationError):
    def __init__(self, message: str = "GitHub API rate limit exceeded"):
        super().__init__(message, error_code="GITHUB_RATE_LIMITED", status_code=429)


class GitHubReviewCreateFailedError(ReviewPublicationError):
    def __init__(self, message: str = "Failed to create pull request review on GitHub"):
        super().__init__(message, error_code="GITHUB_REVIEW_CREATE_FAILED", status_code=502)


class GitHubReviewStateUncertainError(ReviewPublicationError):
    def __init__(self, message: str = "GitHub review creation outcome uncertain; reconciliation required"):
        super().__init__(message, error_code="GITHUB_REVIEW_STATE_UNCERTAIN", status_code=502)


class GitHubPRMetadataInvalidError(ReviewPublicationError):
    def __init__(self, message: str = "GitHub pull request metadata is invalid or missing required fields (base/head ref or sha)"):
        super().__init__(message, error_code="GITHUB_PR_METADATA_INVALID", status_code=502)


class ReconciliationFailedError(ReviewPublicationError):
    def __init__(self, message: str = "Failed to reconcile pull request review status from GitHub"):
        super().__init__(message, error_code="RECONCILIATION_FAILED", status_code=502)
