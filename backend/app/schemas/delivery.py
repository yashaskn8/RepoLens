"""Canonical Pydantic schemas for GitHub pull request delivery endpoints."""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field

from app.schemas.enums import DeliveryStatus, PatchStatus


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DeliveryPreviewResponse(BaseModel):
    """Deterministic preview of GitHub pull request delivery eligibility and proposed targets."""

    eligible: bool = Field(..., description="Whether patch is eligible for automated GitHub delivery")
    blocking_reason: Optional[str] = Field(default=None, description="Human-readable reason if delivery is ineligible or blocked")
    failure_code: Optional[str] = Field(default=None, description="Typed failure code if blocked (e.g. BLOCKED_BASE_DRIFT)")
    repository_url: str = Field(..., description="Target repository URL")
    repository_owner: str = Field(..., description="Target repository owner")
    repository_name: str = Field(..., description="Target repository name")
    base_branch: str = Field(..., description="Target base branch on GitHub")
    scanned_base_sha: str = Field(..., description="Exact commit SHA scanned and analyzed by RepoLens")
    observed_base_sha: Optional[str] = Field(default=None, description="Current remote branch head SHA observed on GitHub")
    files_modified: List[str] = Field(default_factory=list, description="Exact files modified by the approved patch")
    patch_status: PatchStatus = Field(..., description="Current human review status of the patch")
    machine_verdict: Optional[str] = Field(default=None, description="Machine verification verdict")
    human_approved: bool = Field(..., description="Whether the patch has been explicitly approved by a human")
    proposed_branch_name: str = Field(..., description="Deterministic branch name to be created (e.g. repolens/fix-...)")
    proposed_pr_title: str = Field(..., description="Deterministic pull request title")
    github_delivery_configured: bool = Field(..., description="Whether GitHub delivery provider credentials are configured")


class DeliveryRequest(BaseModel):
    """Payload to trigger safe, human-authorized GitHub pull request delivery."""

    requested_by: str = Field(default="user", max_length=128, description="Identifier of the user requesting PR delivery")
    notes: Optional[str] = Field(default=None, max_length=2000, description="Optional delivery or audit sign-off notes")


class DeliveryResponse(BaseModel):
    """API response model for delivery state and pull request tracking."""

    id: UUID = Field(..., description="Unique delivery ID")
    scan_id: UUID = Field(..., description="Associated scan ID")
    finding_id: UUID = Field(..., description="Associated finding ID")
    patch_id: UUID = Field(..., description="Target approved patch ID")
    provider: str = Field(..., description="Delivery provider (github)")
    repository_url: str = Field(..., description="Target repository URL")
    repository_owner: str = Field(..., description="Target repository owner")
    repository_name: str = Field(..., description="Target repository name")
    base_branch: str = Field(..., description="Target base branch on GitHub")
    scanned_base_sha: str = Field(..., description="Exact commit SHA scanned by RepoLens")
    observed_base_sha: Optional[str] = Field(default=None, description="Remote branch head SHA observed at delivery")
    head_branch: Optional[str] = Field(default=None, description="Created dedicated remediation branch")
    head_sha: Optional[str] = Field(default=None, description="Created commit SHA on GitHub")
    pr_number: Optional[int] = Field(default=None, description="Created GitHub pull request number")
    pr_url: Optional[str] = Field(default=None, description="Canonical GitHub pull request URL")
    status: DeliveryStatus = Field(..., description="Current lifecycle status of delivery")
    failure_code: Optional[str] = Field(default=None, description="Typed failure code if failed or blocked")
    failure_message: Optional[str] = Field(default=None, description="Sanitized failure message")
    idempotency_key: str = Field(..., description="Deterministic idempotency key")
    requested_by: str = Field(..., description="User who requested delivery")
    request_notes: Optional[str] = Field(default=None, description="Operator sign-off notes")
    reconciliation_occurred: bool = Field(default=False, description="Whether remote state was recovered by reconciliation")
    attempt_count: int = Field(default=1, description="Delivery execution attempt count")
    last_attempt_at: Optional[datetime] = Field(default=None, description="Timestamp of most recent attempt")
    created_at: datetime = Field(default_factory=_utc_now, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=_utc_now, description="Last update timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Completion timestamp")

    model_config = {
        "from_attributes": True,
    }
