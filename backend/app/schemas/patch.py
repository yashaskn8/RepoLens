"""Canonical Pydantic schemas for Patch API endpoints and human approval actions."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from app.schemas.enums import PatchStatus
from app.schemas.metadata import ModelExecutionMetadata


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PatchReviewRequest(BaseModel):
    """Payload for human approval action."""

    approved_by: str = Field(default="user", description="Name or identifier of the human reviewer")
    notes: Optional[str] = Field(default=None, description="Optional approval notes or sign-off comment")


class PatchRejectRequest(BaseModel):
    """Payload for human rejection action."""

    reason: str = Field(..., min_length=1, description="Required justification explaining why patch was rejected")


class PatchReviseRequest(BaseModel):
    """Payload for requesting one targeted revision with human feedback."""

    user_feedback: str = Field(..., min_length=1, description="Specific feedback or adjustments requested by human reviewer")


class PatchResponse(BaseModel):
    """API response model for remediation patch proposals and approval status."""

    id: UUID = Field(..., description="Unique patch ID")
    finding_id: UUID = Field(..., description="Target finding ID")
    plan_id: Optional[UUID] = Field(default=None, description="Approved FixPlan ID if linked")
    scan_id: UUID = Field(..., description="Associated scan ID")
    parent_patch_id: Optional[UUID] = Field(default=None, description="Parent patch ID if this is a human-requested revision")
    revision_number: int = Field(default=0, ge=0, description="Revision number in lineage (0 for original, 1 for child revision)")
    thread_id: Optional[str] = Field(default=None, description="Durable LangGraph remediation thread ID")
    status: PatchStatus = Field(..., description="Human review status: DRAFT, VERIFIED, NEEDS_REVIEW, REJECTED, APPROVED")
    machine_verdict: Optional[str] = Field(default=None, description="Machine verification verdict: PASSED, NEEDS_REVIEW, REJECTED")
    unified_diff: str = Field(..., description="Standard unified diff")
    files_modified: List[str] = Field(..., description="Repository files modified by this patch")
    explanation: str = Field(..., description="Summary explanation of the change")
    expected_behavior_change: str = Field(..., description="Runtime behavioral impact")
    generated_tests_or_test_plan: Optional[List[str]] = Field(default=None, description="Targeted test plan")
    verification_report: Optional[Dict[str, Any]] = Field(default=None, description="Deterministic sandbox verification outcome")
    critic_report: Optional[Dict[str, Any]] = Field(default=None, description="Independent critic report if evaluated")
    user_feedback: Optional[str] = Field(default=None, description="Human reviewer feedback")
    approved_by: Optional[str] = Field(default=None, description="Reviewer who approved the patch")
    approved_at: Optional[datetime] = Field(default=None, description="Timestamp of human approval")
    rejected_reason: Optional[str] = Field(default=None, description="Rejection reason if rejected")
    model_metadata: Optional[ModelExecutionMetadata] = Field(default=None, description="Model execution telemetry")
    created_at: datetime = Field(default_factory=_utc_now, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=_utc_now, description="Last update timestamp")

    model_config = {
        "from_attributes": True,
    }
