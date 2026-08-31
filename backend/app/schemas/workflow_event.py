"""Canonical Pydantic schemas for workflow events and audit telemetry."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class WorkflowEventType(str, Enum):
    """Stable taxonomy for durable workflow events."""

    SCAN_CREATED = "SCAN_CREATED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"

    STAGE_STARTED = "STAGE_STARTED"
    STAGE_COMPLETED = "STAGE_COMPLETED"
    STAGE_FAILED = "STAGE_FAILED"

    TOOL_STARTED = "TOOL_STARTED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    TOOL_FAILED = "TOOL_FAILED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"

    FINDING_CONFIRMED = "FINDING_CONFIRMED"

    PATCH_GENERATED = "PATCH_GENERATED"
    PATCH_VERIFIED = "PATCH_VERIFIED"
    PATCH_NEEDS_REVIEW = "PATCH_NEEDS_REVIEW"
    PATCH_REJECTED = "PATCH_REJECTED"
    PATCH_APPROVED = "PATCH_APPROVED"
    PATCH_REVISION_CREATED = "PATCH_REVISION_CREATED"

    HUMAN_APPROVED = "HUMAN_APPROVED"
    HUMAN_REJECTED = "HUMAN_REJECTED"
    HUMAN_REVISION_REQUESTED = "HUMAN_REVISION_REQUESTED"

    DELIVERY_REQUESTED = "DELIVERY_REQUESTED"
    DELIVERY_VALIDATED = "DELIVERY_VALIDATED"
    DELIVERY_BLOCKED = "DELIVERY_BLOCKED"
    DELIVERY_COMMIT_CREATED = "DELIVERY_COMMIT_CREATED"
    DELIVERY_BRANCH_CREATED = "DELIVERY_BRANCH_CREATED"
    DELIVERY_PR_CREATED = "DELIVERY_PR_CREATED"
    DELIVERY_FAILED = "DELIVERY_FAILED"

    CHANGE_ANALYSIS_REQUESTED = "CHANGE_ANALYSIS_REQUESTED"
    CHANGE_REVISIONS_ACQUIRED = "CHANGE_REVISIONS_ACQUIRED"
    CHANGE_DIFF_COMPLETED = "CHANGE_DIFF_COMPLETED"
    CHANGE_IMPACT_ANALYZED = "CHANGE_IMPACT_ANALYZED"
    CHANGE_ANALYSIS_COMPLETED = "CHANGE_ANALYSIS_COMPLETED"
    CHANGE_ANALYSIS_FAILED = "CHANGE_ANALYSIS_FAILED"

    PR_REVIEW_PREVIEW_READY = "PR_REVIEW_PREVIEW_READY"
    PR_REVIEW_APPROVED = "PR_REVIEW_APPROVED"
    PR_REVIEW_PUBLISH_STARTED = "PR_REVIEW_PUBLISH_STARTED"
    PR_REVIEW_PUBLISHED = "PR_REVIEW_PUBLISHED"
    PR_REVIEW_BLOCKED = "PR_REVIEW_BLOCKED"
    PR_REVIEW_FAILED = "PR_REVIEW_FAILED"

    WORKFLOW_ERROR = "WORKFLOW_ERROR"


class WorkflowEventBase(BaseModel):
    """Base schema for workflow event payload."""

    event_type: WorkflowEventType = Field(..., description="Canonical event type from WorkflowEventType taxonomy")
    scan_id: Optional[UUID] = Field(default=None, description="Associated scan ID if applicable")
    change_analysis_id: Optional[UUID] = Field(default=None, description="Associated change analysis ID if applicable")
    finding_id: Optional[UUID] = Field(default=None, description="Optional finding ID if event pertains to a specific finding")
    patch_id: Optional[UUID] = Field(default=None, description="Optional patch ID if event pertains to a specific patch proposal")
    delivery_id: Optional[UUID] = Field(default=None, description="Optional delivery ID if event pertains to a pull request delivery")
    pr_review_publication_id: Optional[UUID] = Field(default=None, description="Optional PR review publication ID if event pertains to review publication")
    thread_id: Optional[str] = Field(default=None, description="Optional LangGraph durable thread identifier")
    commit_sha: Optional[str] = Field(default=None, description="Exact commit SHA being operated upon")
    stage: Optional[str] = Field(default=None, description="Pipeline stage name (e.g. ingestion, analysis, remediation, delivery)")
    tool_name: Optional[str] = Field(default=None, description="Tool or scanner name (e.g. semgrep, trivy, osv, tree-sitter, github)")
    provider: Optional[str] = Field(default=None, description="LLM or delivery provider if applicable (e.g. gemini, groq, github)")
    model_name: Optional[str] = Field(default=None, description="LLM model identifier if applicable")
    actor_user_id: Optional[str] = Field(default=None, description="Optional authenticated user ID who initiated or approved the action")
    message: Optional[str] = Field(default=None, description="Human-readable event summary or description")
    metadata_payload: Dict[str, Any] = Field(default_factory=dict, description="Structured event telemetry payload")


class WorkflowEventCreate(WorkflowEventBase):
    """Payload to emit a new workflow event."""
    pass


class WorkflowEventResponse(WorkflowEventBase):
    """Serialized representation of a persisted workflow event."""

    id: int = Field(..., description="Monotonically increasing integer event ID for reliable ordering and SSE replay")
    created_at: datetime = Field(..., description="Timestamp when event was recorded")

    model_config = ConfigDict(from_attributes=True)
