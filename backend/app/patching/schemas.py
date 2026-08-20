"""Canonical schemas for evidence-constrained safe patch generation."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from app.schemas.metadata import ModelExecutionMetadata


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PatchValidationStatus(str, Enum):
    """Validation verdict for a generated patch proposal."""

    VALID = "VALID"
    REJECTED = "REJECTED"


class PatchValidationReport(BaseModel):
    """Deterministic validation results for a unified diff patch."""

    status: PatchValidationStatus = Field(..., description="VALID if all checks pass, REJECTED if any violation occurs")
    is_valid: bool = Field(..., description="True if no patch rejection rules were triggered")
    rejection_reasons: List[str] = Field(default_factory=list, description="Detailed reasons explaining why patch was rejected")
    parsed_files: List[str] = Field(default_factory=list, description="Files parsed from the unified diff headers")
    hunks_count: int = Field(default=0, ge=0, description="Total number of diff hunks contained in the patch")


class PatchProposal(BaseModel):
    """Canonical patch proposal containing unified diff and validation telemetry.
    
    Guarantees:
    - Never mutates the original repository directly.
    - Never commits or pushes changes.
    - Captures unified diffs only.
    """

    id: UUID = Field(default_factory=uuid4, description="Unique patch proposal identifier")
    finding_id: UUID = Field(..., description="UUID of the confirmed finding being remediated")
    plan_id: Optional[UUID] = Field(default=None, description="UUID of the approved FixPlan if available")
    unified_diff: str = Field(..., description="Standard unified diff representation (--- a/file +++ b/file @@ ... @@)")
    files_modified: List[str] = Field(..., min_length=1, description="List of repository files modified by this patch")
    explanation: str = Field(..., description="Technical explanation of the proposed changes and rationale")
    expected_behavior_change: str = Field(..., description="Expected runtime behavior difference after patch is applied")
    generated_tests_or_test_plan: List[str] = Field(default_factory=list, description="Targeted unit tests or verification instructions")
    validation_report: Optional[PatchValidationReport] = Field(default=None, description="Deterministic diff syntax and boundary validation report")
    model_metadata: Optional[ModelExecutionMetadata] = Field(default=None, description="LLM execution metadata")
    created_at: datetime = Field(default_factory=_utc_now, description="Timestamp of patch creation")
