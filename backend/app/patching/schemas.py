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


class CheckStatus(str, Enum):
    """Execution status for an individual verification check."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    NOT_EVALUATED = "NOT_EVALUATED"


class VerificationStatus(str, Enum):
    """Overall status of deterministic patch verification."""

    PASSED = "PASSED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED = "FAILED"


class VerificationCheckItem(BaseModel):
    """Individual verification check result."""

    check_name: str = Field(..., description="Canonical name of the verification check")
    passed: bool = Field(..., description="True if the check passed, False otherwise")
    status: CheckStatus = Field(default=CheckStatus.PASSED, description="Execution status: PASSED, FAILED, NEEDS_REVIEW, UNAVAILABLE, TIMEOUT, NOT_EVALUATED")
    details: Optional[str] = Field(default=None, description="Diagnostic notes or failure explanation")



class PatchVerificationResult(BaseModel):
    """Rigorous, deterministic multi-step verification result for a candidate patch.
    
    Guarantees:
    - Never runs untrusted repository tests or package scripts.
    - Verified strictly in an isolated temporary sandbox.
    """

    id: UUID = Field(default_factory=uuid4, description="Unique verification report identifier")
    patch_id: UUID = Field(..., description="UUID of the evaluated PatchProposal")
    finding_id: UUID = Field(..., description="UUID of the target finding")
    status: VerificationStatus = Field(..., description="Overall verdict: PASSED, NEEDS_REVIEW, or FAILED")
    syntax_valid: bool = Field(..., description="True if all modified files still parse cleanly with Tree-sitter")
    security_clean: bool = Field(..., description="True if no new secrets or high/critical vulnerabilities were introduced")
    contract_aligned: bool = Field(..., description="True if route contracts and relationships remain intact")
    target_finding_resolved: bool = Field(..., description="True if original defect evidence was remediated")
    checks: List[VerificationCheckItem] = Field(default_factory=list, description="All 12 individual check results")
    checks_passed: List[str] = Field(default_factory=list, description="Names of all passed checks")
    checks_failed: List[str] = Field(default_factory=list, description="Names of any failed checks")
    explanation: str = Field(..., description="Summary explanation of verification findings")
    verified_at: datetime = Field(default_factory=_utc_now, description="Verification timestamp")


class CriticVerdict(str, Enum):
    """Independent patch critic verdict."""

    APPROVE = "APPROVE"
    REVISE = "REVISE"
    REJECT = "REJECT"


class PatchCriticReport(BaseModel):
    """Structured report produced by the independent PatchCriticAgent."""

    id: UUID = Field(default_factory=uuid4, description="Unique critic evaluation identifier")
    patch_id: UUID = Field(..., description="Evaluated patch proposal ID")
    finding_id: UUID = Field(..., description="Target finding ID")
    verdict: CriticVerdict = Field(..., description="APPROVE, REVISE, or REJECT")
    critic_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Quality/confidence score")
    concerns: List[str] = Field(default_factory=list, description="Specific architectural, regression, or security concerns")
    required_revisions: Optional[str] = Field(default=None, description="Actionable revision guidance if verdict is REVISE")
    evidence_notes: str = Field(..., description="Analysis grounded in independent repository retrieval")
    escalation_reasons: List[str] = Field(default_factory=list, description="Reasons why critic was conditionally invoked")
    model_metadata: Optional[ModelExecutionMetadata] = Field(default=None, description="Telemetry from independent critic model")
    created_at: datetime = Field(default_factory=_utc_now, description="Critic evaluation timestamp")


class PatchWorkflowResult(BaseModel):
    """End-to-end outcome of the safe patch generation, verification, and criticism workflow."""

    finding_id: UUID = Field(..., description="Target finding ID")
    proposal: PatchProposal = Field(..., description="Final candidate patch proposal")
    verification_result: PatchVerificationResult = Field(..., description="Deterministic sandbox verification outcome")
    critic_escalated: bool = Field(default=False, description="True if conditional escalation rules invoked the critic")
    critic_report: Optional[PatchCriticReport] = Field(default=None, description="Critic evaluation report if escalated")
    revision_count: int = Field(default=0, ge=0, le=1, description="Number of automatic revisions applied (capped at 1)")
    machine_verdict: str = Field(default="NEEDS_REVIEW", description="Machine verification verdict: PASSED, NEEDS_REVIEW, or REJECTED")
    final_verdict: str = Field(default="NEEDS_REVIEW", description="Backward-compatible alias for machine_verdict")
