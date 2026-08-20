"""Canonical schemas for structured remediation and root-cause fix planning."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from app.schemas.metadata import ModelExecutionMetadata


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FixScope(str, Enum):
    """Estimated architectural scope of the proposed remediation."""

    LINE = "line"               # Local statement-level fix within single block
    FUNCTION = "function"       # Function-level refactoring
    FILE = "file"               # Single file modifications
    CROSS_FILE = "cross_file"   # Multi-file coordinated contract change


class OrderedChangeStep(BaseModel):
    """Single discrete step in the ordered remediation sequence."""

    step_number: int = Field(..., ge=1, description="1-indexed execution order")
    target_file: str = Field(..., description="Normalized repository file path to modify")
    target_symbol: Optional[str] = Field(default=None, description="Function, class, or route symbol to modify")
    description: str = Field(..., description="Clear explanation of the change to be made without raw code")
    rationale: str = Field(..., description="Why this change is necessary to resolve the root cause")


class PlanValidationStatus(str, Enum):
    """Validation verdict for a proposed fix plan."""

    VALID = "VALID"
    REJECTED = "REJECTED"


class PlanValidationReport(BaseModel):
    """Deterministic validation results checking against repository evidence."""

    status: PlanValidationStatus = Field(..., description="VALID if all checks pass, REJECTED if any violation occurs")
    is_valid: bool = Field(..., description="True if no plan rejection rules were triggered")
    rejection_reasons: List[str] = Field(default_factory=list, description="Reasons explaining why plan was rejected")
    validated_files: List[str] = Field(default_factory=list, description="Files verified to exist in repository manifest")
    validated_symbols: List[str] = Field(default_factory=list, description="Symbols verified to exist in repository AST")


class FixPlan(BaseModel):
    """Canonical structured remediation plan for a verified repository finding."""

    id: UUID = Field(default_factory=uuid4, description="Unique plan identifier")
    finding_id: UUID = Field(..., description="UUID of the confirmed finding this plan remediates")
    root_cause: str = Field(..., description="Rigorous explanation of the underlying root cause")
    objective: str = Field(..., description="Core goal of the remediation without extra features")
    files_expected_to_change: List[str] = Field(..., min_length=1, description="Exact existing files targeted for modification")
    symbols_expected_to_change: List[str] = Field(default_factory=list, description="Specific existing symbols to modify")
    ordered_changes: List[OrderedChangeStep] = Field(..., min_length=1, description="Ordered change steps detailing the smallest coherent fix")
    interfaces_affected: List[str] = Field(default_factory=list, description="APIs, routes, or function signatures affected")
    migration_config_impact: Optional[str] = Field(default=None, description="Any database, config, or dependency version requirements")
    regression_risks: List[str] = Field(default_factory=list, description="Potential side effects or backward compatibility risks")
    validation_plan: List[str] = Field(..., min_length=1, description="Concrete automated tests or verification checks required")
    estimated_scope: FixScope = Field(default=FixScope.FILE, description="Scope of the change")
    assumptions: List[str] = Field(default_factory=list, description="Explicit assumptions made by the planner")
    validation_report: Optional[PlanValidationReport] = Field(default=None, description="Deterministic validation report against repo facts")
    model_metadata: Optional[ModelExecutionMetadata] = Field(default=None, description="LLM execution and token telemetry")
    created_at: datetime = Field(default_factory=_utc_now, description="Creation timestamp")
