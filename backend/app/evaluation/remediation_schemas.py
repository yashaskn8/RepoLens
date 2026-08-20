"""Schemas for remediation-quality evaluation harness (Phase 3H).

Extends the Phase 2 evaluation harness with remediation-specific metrics
measured deterministically — no LLM-as-judge.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationPipelineVariant(str, Enum):
    """Pipeline variants compared in the remediation evaluation."""

    DIRECT_LLM = "A. direct LLM patch"
    FIXPLAN_PATCH = "B. FixPlan → Patch"
    FIXPLAN_PATCH_VERIFICATION = "C. FixPlan → Patch → deterministic verification"
    FULL_PIPELINE = "D. full pipeline with conditional critic"


class PatchEvaluationMetrics(BaseModel):
    """Deterministic quality metrics for a single patch attempt."""

    finding_id: str = Field(..., description="Ground-truth finding being remediated")
    variant: RemediationPipelineVariant
    valid_unified_diff: bool = Field(..., description="True if patch parses as valid unified diff")
    fabricated_paths: List[str] = Field(default_factory=list, description="File paths in diff not present in repository")
    fabricated_path_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Fraction of diff paths that are fabricated")
    target_finding_resolved: bool = Field(default=False, description="True if defect evidence snippet was removed/remediated")
    unnecessary_files_changed: List[str] = Field(default_factory=list, description="Files changed outside the expected scope")
    unnecessary_file_change_rate: float = Field(default=0.0, ge=0.0, le=1.0, description="Fraction of changed files outside scope")
    plan_evidence_grounded: Optional[bool] = Field(default=None, description="True if FixPlan references only real files/symbols")
    verifier_rejected: Optional[bool] = Field(default=None, description="True if deterministic verifier rejected the patch")
    critic_invoked: Optional[bool] = Field(default=None, description="True if critic was conditionally escalated")
    revision_applied: bool = Field(default=False, description="True if a revision round was triggered")
    model_calls: int = Field(default=0, ge=0, description="Total LLM calls consumed for this attempt")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Wall-clock time in milliseconds")
    final_verdict: Optional[str] = Field(default=None, description="APPROVED, REJECTED, or NEEDS_HUMAN_REVIEW")


class VariantAggregateMetrics(BaseModel):
    """Aggregate metrics across all fixture findings for a single pipeline variant."""

    variant: RemediationPipelineVariant
    total_findings: int = Field(default=0, ge=0)
    valid_diff_count: int = Field(default=0, ge=0)
    valid_diff_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    fabricated_path_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    target_resolution_count: int = Field(default=0, ge=0)
    target_resolution_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    unnecessary_file_change_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    plan_evidence_grounding_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    verifier_rejection_count: int = Field(default=0, ge=0)
    verifier_rejection_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    patch_revision_count: int = Field(default=0, ge=0)
    patch_revision_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    avg_model_calls: float = Field(default=0.0, ge=0.0)
    avg_latency_ms: float = Field(default=0.0, ge=0.0)


class RemediationBenchmarkReport(BaseModel):
    """Complete machine-readable remediation evaluation benchmark report."""

    timestamp: datetime = Field(default_factory=_utc_now)
    fixture_name: str = Field(default="", description="Name of the evaluation fixture used")
    total_findings_evaluated: int = Field(default=0, ge=0)
    variant_results: Dict[str, VariantAggregateMetrics] = Field(default_factory=dict)
    per_patch_results: List[PatchEvaluationMetrics] = Field(default_factory=list)
    markdown_summary: str = Field(default="", description="Concise human-readable comparison table")
