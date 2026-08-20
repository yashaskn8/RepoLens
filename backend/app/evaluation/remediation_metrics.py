"""Deterministic remediation-quality metric computation (Phase 3H).

All metrics are computed deterministically — no LLM-as-judge.
Uses structural diff parsing, file-set intersection, and snippet matching.
"""

import re
from typing import Dict, List, Optional, Set

from app.evaluation.remediation_fixtures import RemediationFixtureFinding
from app.evaluation.remediation_schemas import (
    PatchEvaluationMetrics,
    RemediationPipelineVariant,
    VariantAggregateMetrics,
)
from app.patching.schemas import (
    PatchProposal,
    PatchVerificationResult,
    PatchWorkflowResult,
    VerificationStatus,
)
from app.patching.validator import parse_diff_files
from app.planning.schemas import FixPlan


def _is_valid_unified_diff(diff_text: str) -> bool:
    """Check if a string is a syntactically valid unified diff."""
    if not diff_text or not diff_text.strip():
        return False
    has_orig = bool(re.search(r"^--- ", diff_text, re.MULTILINE))
    has_new = bool(re.search(r"^\+\+\+ ", diff_text, re.MULTILINE))
    has_hunk = bool(re.search(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", diff_text, re.MULTILINE))
    has_changes = bool(re.search(r"^[+-](?!\+\+|--)", diff_text, re.MULTILINE))
    return has_orig and has_new and has_hunk and has_changes


def _compute_fabricated_paths(diff_text: str, known_files: Set[str]) -> List[str]:
    """Return file paths in the diff that are not in the known repository file set."""
    diff_files = parse_diff_files(diff_text)
    return [f for f in diff_files if f not in known_files]


def _compute_unnecessary_files(diff_text: str, expected_files: List[str]) -> List[str]:
    """Return files modified in the diff that are outside the expected scope."""
    diff_files = parse_diff_files(diff_text)
    expected_set = set(f.replace("\\", "/").lstrip("/") for f in expected_files)
    return [f for f in diff_files if f not in expected_set]


def _check_defect_resolved(diff_text: str, defect_snippet: str) -> bool:
    """Check if the defect snippet appears in a deletion (-) line of the diff."""
    if not defect_snippet or not diff_text:
        return False
    snippet_core = defect_snippet.strip()
    for line in diff_text.split("\n"):
        if line.startswith("-") and not line.startswith("---"):
            if snippet_core in line:
                return True
    return False


def _check_plan_evidence_grounded(fix_plan: Optional[FixPlan], known_files: Set[str]) -> Optional[bool]:
    """Check if all files referenced in the FixPlan actually exist in the repository."""
    if fix_plan is None:
        return None
    for f in fix_plan.files_expected_to_change:
        normalized = f.replace("\\", "/").lstrip("/")
        if normalized not in known_files:
            return False
    return True


def evaluate_single_patch(
    fixture: RemediationFixtureFinding,
    variant: RemediationPipelineVariant,
    diff_text: str,
    known_repo_files: Set[str],
    fix_plan: Optional[FixPlan] = None,
    verification_result: Optional[PatchVerificationResult] = None,
    workflow_result: Optional[PatchWorkflowResult] = None,
    model_calls: int = 0,
    latency_ms: float = 0.0,
) -> PatchEvaluationMetrics:
    """Deterministically evaluate a single patch attempt against a fixture finding."""

    valid_diff = _is_valid_unified_diff(diff_text)

    fabricated = _compute_fabricated_paths(diff_text, known_repo_files) if valid_diff else []
    diff_files = parse_diff_files(diff_text) if valid_diff else []
    fabricated_rate = len(fabricated) / len(diff_files) if diff_files else 0.0

    unnecessary = _compute_unnecessary_files(diff_text, fixture.expected_files_to_change) if valid_diff else []
    unnecessary_rate = len(unnecessary) / len(diff_files) if diff_files else 0.0

    resolved = _check_defect_resolved(diff_text, fixture.defect_snippet) if valid_diff else False

    plan_grounded = _check_plan_evidence_grounded(fix_plan, known_repo_files)

    verifier_rejected = None
    if verification_result is not None:
        verifier_rejected = verification_result.status == VerificationStatus.FAILED

    critic_invoked = None
    revision_applied = False
    final_verdict = None
    if workflow_result is not None:
        critic_invoked = workflow_result.critic_escalated
        revision_applied = workflow_result.revision_count > 0
        final_verdict = workflow_result.final_verdict

    return PatchEvaluationMetrics(
        finding_id=fixture.ground_truth.issue_id,
        variant=variant,
        valid_unified_diff=valid_diff,
        fabricated_paths=fabricated,
        fabricated_path_rate=round(fabricated_rate, 4),
        target_finding_resolved=resolved,
        unnecessary_files_changed=unnecessary,
        unnecessary_file_change_rate=round(unnecessary_rate, 4),
        plan_evidence_grounded=plan_grounded,
        verifier_rejected=verifier_rejected,
        critic_invoked=critic_invoked,
        revision_applied=revision_applied,
        model_calls=model_calls,
        latency_ms=round(latency_ms, 2),
        final_verdict=final_verdict,
    )


def aggregate_variant_metrics(
    per_patch: List[PatchEvaluationMetrics],
    variant: RemediationPipelineVariant,
) -> VariantAggregateMetrics:
    """Aggregate per-patch metrics into variant-level summary metrics."""
    matching = [p for p in per_patch if p.variant == variant]
    total = len(matching)
    if total == 0:
        return VariantAggregateMetrics(variant=variant)

    valid_count = sum(1 for p in matching if p.valid_unified_diff)
    resolved_count = sum(1 for p in matching if p.target_finding_resolved)
    verifier_rejected_count = sum(1 for p in matching if p.verifier_rejected is True)
    revision_count = sum(1 for p in matching if p.revision_applied)

    avg_fab_rate = sum(p.fabricated_path_rate for p in matching) / total
    avg_unnecessary_rate = sum(p.unnecessary_file_change_rate for p in matching) / total
    avg_model_calls = sum(p.model_calls for p in matching) / total
    avg_latency = sum(p.latency_ms for p in matching) / total

    # Plan grounding only applies to variants B, C, D
    plan_grounded_values = [p.plan_evidence_grounded for p in matching if p.plan_evidence_grounded is not None]
    plan_grounding_rate = (
        sum(1 for v in plan_grounded_values if v) / len(plan_grounded_values)
        if plan_grounded_values else None
    )

    return VariantAggregateMetrics(
        variant=variant,
        total_findings=total,
        valid_diff_count=valid_count,
        valid_diff_rate=round(valid_count / total, 4),
        fabricated_path_rate=round(avg_fab_rate, 4),
        target_resolution_count=resolved_count,
        target_resolution_rate=round(resolved_count / total, 4),
        unnecessary_file_change_rate=round(avg_unnecessary_rate, 4),
        plan_evidence_grounding_rate=round(plan_grounding_rate, 4) if plan_grounding_rate is not None else None,
        verifier_rejection_count=verifier_rejected_count,
        verifier_rejection_rate=round(verifier_rejected_count / total, 4),
        patch_revision_count=revision_count,
        patch_revision_rate=round(revision_count / total, 4),
        avg_model_calls=round(avg_model_calls, 2),
        avg_latency_ms=round(avg_latency, 2),
    )
