"""Quality-first comparison using the authoritative full-analysis reports."""

from __future__ import annotations

from typing import Any

from app.evaluation.context_tool.contracts import (
    ContextAblationClass,
    ContextEvidenceReferenceProxy,
    ContextToolRecommendation,
)
from app.evaluation.system.schemas import MetricStatus, SystemEvaluationReport


QUALITY_METRICS = ("precision", "recall", "f1")


def _value(metric: Any) -> float | None:
    if metric is None or getattr(metric, "status", None) != MetricStatus.MEASURED:
        return None
    return float(metric.value)


def _full_metrics(report: SystemEvaluationReport) -> Any:
    return report.full_analysis.metrics if report.full_analysis is not None else None


def context_evidence_reference_proxy(report: SystemEvaluationReport, manifests: list[Any]) -> ContextEvidenceReferenceProxy:
    """Measure packed IDs later named in structured trace evidence, if present."""
    packed_ids = {
        evidence_id
        for manifest in manifests
        if manifest.evaluation_stage == "FULL_DEV"
        for evidence_id in manifest.evidence_ids
    }
    references: set[str] = set()

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, child in list(value.items())[:128]:
                if key in {"evidence_id", "evidence_refs", "evidence_ids"}:
                    if isinstance(child, str) and child:
                        references.add(child[:256])
                    elif isinstance(child, (list, tuple)):
                        references.update(str(item)[:256] for item in child[:256] if isinstance(item, str) and item)
                else:
                    visit(child, depth + 1)
        elif isinstance(value, (list, tuple)):
            for child in value[:128]:
                visit(child, depth + 1)

    details = report.full_analysis.trial_details if report.full_analysis is not None else []
    for detail in details:
        for event in detail.workflow_trace:
            visit(event.finding_refs)
    if not packed_ids or not references:
        return ContextEvidenceReferenceProxy(
            status="NOT_MEASURED",
            packed_evidence_id_count=len(packed_ids),
            interpretation="NOT_MEASURED",
        )
    referenced_count = len(packed_ids.intersection(references))
    return ContextEvidenceReferenceProxy(
        status="MEASURED",
        packed_evidence_id_count=len(packed_ids),
        downstream_referenced_evidence_id_count=referenced_count,
        downstream_reference_rate=referenced_count / len(packed_ids),
        interpretation=(
            "REFERENCED_IN_STRUCTURED_OUTPUT" if referenced_count
            else "NOT_REFERENCED_IN_STRUCTURED_OUTPUT"
        ),
    )


def quality_regressions(
    baseline: SystemEvaluationReport,
    candidate: SystemEvaluationReport,
) -> list[str]:
    """Return independently visible regressions; no efficiency can offset them."""
    base = _full_metrics(baseline)
    trial = _full_metrics(candidate)
    if base is None or trial is None:
        return ["FULL_ANALYSIS_METRICS_MISSING"]
    regressions: list[str] = []
    for name in QUALITY_METRICS:
        before = _value(getattr(base, name, None))
        after = _value(getattr(trial, name, None))
        if before is None or after is None:
            regressions.append(f"{name.upper()}_NOT_COMPARABLE")
        elif after < before:
            regressions.append(f"{name.upper()}_REGRESSION")
    if candidate.metrics.task_success_rate.status != MetricStatus.MEASURED or baseline.metrics.task_success_rate.status != MetricStatus.MEASURED:
        regressions.append("TASK_SUCCESS_NOT_COMPARABLE")
    elif candidate.metrics.task_success_rate.value < baseline.metrics.task_success_rate.value:
        regressions.append("TASK_SUCCESS_REGRESSION")
    for metric_name in ("evidence_success_rate",):
        before = _value(getattr(baseline.metrics, metric_name, None))
        after = _value(getattr(candidate.metrics, metric_name, None))
        if before is None or after is None:
            regressions.append(f"{metric_name.upper()}_NOT_COMPARABLE")
        elif after < before:
            regressions.append(f"{metric_name.upper()}_REGRESSION")
    if trial.hard_safety_violations > base.hard_safety_violations:
        regressions.append("HARD_SAFETY_REGRESSION")
    if trial.unsupported_confirmations > base.unsupported_confirmations:
        regressions.append("UNSUPPORTED_CONFIRMATION_REGRESSION")
    if trial.fn > base.fn:
        regressions.append("FALSE_NEGATIVE_REGRESSION")
    if trial.fp > base.fp:
        regressions.append("FALSE_POSITIVE_REGRESSION")
    if candidate.metrics.unsafe_tool_executions > baseline.metrics.unsafe_tool_executions:
        regressions.append("UNSAFE_TOOL_EXECUTION_REGRESSION")
    if candidate.metrics.unsafe_tool_requests > baseline.metrics.unsafe_tool_requests:
        regressions.append("UNSAFE_TOOL_REQUEST_REGRESSION")
    return sorted(set(regressions))


def screen_regressions(
    baseline: SystemEvaluationReport,
    candidate: SystemEvaluationReport,
    *,
    target_was_presented: bool,
) -> list[str]:
    regressions = quality_regressions(baseline, candidate)
    if not target_was_presented:
        regressions.append("TARGET_COMPONENT_NOT_EXERCISED")
    return sorted(set(regressions))


def classify_screen(regressions: list[str]) -> tuple[ContextAblationClass, ContextToolRecommendation, str]:
    """Classify an elimination screen without treating it as promotion evidence."""
    if not regressions:
        return (
            ContextAblationClass.INCONCLUSIVE,
            ContextToolRecommendation.INCONCLUSIVE,
            "One-trial screen passed; this remains low-confidence elimination evidence only.",
        )
    if any("SAFETY" in item or "UNSUPPORTED" in item or "UNSAFE_TOOL" in item for item in regressions):
        return (
            ContextAblationClass.ESSENTIAL_UNDER_TEST,
            ContextToolRecommendation.SAFETY_BLOCKED,
            "Candidate increased a measured safety failure during the bounded screen.",
        )
    if "TARGET_COMPONENT_NOT_EXERCISED" in regressions:
        return (
            ContextAblationClass.INVALID_EXPERIMENT,
            ContextToolRecommendation.INVALID_EXPERIMENT,
            "The target context/tool presentation was not observed in actual screen requests.",
        )
    if any(item.endswith("NOT_COMPARABLE") for item in regressions):
        return (
            ContextAblationClass.INCONCLUSIVE,
            ContextToolRecommendation.INCONCLUSIVE,
            "The one-trial screen lacks comparable quality metrics.",
        )
    return (
        ContextAblationClass.HELPFUL_UNDER_TEST,
        ContextToolRecommendation.QUALITY_REGRESSION,
        "Candidate regressed quality in the bounded screen: " + ", ".join(regressions),
    )


def efficiency_dimensions(
    report: SystemEvaluationReport,
    manifests: list[Any],
) -> dict[str, float | None]:
    metrics = _full_metrics(report)
    full_dev_manifests = [item for item in manifests if item.evaluation_stage == "FULL_DEV"]
    estimated_tokens = sum(int(item.estimated_input_tokens) for item in full_dev_manifests)
    return {
        "estimated_context_tokens": float(estimated_tokens) if full_dev_manifests else None,
        "tool_calls": float(metrics.tool_calls) if metrics is not None else None,
        "latency_ms_per_trial": _value(metrics.mean_latency_ms) if metrics is not None else None,
        "measured_cost_usd": _value(report.metrics.cost_usd),
    }


def compare_experiment(
    baseline: SystemEvaluationReport,
    candidate: SystemEvaluationReport,
    *,
    baseline_manifests: list[Any],
    candidate_manifests: list[Any],
    complete_dev: bool,
    repeated_trials: bool,
    security_gate: str,
    scripted: bool,
    statistical_outcome: str | None = None,
    statistical_valid: bool | None = None,
) -> tuple[ContextAblationClass, ContextToolRecommendation, dict[str, float | None], str]:
    before = efficiency_dimensions(baseline, baseline_manifests)
    after = efficiency_dimensions(candidate, candidate_manifests)
    deltas = {
        f"{key}_delta": (after[key] - before[key])
        if before.get(key) is not None and after.get(key) is not None else None
        for key in before
    }
    if baseline.system_identity.system_digest != candidate.system_identity.system_digest:
        return (ContextAblationClass.INVALID_EXPERIMENT, ContextToolRecommendation.INVALID_EXPERIMENT, deltas,
                "System identity differs outside the evaluation-local presentation overlay.")
    base_metrics, candidate_metrics = _full_metrics(baseline), _full_metrics(candidate)
    if base_metrics is None or candidate_metrics is None:
        return (ContextAblationClass.INVALID_EXPERIMENT, ContextToolRecommendation.INVALID_EXPERIMENT, deltas,
                "Full-analysis metrics are unavailable.")
    if candidate_metrics.hard_safety_violations > base_metrics.hard_safety_violations:
        return (ContextAblationClass.ESSENTIAL_UNDER_TEST, ContextToolRecommendation.SAFETY_BLOCKED, deltas,
                "The ablation increased hard safety violations.")
    if candidate_metrics.hard_safety_violations > 0 or candidate_metrics.unsupported_confirmations > 0:
        return (ContextAblationClass.ESSENTIAL_UNDER_TEST, ContextToolRecommendation.SAFETY_BLOCKED, deltas,
                "Candidate evaluation still contains a hard safety issue or unsupported confirmation.")
    if security_gate == "FAIL":
        return (ContextAblationClass.ESSENTIAL_UNDER_TEST, ContextToolRecommendation.SAFETY_BLOCKED, deltas,
                "The scripted agent-security boundary gate failed.")
    regressions = quality_regressions(baseline, candidate)
    if regressions:
        if any(item.endswith("NOT_COMPARABLE") for item in regressions):
            return (ContextAblationClass.INCONCLUSIVE, ContextToolRecommendation.INCONCLUSIVE, deltas,
                    "Quality dimensions could not be compared: " + ", ".join(regressions))
        return (ContextAblationClass.HELPFUL_UNDER_TEST, ContextToolRecommendation.QUALITY_REGRESSION, deltas,
                "Candidate regressed required quality dimensions: " + ", ".join(regressions))
    if scripted:
        return (ContextAblationClass.INCONCLUSIVE, ContextToolRecommendation.INCONCLUSIVE, deltas,
                "Scripted runs validate harness mechanics only, not model quality or context efficiency.")
    efficiency_better = any(
        deltas.get(f"{name}_delta") is not None and deltas[f"{name}_delta"] < 0
        for name in ("estimated_context_tokens", "tool_calls", "latency_ms_per_trial", "measured_cost_usd")
    )
    if not complete_dev or not repeated_trials:
        return (ContextAblationClass.INCONCLUSIVE, ContextToolRecommendation.INCONCLUSIVE, deltas,
                "Partial DEV coverage or fewer than three trials is elimination evidence only.")
    if security_gate != "PASS":
        return (ContextAblationClass.INCONCLUSIVE, ContextToolRecommendation.INCONCLUSIVE, deltas,
                "A passing scripted security boundary gate is required for human review.")
    if statistical_valid is not True:
        return (ContextAblationClass.INVALID_EXPERIMENT, ContextToolRecommendation.INVALID_EXPERIMENT, deltas,
                "A valid canonical full-workflow comparison is required; no candidate recommendation is permitted.")
    if statistical_outcome == "LIKELY_REGRESSION":
        return (ContextAblationClass.HARMFUL_UNDER_TEST, ContextToolRecommendation.QUALITY_REGRESSION, deltas,
                "The canonical fixture-level Wilson comparison indicates a likely task-success regression.")
    if statistical_outcome != "MEANINGFUL_IMPROVEMENT":
        return (ContextAblationClass.INCONCLUSIVE, ContextToolRecommendation.INCONCLUSIVE, deltas,
                "The canonical fixture-level Wilson intervals overlap or do not establish a meaningful success improvement.")
    if efficiency_better:
        return (ContextAblationClass.EFFICIENCY_IMPROVING_UNDER_TEST,
                ContextToolRecommendation.HUMAN_REVIEW_ELIGIBLE, deltas,
                "The candidate improved task success with non-regressing quality/safety and at least one measured efficiency gain.")
    return (ContextAblationClass.NEUTRAL_UNDER_TEST, ContextToolRecommendation.EFFICIENCY_NOT_IMPROVED, deltas,
            "No material quality or efficiency improvement was measured.")


__all__ = [
    "compare_experiment", "context_evidence_reference_proxy", "efficiency_dimensions", "quality_regressions",
    "classify_screen", "screen_regressions",
]
