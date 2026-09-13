"""Statistically defensible metric calculations, Wilson intervals, and family cluster bootstrap."""

from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from app.evaluation.ground_truth.matcher import CaseEvaluationResult
from app.evaluation.ground_truth.schemas import EvaluationStage


def safe_div(numerator: float, denominator: float) -> Optional[float]:
    """Perform safe division returning None when denominator is zero."""
    if denominator <= 0.0:
        return None
    return float(numerator) / float(denominator)


def compute_f1(precision: Optional[float], recall: Optional[float]) -> Optional[float]:
    """Compute F1 score safely from precision and recall."""
    if precision is None or recall is None:
        return None
    denom = precision + recall
    if denom <= 0.0:
        return 0.0
    return 2.0 * (precision * recall) / denom


def compute_wilson_ci(
    successes: int,
    total: int,
    confidence: float = 0.95,
) -> Optional[Tuple[float, float]]:
    """Compute Wilson score interval for a binomial proportion.

    Returns:
        (lower_bound, upper_bound) rounded to 4 decimals, or None if total == 0.
    """
    if total <= 0:
        return None

    # z = 1.95996 for 95% confidence
    z = 1.95996 if confidence == 0.95 else 1.64485
    p = float(successes) / float(total)
    denominator = 1.0 + (z * z) / float(total)
    centre_adjusted = p + (z * z) / (2.0 * float(total))
    adjusted_std_error = z * math.sqrt(
        (p * (1.0 - p) + (z * z) / (4.0 * float(total))) / float(total)
    )

    lower = max(0.0, (centre_adjusted - adjusted_std_error) / denominator)
    upper = min(1.0, (centre_adjusted + adjusted_std_error) / denominator)
    return round(lower, 4), round(upper, 4)


class MetricConfidenceInterval(BaseModel):
    """Uncertainty interval for an empirical metric."""

    metric_name: str
    point_estimate: Optional[float]
    lower: Optional[float]
    upper: Optional[float]
    method: str = "cluster_bootstrap"
    valid_replicates: int
    total_replicates: int


class LayerMetricSummary(BaseModel):
    """Metrics aggregated for a specific evaluation stage."""

    stage: EvaluationStage
    status: str = "EXECUTED"  # or NOT_EXECUTED
    tp: int = 0
    fp: int = 0
    fn: int = 0
    duplicate_fp: int = 0
    invalid_reference_count: int = 0
    unsupported_claim_count: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    precision_ci: Optional[Tuple[float, float]] = None
    recall_ci: Optional[Tuple[float, float]] = None
    f1_ci: Optional[Tuple[float, float]] = None


class CleanCaseSummary(BaseModel):
    """Metrics for whole-repository clean cases."""

    clean_cases_total: int = 0
    clean_cases_without_fp: int = 0  # Case-level TN
    clean_cases_with_any_fp: int = 0  # Case-level FP
    clean_case_false_positive_rate: Optional[float] = None
    clean_case_specificity: Optional[float] = None
    specificity_wilson_ci: Optional[Tuple[float, float]] = None


class AbstentionSummary(BaseModel):
    """Metrics for UNKNOWN / insufficient evidence cases."""

    unknown_cases_total: int = 0
    explicit_correct_abstentions: int = 0
    no_positive_publications: int = 0
    incorrect_confident_positives: int = 0
    incorrect_confident_negatives: int = 0
    pipeline_not_evaluable: int = 0
    correct_abstention_rate: Optional[float] = None
    abstention_rate_wilson_ci: Optional[Tuple[float, float]] = None


class BenchmarkAggregateMetrics(BaseModel):
    """Complete auditable aggregate metrics preserving raw confusion counts."""

    # Raw global confusion counts
    raw_confusion: Dict[str, int] = Field(default_factory=dict)

    # Finding-level overall metrics
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None

    # Localization
    file_localization_accuracy: Optional[float] = None
    symbol_localization_accuracy: Optional[float] = None

    # Unsupported published findings
    unsupported_finding_count: int = 0
    unsupported_published_rate: Optional[float] = None

    # Layer breakdowns
    layer_metrics: Dict[str, LayerMetricSummary] = Field(default_factory=dict)

    # Clean case performance
    clean_cases: CleanCaseSummary = Field(default_factory=CleanCaseSummary)

    # Abstention performance
    abstentions: AbstentionSummary = Field(default_factory=AbstentionSummary)

    # Cluster Bootstrap Confidence Intervals
    confidence_intervals: Dict[str, MetricConfidenceInterval] = Field(default_factory=dict)


def compute_family_cluster_bootstrap(
    case_results: List[CaseEvaluationResult],
    iterations: int = 1000,
    seed: int = 42,
    confidence: float = 0.95,
) -> Dict[str, MetricConfidenceInterval]:
    """Compute 95% confidence intervals by resampling whole case families.

    Guarantees:
    - Resamples entire families with replacement (preserving intra-family correlation).
    - Replicates where metric is mathematically undefined are excluded from that metric's distribution.
    - Records valid_replicates / total_replicates explicitly.
    """
    if not case_results:
        return {}

    rng = random.Random(seed)

    # Group cases by family
    families: Dict[str, List[CaseEvaluationResult]] = {}
    for r in case_results:
        families.setdefault(r.case_family, []).append(r)

    family_keys = list(families.keys())
    num_families = len(family_keys)
    if num_families < 2:
        return {}

    precisions: List[float] = []
    recalls: List[float] = []
    f1s: List[float] = []
    unsupported_rates: List[float] = []

    for _ in range(iterations):
        sampled_family_keys = rng.choices(family_keys, k=num_families)
        sample_results = [r for k in sampled_family_keys for r in families[k]]

        tp = sum(r.tp for r in sample_results)
        fp = sum(r.fp for r in sample_results)
        fn = sum(r.fn for r in sample_results)
        unsupported = sum(r.invalid_reference_count + r.unsupported_claim_count for r in sample_results)
        total_published = tp + fp

        # Precision replicate
        if (tp + fp) > 0:
            precisions.append(float(tp) / float(tp + fp))

        # Recall replicate
        if (tp + fn) > 0:
            recalls.append(float(tp) / float(tp + fn))

        # F1 replicate
        if (tp + fp) > 0 and (tp + fn) > 0:
            p = float(tp) / float(tp + fp)
            r = float(tp) / float(tp + fn)
            f1_val = compute_f1(p, r)
            if f1_val is not None:
                f1s.append(f1_val)

        # Unsupported rate replicate
        if total_published > 0:
            unsupported_rates.append(float(unsupported) / float(total_published))

    alpha = 1.0 - confidence
    lower_pct = (alpha / 2.0) * 100.0
    upper_pct = (1.0 - alpha / 2.0) * 100.0

    def _get_percentiles(values: List[float]) -> Optional[Tuple[float, float]]:
        if len(values) < 10:
            return None
        sorted_vals = sorted(values)
        idx_lower = int(math.floor((lower_pct / 100.0) * (len(sorted_vals) - 1)))
        idx_upper = int(math.ceil((upper_pct / 100.0) * (len(sorted_vals) - 1)))
        return round(sorted_vals[idx_lower], 4), round(sorted_vals[idx_upper], 4)

    intervals: Dict[str, MetricConfidenceInterval] = {}

    for name, sample_list in [
        ("precision", precisions),
        ("recall", recalls),
        ("f1", f1s),
        ("unsupported_rate", unsupported_rates),
    ]:
        bounds = _get_percentiles(sample_list)
        intervals[name] = MetricConfidenceInterval(
            metric_name=name,
            point_estimate=round(sum(sample_list) / len(sample_list), 4) if sample_list else None,
            lower=bounds[0] if bounds else None,
            upper=bounds[1] if bounds else None,
            valid_replicates=len(sample_list),
            total_replicates=iterations,
        )

    return intervals


def aggregate_case_metrics(
    case_results: List[CaseEvaluationResult],
    run_bootstrap: bool = True,
    bootstrap_iterations: int = 1000,
    bootstrap_seed: int = 42,
) -> BenchmarkAggregateMetrics:
    """Compute overall and layer-separated benchmark metrics from case results."""
    raw_tp = sum(r.tp for r in case_results)
    raw_fp = sum(r.fp for r in case_results)
    raw_fn = sum(r.fn for r in case_results)
    raw_dup_fp = sum(r.duplicate_fp for r in case_results)
    raw_invalid_ref = sum(r.invalid_reference_count for r in case_results)
    raw_unsupported_claim = sum(r.unsupported_claim_count for r in case_results)
    raw_file_loc = sum(r.file_localized_tp for r in case_results)
    raw_sym_loc = sum(r.symbol_localized_tp for r in case_results)

    clean_cases = [r for r in case_results if r.is_clean_case]
    unknown_cases = [r for r in case_results if r.is_unknown_case]

    case_level_tn = sum(1 for r in clean_cases if r.clean_case_tn)
    case_level_fp = sum(1 for r in clean_cases if r.clean_case_fp)

    raw_confusion = {
        "tp": raw_tp,
        "fp": raw_fp,
        "fn": raw_fn,
        "duplicate_fp": raw_dup_fp,
        "invalid_reference_count": raw_invalid_ref,
        "unsupported_claim_count": raw_unsupported_claim,
        "case_level_tn": case_level_tn,
        "case_level_fp": case_level_fp,
    }

    # Finding level
    precision = safe_div(raw_tp, raw_tp + raw_fp)
    recall = safe_div(raw_tp, raw_tp + raw_fn)
    f1 = compute_f1(precision, recall)

    file_loc_acc = safe_div(raw_file_loc, raw_tp)
    sym_loc_acc = safe_div(raw_sym_loc, raw_tp)

    total_unsupported = raw_invalid_ref + raw_unsupported_claim
    total_published = raw_tp + raw_fp
    unsupported_rate = safe_div(total_unsupported, total_published)

    # Clean cases summary
    clean_summary = CleanCaseSummary(
        clean_cases_total=len(clean_cases),
        clean_cases_without_fp=case_level_tn,
        clean_cases_with_any_fp=case_level_fp,
        clean_case_false_positive_rate=safe_div(case_level_fp, len(clean_cases)),
        clean_case_specificity=safe_div(case_level_tn, len(clean_cases)),
        specificity_wilson_ci=compute_wilson_ci(case_level_tn, len(clean_cases)),
    )

    # Abstentions summary
    correct_abstentions = sum(
        1 for r in unknown_cases if r.abstention_outcome and r.abstention_outcome.value == "EXPLICIT_CORRECT_ABSTENTION"
    )
    abstention_summary = AbstentionSummary(
        unknown_cases_total=len(unknown_cases),
        explicit_correct_abstentions=correct_abstentions,
        no_positive_publications=sum(
            1 for r in unknown_cases if r.abstention_outcome and r.abstention_outcome.value == "NO_POSITIVE_PUBLICATION"
        ),
        incorrect_confident_positives=sum(
            1 for r in unknown_cases if r.abstention_outcome and r.abstention_outcome.value == "INCORRECT_CONFIDENT_POSITIVE"
        ),
        incorrect_confident_negatives=sum(
            1 for r in unknown_cases if r.abstention_outcome and r.abstention_outcome.value == "INCORRECT_CONFIDENT_NEGATIVE"
        ),
        pipeline_not_evaluable=sum(
            1 for r in unknown_cases if r.abstention_outcome and r.abstention_outcome.value == "PIPELINE_NOT_EVALUABLE"
        ),
        correct_abstention_rate=safe_div(correct_abstentions, len(unknown_cases)),
        abstention_rate_wilson_ci=compute_wilson_ci(correct_abstentions, len(unknown_cases)),
    )

    # Layer summaries
    layer_metrics: Dict[str, LayerMetricSummary] = {}
    for stage in [
        EvaluationStage.STATIC_FINDING,
        EvaluationStage.ANALYSIS_CANDIDATE,
        EvaluationStage.CHANGE_FACT,
        EvaluationStage.IMPACT_FACT,
    ]:
        stage_cases = [r for r in case_results if r.evaluation_stage == stage]
        s_tp = sum(r.tp for r in stage_cases)
        s_fp = sum(r.fp for r in stage_cases)
        s_fn = sum(r.fn for r in stage_cases)
        s_prec = safe_div(s_tp, s_tp + s_fp)
        s_rec = safe_div(s_tp, s_tp + s_fn)
        s_f1 = compute_f1(s_prec, s_rec)

        layer_metrics[stage.value] = LayerMetricSummary(
            stage=stage,
            status="EXECUTED",
            tp=s_tp,
            fp=s_fp,
            fn=s_fn,
            duplicate_fp=sum(r.duplicate_fp for r in stage_cases),
            invalid_reference_count=sum(r.invalid_reference_count for r in stage_cases),
            unsupported_claim_count=sum(r.unsupported_claim_count for r in stage_cases),
            precision=round(s_prec, 4) if s_prec is not None else None,
            recall=round(s_rec, 4) if s_rec is not None else None,
            f1=round(s_f1, 4) if s_f1 is not None else None,
        )

    # E2E Published Finding stage (marked NOT_EXECUTED for deterministic runner)
    layer_metrics[EvaluationStage.PUBLISHED_FINDING.value] = LayerMetricSummary(
        stage=EvaluationStage.PUBLISHED_FINDING,
        status="NOT_EXECUTED",
    )

    # Cluster Bootstrap
    confidence_intervals = {}
    if run_bootstrap and len(case_results) > 1:
        confidence_intervals = compute_family_cluster_bootstrap(
            case_results,
            iterations=bootstrap_iterations,
            seed=bootstrap_seed,
        )

    return BenchmarkAggregateMetrics(
        raw_confusion=raw_confusion,
        precision=round(precision, 4) if precision is not None else None,
        recall=round(recall, 4) if recall is not None else None,
        f1=round(f1, 4) if f1 is not None else None,
        file_localization_accuracy=round(file_loc_acc, 4) if file_loc_acc is not None else None,
        symbol_localization_accuracy=round(sym_loc_acc, 4) if sym_loc_acc is not None else None,
        unsupported_finding_count=total_unsupported,
        unsupported_published_rate=round(unsupported_rate, 4) if unsupported_rate is not None else None,
        layer_metrics=layer_metrics,
        clean_cases=clean_summary,
        abstentions=abstention_summary,
        confidence_intervals=confidence_intervals,
    )
