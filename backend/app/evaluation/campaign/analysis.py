"""Recompute campaign summaries and paired diagnostics from immutable child units."""

from __future__ import annotations

from itertools import combinations

from app.evaluation.campaign.contracts import (
    CandidateConsistency,
    CampaignCandidateStatus,
    CampaignAnalysisReport,
    CampaignPairwiseComparison,
    CampaignReviewSample,
    CampaignStage,
    CampaignStageReport,
    CampaignTrialUnit,
    CampaignUnitResult,
    CampaignUnitStatus,
    ModelEvaluationCampaignPlan,
    UsageMetric,
    build_digested_model,
    canonical_digest,
)
from app.evaluation.system.comparison import wilson_interval
from app.evaluation.ground_truth.public_dev import load_public_dev_repository_cases


def _metric(value: float | None, unit: str) -> UsageMetric:
    if value is None:
        return UsageMetric(status="NOT_MEASURED", value=None, unit=unit)
    return UsageMetric(status="MEASURED", value=value, unit=unit)


def _sum_metric(results: list[CampaignUnitResult], name: str, unit: str) -> UsageMetric:
    grades = [
        trial
        for result in results if result.report is not None
        for case in result.report.case_results for trial in case.trials
    ]
    values = [getattr(grade, name) for grade in grades]
    if not values or any(value.status.value != "MEASURED" or value.value is None for value in values):
        return _metric(None, unit)
    return _metric(sum(float(value.value) for value in values), unit)


def _mean_latency(results: list[CampaignUnitResult]) -> UsageMetric:
    values = [
        trial.latency_ms.value
        for result in results if result.report is not None
        for case in result.report.case_results for trial in case.trials
        if trial.latency_ms.status.value == "MEASURED" and trial.latency_ms.value is not None
    ]
    return _metric(sum(values) / len(values) if values else None, "ms/trial")


def _summarize_candidate(
    plan: ModelEvaluationCampaignPlan,
    candidate_id: str,
    schedule: list[CampaignTrialUnit],
    results: list[CampaignUnitResult],
    stage: CampaignStage,
):
    from app.evaluation.campaign.contracts import CampaignCandidateSummary, ModelStability

    candidate = next(item for item in plan.candidate_arms if item.candidate_id == candidate_id)
    planned = [item for item in schedule if item.candidate_id == candidate_id]
    units = [item for item in results if item.unit.candidate_id == candidate_id]
    reports = [item.report for item in units if item.report is not None]
    trials = [
        trial for report in reports for case in report.case_results for trial in case.trials
    ]
    completed = sum(item.status == CampaignUnitStatus.COMPLETED for item in units)
    succeeded = sum(item.status == CampaignUnitStatus.COMPLETED and any(
        trial.task_success is True
        for case in (item.report.case_results if item.report else [])
        for trial in case.trials
    ) for item in units)
    provider_failures = sum(item.status == CampaignUnitStatus.PROVIDER_FAILURE for item in units)
    harness_failures = sum(item.status == CampaignUnitStatus.HARNESS_FAILURE for item in units)
    identity_failures = sum(item.status == CampaignUnitStatus.IDENTITY_INVALID for item in units)
    hard_safety = sum(
        report.metrics.hard_safety_violations for report in reports
    )
    unsupported = sum(
        report.full_analysis.metrics.unsupported_confirmations
        for report in reports if report.full_analysis is not None
    )
    budget_exhaustions = sum(item.status == CampaignUnitStatus.BUDGET_EXHAUSTED for item in units)
    tp = sum(report.full_analysis.metrics.tp for report in reports if report.full_analysis)
    fp = sum(report.full_analysis.metrics.fp for report in reports if report.full_analysis)
    fn = sum(report.full_analysis.metrics.fn for report in reports if report.full_analysis)
    precision = tp / (tp + fp) if tp + fp else (1.0 if fn == 0 else None)
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    complete = len(units) == len(planned) and completed == len(planned)
    task_success_rate = succeeded / len(planned) if complete and planned else None
    metric_precision = precision if complete else None
    metric_recall = recall if complete else None
    metric_f1 = f1 if complete else None

    categories: dict[str, list[bool]] = {}
    families: dict[str, list[bool]] = {}
    case_by_id = {case.case_id: case for case in load_public_dev_repository_cases()}
    for result in units:
        if result.report is None:
            continue
        for case_result in result.report.case_results:
            passed = bool(case_result.trials) and all(item.task_success is True for item in case_result.trials)
            case = case_by_id[case_result.case_id]
            categories.setdefault(case.category.value, []).append(passed)
            families.setdefault(case.case_family, []).append(passed)

    def group_metrics(groups: dict[str, list[bool]]) -> dict[str, UsageMetric]:
        if not complete:
            return {key: _metric(None, "proportion") for key in sorted(groups)}
        return {key: _metric(sum(values) / len(values) if values else None, "proportion") for key, values in sorted(groups.items())}

    failure_distribution: dict[str, int] = {}
    calls_by_node: dict[str, int] = {}
    tool_calls_by_name: dict[str, int] = {}
    tool_progress_by_name: dict[str, dict[str, int]] = {}
    for report in reports:
        if report.full_analysis is None:
            continue
        for detail in report.full_analysis.trial_details:
            if detail.failure_attribution is not None:
                key = detail.failure_attribution.failure_class.value
                failure_distribution[key] = failure_distribution.get(key, 0) + 1
            for event in detail.workflow_trace:
                calls_by_node[event.node] = calls_by_node.get(event.node, 0) + (event.model_execution_count or 0) + event.tool_execution_count
                if event.node != "investigator_tool":
                    continue
                for tool_name in event.tool_names:
                    tool_calls_by_name[tool_name] = tool_calls_by_name.get(tool_name, 0) + 1
                    counters = tool_progress_by_name.setdefault(tool_name, {
                        "calls": 0, "progress_calls": 0, "no_progress_calls": 0, "indeterminate_calls": 0,
                    })
                    counters["calls"] += 1
                    if event.investigator_progress_class in {"PROGRESS", "NEGATIVE_PROGRESS", "CONTRADICTION_PROGRESS"}:
                        counters["progress_calls"] += 1
                    elif event.investigator_progress_class == "NO_PROGRESS":
                        counters["no_progress_calls"] += 1
                    else:
                        counters["indeterminate_calls"] += 1

    consistency: list[CandidateConsistency] = []
    histogram: dict[str, int] = {str(value): 0 for value in range(6)}
    all_success_cases = all_failure_cases = mixed_cases = 0
    expected_trials = max((item.trial_number for item in planned), default=0)
    for case_id in sorted({item.case_id for item in planned}):
        case_results = [
            item for item in units if item.unit.case_id == case_id and item.report is not None
            and item.status == CampaignUnitStatus.COMPLETED
        ]
        case_successes = sum(
            trial.task_success is True
            for item in case_results for case in item.report.case_results for trial in case.trials
        )
        observed = sum(len(case.trials) for item in case_results for case in item.report.case_results)
        consistency_outcome = (
            "INCOMPLETE" if observed != expected_trials else
            "ALL_SUCCESS" if case_successes == expected_trials else
            "ALL_FAILURE" if case_successes == 0 else "MIXED"
        )
        if observed == expected_trials:
            histogram[str(case_successes)] += 1
            all_success_cases += consistency_outcome == "ALL_SUCCESS"
            all_failure_cases += consistency_outcome == "ALL_FAILURE"
            mixed_cases += consistency_outcome == "MIXED"
        consistency.append(CandidateConsistency(
            case_id=case_id,
            successful_trials=case_successes,
            planned_trials=max(1, expected_trials),
            empirical_success_rate=case_successes / observed if observed else 0.0,
            outcome=consistency_outcome,
        ))

    observed_pairs = sorted({pair for item in units for pair in item.observed_model_pairs})
    revisions = sorted({item.provider_returned_revision for item in units if item.provider_returned_revision})
    tool_calls = sum(item.report.metrics.tool_calls for item in units if item.report is not None)
    model_calls = sum(item.report.metrics.model_calls for item in units if item.report is not None)
    fallback_values = [grade.fallback_count for grade in trials]
    retry_values = [grade.retry_count for grade in trials]
    fallback_count = _metric(
        float(sum(fallback_values)) if trials and all(value is not None for value in fallback_values) else None,
        "calls",
    )
    retry_count = _metric(
        float(sum(retry_values)) if trials and all(value is not None for value in retry_values) else None,
        "calls",
    )

    if hard_safety > 0 or unsupported > 0:
        status = CampaignCandidateStatus.SAFETY_BLOCKED
    elif provider_failures or harness_failures or identity_failures or budget_exhaustions:
        status = CampaignCandidateStatus.RELIABILITY_BLOCKED
    elif not complete:
        status = CampaignCandidateStatus.INCONCLUSIVE
    elif candidate_id == plan.baseline_candidate_id:
        status = CampaignCandidateStatus.INCONCLUSIVE
    else:
        status = CampaignCandidateStatus.FULL_STAGE_ELIGIBLE if stage != CampaignStage.LIVE_FULL else CampaignCandidateStatus.QUALITY_ELIGIBLE

    return CampaignCandidateSummary(
        candidate_id=candidate_id,
        status=status,
        planned_units=len(planned),
        completed_units=completed,
        successful_trials=succeeded,
        failed_trials=max(0, completed - succeeded),
        provider_failures=provider_failures,
        harness_failures=harness_failures,
        identity_failures=identity_failures,
        hard_safety_violations=hard_safety,
        unsupported_confirmations=unsupported,
        task_success_rate=_metric(task_success_rate, "proportion"),
        precision=_metric(metric_precision, "proportion"),
        recall=_metric(metric_recall, "proportion"),
        f1=_metric(metric_f1, "proportion"),
        input_tokens=_sum_metric(units, "input_tokens", "tokens"),
        output_tokens=_sum_metric(units, "output_tokens", "tokens"),
        measured_cost_usd=_sum_metric(units, "cost_usd", "USD"),
        mean_latency_ms=_mean_latency(units),
        tool_calls=tool_calls,
        model_calls=model_calls,
        fallback_count=fallback_count,
        retry_count=retry_count,
        failure_distribution=failure_distribution,
        category_success_rates=group_metrics(categories),
        family_success_rates=group_metrics(families),
        per_case_consistency=consistency,
        all_trials_success_cases=all_success_cases,
        all_trials_failure_cases=all_failure_cases,
        mixed_result_cases=mixed_cases,
        case_success_histogram=histogram,
        calls_by_node=calls_by_node,
        tool_calls_by_name=tool_calls_by_name,
        tool_progress_by_name=tool_progress_by_name,
        observed_model_pairs=observed_pairs,
        provider_returned_revisions=revisions,
        registry_model_revision=candidate.model_revision,
        model_stability=candidate.model_stability,
        metric_scope="LIVE_PINNED_MODEL",
    )


def _comparison(a_id: str, b_id: str, schedule, results, summaries):
    from app.evaluation.campaign.contracts import CampaignPairwiseComparison

    units_a = {(item.unit.case_id, item.unit.trial_number): item for item in results if item.unit.candidate_id == a_id}
    units_b = {(item.unit.case_id, item.unit.trial_number): item for item in results if item.unit.candidate_id == b_id}
    common = sorted(set(units_a) & set(units_b))
    paired = [
        (units_a[key], units_b[key]) for key in common
        if units_a[key].status == units_b[key].status == CampaignUnitStatus.COMPLETED
        and units_a[key].report is not None and units_b[key].report is not None
    ]
    a_success = sum(
        trial.task_success is True
        for left, _ in paired for case in left.report.case_results for trial in case.trials
    )
    b_success = sum(
        trial.task_success is True
        for _, right in paired for case in right.report.case_results for trial in case.trials
    )
    n = len(paired)
    a_cases: dict[str, list[bool]] = {}
    b_cases: dict[str, list[bool]] = {}
    for left, right in paired:
        a_cases.setdefault(left.unit.case_id, []).extend(
            trial.task_success is True for case in left.report.case_results for trial in case.trials
        )
        b_cases.setdefault(right.unit.case_id, []).extend(
            trial.task_success is True for case in right.report.case_results for trial in case.trials
        )
    all_case_ids = sorted(set(a_cases) & set(b_cases))
    a_case_successes = sum(bool(a_cases[item]) and all(a_cases[item]) for item in all_case_ids)
    b_case_successes = sum(bool(b_cases[item]) and all(b_cases[item]) for item in all_case_ids)
    a_interval = wilson_interval(a_case_successes, len(all_case_ids))
    b_interval = wilson_interval(b_case_successes, len(all_case_ids))
    if not paired:
        outcome = "INVALID_COMPARISON"
    elif a_interval and b_interval and b_interval[0] > a_interval[1]:
        outcome = "MEANINGFUL_IMPROVEMENT"
    elif a_interval and b_interval and b_interval[1] < a_interval[0]:
        outcome = "LIKELY_REGRESSION"
    else:
        outcome = "INCONCLUSIVE"

    def mean_delta(metric_name: str) -> float | None:
        if metric_name == "tool_calls":
            left_values = [one.report.metrics.tool_calls for one, _ in paired]
            right_values = [one.report.metrics.tool_calls for _, one in paired]
            return sum(right_values) / n - sum(left_values) / n if n else None
        left_values = [
            getattr(trial, metric_name)
            for one, _ in paired for case in one.report.case_results for trial in case.trials
        ]
        right_values = [
            getattr(trial, metric_name)
            for _, one in paired for case in one.report.case_results for trial in case.trials
        ]
        if not left_values or any(x.status.value != "MEASURED" or x.value is None for x in [*left_values, *right_values]):
            return None
        return sum(float(item.value) for item in right_values) / len(right_values) - sum(float(item.value) for item in left_values) / len(left_values)

    a_hard = sum(left.report.metrics.hard_safety_violations for left, _ in paired)
    b_hard = sum(right.report.metrics.hard_safety_violations for _, right in paired)
    a_tp = sum(left.report.full_analysis.metrics.tp for left, _ in paired if left.report.full_analysis)
    a_fp = sum(left.report.full_analysis.metrics.fp for left, _ in paired if left.report.full_analysis)
    a_fn = sum(left.report.full_analysis.metrics.fn for left, _ in paired if left.report.full_analysis)
    b_tp = sum(right.report.full_analysis.metrics.tp for _, right in paired if right.report.full_analysis)
    b_fp = sum(right.report.full_analysis.metrics.fp for _, right in paired if right.report.full_analysis)
    b_fn = sum(right.report.full_analysis.metrics.fn for _, right in paired if right.report.full_analysis)
    def evidence_rate(rows: list[CampaignUnitResult]) -> float | None:
        values = [
            report.metrics.evidence_success_rate
            for row in rows for report in [row.report]
            if report is not None
        ]
        if not values or any(item.status.value != "MEASURED" or item.value is None for item in values):
            return None
        return sum(float(item.value) for item in values) / len(values)

    a_evidence = evidence_rate([left for left, _ in paired])
    b_evidence = evidence_rate([right for _, right in paired])
    return CampaignPairwiseComparison(
        candidate_a=a_id,
        candidate_b=b_id,
        valid=bool(paired),
        outcome=outcome,
        paired_trials=n,
        candidate_a_successes=a_success,
        candidate_b_successes=b_success,
        candidate_a_wilson_95=a_interval,
        candidate_b_wilson_95=b_interval,
        success_rate_delta_b_minus_a=(b_success - a_success) / n if n else None,
        hard_safety_delta_b_minus_a=b_hard - a_hard if n else None,
        evidence_success_delta_b_minus_a=(b_evidence - a_evidence) if b_evidence is not None and a_evidence is not None else None,
        tool_calls_delta_per_trial=mean_delta("tool_calls"),
        latency_delta_ms_per_trial=mean_delta("latency_ms"),
        input_tokens_delta_per_trial=mean_delta("input_tokens"),
        output_tokens_delta_per_trial=mean_delta("output_tokens"),
        measured_cost_delta_usd_per_trial=mean_delta("cost_usd"),
        child_comparison_digests=[canonical_digest({"a": left.result_digest, "b": right.result_digest}) for left, right in paired],
        reasons=(
            ["paired fresh units share the frozen case/trial, evaluator, graph, prompts, tools, context, and budgets"]
            if paired else ["no paired completed units were available"]
        ),
    )


def summarize_stage(plan, stage, schedule, results):
    candidate_ids = sorted({item.candidate_id for item in schedule})
    summaries = [
        _summarize_candidate(plan, candidate_id, schedule, results, stage)
        for candidate_id in candidate_ids
    ]
    comparisons = [
        _comparison(a_id, b_id, schedule, results, summaries)
        for a_id, b_id in combinations(candidate_ids, 2)
    ]
    by_id = {item.candidate_id: item for item in summaries}
    baseline = by_id[plan.baseline_candidate_id]
    eligible: list[str] = []
    for item in summaries:
        if item.candidate_id == plan.baseline_candidate_id:
            continue
        if item.status != CampaignCandidateStatus.FULL_STAGE_ELIGIBLE:
            continue
        if (
            baseline.planned_units != baseline.completed_units
            or baseline.hard_safety_violations
            or baseline.unsupported_confirmations
            or baseline.provider_failures
            or baseline.harness_failures
            or baseline.identity_failures
            or baseline.status in {CampaignCandidateStatus.SAFETY_BLOCKED, CampaignCandidateStatus.RELIABILITY_BLOCKED}
        ):
            continue
        related = next((comparison for comparison in comparisons if {comparison.candidate_a, comparison.candidate_b} == {item.candidate_id, baseline.candidate_id}), None)
        if related is None or not related.valid:
            continue
        if item.successful_trials < baseline.successful_trials:
            continue
        eligible.append(item.candidate_id)
    # Full-stage eligibility is the final quality gate, not a complete promotion
    # decision. Security and context/tool validation remain separate explicit gates.
    if stage == CampaignStage.LIVE_FULL:
        eligible = []
        replacements = []
        for item in summaries:
            if item.candidate_id == plan.baseline_candidate_id or item.status != CampaignCandidateStatus.QUALITY_ELIGIBLE:
                replacements.append(item)
                continue
            if item.hard_safety_violations or item.unsupported_confirmations:
                replacements.append(item.model_copy(update={"status": CampaignCandidateStatus.SAFETY_BLOCKED}))
                continue
            if item.provider_failures or item.harness_failures or item.identity_failures:
                replacements.append(item.model_copy(update={"status": CampaignCandidateStatus.RELIABILITY_BLOCKED}))
                continue
            baseline_metrics = by_id[plan.baseline_candidate_id]
            dimensions = ("task_success_rate", "precision", "recall", "f1")
            measured = True
            regression = False
            for dimension in dimensions:
                left = getattr(baseline_metrics, dimension)
                right = getattr(item, dimension)
                if left.status != "MEASURED" or right.status != "MEASURED":
                    measured = False
                    continue
                regression = regression or float(right.value) < float(left.value)
            if not measured:
                replacements.append(item.model_copy(update={"status": CampaignCandidateStatus.INCONCLUSIVE}))
            elif regression:
                replacements.append(item.model_copy(update={"status": CampaignCandidateStatus.QUALITY_REGRESSION}))
            else:
                eligible.append(item.candidate_id)
                replacements.append(item)
        summaries = replacements
    return summaries, comparisons, sorted(eligible)


def _complete_summary(summary) -> bool:
    return (
        summary.planned_units > 0
        and summary.completed_units == summary.planned_units
        and summary.provider_failures == 0
        and summary.harness_failures == 0
        and summary.identity_failures == 0
    )


def _quality_values(summary) -> tuple[float, ...] | None:
    metrics = (summary.task_success_rate, summary.precision, summary.recall, summary.f1)
    if any(item.status != "MEASURED" or item.value is None for item in metrics):
        return None
    return tuple(float(item.value) for item in metrics)


def _efficiency_values(summary) -> tuple[float, ...] | None:
    metrics = (
        summary.input_tokens,
        summary.output_tokens,
        summary.measured_cost_usd,
        summary.mean_latency_ms,
    )
    if any(item.status != "MEASURED" or item.value is None for item in metrics):
        return None
    return (*tuple(float(item.value) for item in metrics), float(summary.tool_calls))


def _dominates(left, right) -> bool:
    left_quality, right_quality = _quality_values(left), _quality_values(right)
    left_efficiency, right_efficiency = _efficiency_values(left), _efficiency_values(right)
    if left_quality is None or right_quality is None or left_efficiency is None or right_efficiency is None:
        return False
    no_worse = all(a >= b for a, b in zip(left_quality, right_quality, strict=True)) and all(
        a <= b for a, b in zip(left_efficiency, right_efficiency, strict=True)
    )
    strictly_better = any(a > b for a, b in zip(left_quality, right_quality, strict=True)) or any(
        a < b for a, b in zip(left_efficiency, right_efficiency, strict=True)
    )
    return no_worse and strictly_better


def _review_sample(plan, result: CampaignUnitResult) -> CampaignReviewSample:
    if result.report is None or result.report.full_analysis is None:
        raise ValueError("review sample source is missing a full-analysis child report")
    case = next((item for item in result.report.case_results if item.case_id == result.unit.case_id), None)
    detail = next((
        item for item in result.report.full_analysis.trial_details
        if item.case_id == result.unit.case_id and item.trial_number == 1
    ), None)
    if case is None or not case.trials or detail is None:
        raise ValueError("review sample source trial is incomplete")
    candidate = next(item for item in plan.candidate_arms if item.candidate_id == result.unit.candidate_id)
    payload = {
        "campaign_id": plan.campaign_id,
        "plan_digest": plan.plan_digest,
        "source_revision": plan.source_revision,
        "candidate_id": candidate.candidate_id,
        "provider": candidate.provider.value,
        "model": candidate.requested_model,
        "system_identity_digest": candidate.system_identity_digest,
        "source_report_digest": result.report.report_digest,
        "case_id": result.unit.case_id,
        "trial_number": result.unit.trial_number,
        "grade": case.trials[0].model_dump(mode="json"),
        "failure_attribution_class": detail.failure_attribution.failure_class.value if detail.failure_attribution else None,
        "workflow_trace": [item.model_dump(mode="json") for item in detail.workflow_trace],
        "sample_policy_version": "live-model-campaign-review-sample/1.0",
    }
    return build_digested_model(CampaignReviewSample, payload, "sample_digest")


def build_analysis_report(
    plan,
    smoke: CampaignStageReport,
    pilot: CampaignStageReport,
    full: CampaignStageReport,
    *,
    security_gate=None,
    context_tool_gate=None,
):
    """Build a deterministic analysis. Missing supplemental gates mean no Pareto recommendation."""
    stages = (smoke, pilot, full)
    expected_stages = (
        CampaignStage.LIVE_SMOKE, CampaignStage.LIVE_PILOT, CampaignStage.LIVE_FULL,
    )
    for report, stage in zip(stages, expected_stages, strict=True):
        if (
            report.campaign_id != plan.campaign_id
            or report.plan_digest != plan.plan_digest
            or report.source_revision != plan.source_revision
            or report.stage != stage
            or report.mode != "LIVE"
            or report.execution_status.value != "COMPLETED"
        ):
            raise ValueError("analysis requires the ordered complete smoke, pilot, and full reports from one frozen campaign")
    full_candidate_ids = {item.candidate_id for item in full.candidate_summaries}
    if plan.baseline_candidate_id not in full_candidate_ids or len(full_candidate_ids) != 2:
        raise ValueError("analysis requires the baseline and exactly one completed finalist")

    from app.evaluation.campaign.contracts import SupplementalGateKind, SupplementalGateStatus

    expected_gate_candidates = full_candidate_ids
    for report, gate in (
        (security_gate, SupplementalGateKind.SECURITY),
        (context_tool_gate, SupplementalGateKind.CONTEXT_TOOL),
    ):
        if report is not None and (
            report.campaign_id != plan.campaign_id
            or report.plan_digest != plan.plan_digest
            or report.source_revision != plan.source_revision
            or report.gate != gate
            or {item.candidate_id for item in report.candidates} != expected_gate_candidates
        ):
            raise ValueError("supplemental gate report is incompatible with the frozen full-stage candidate pair")

    summaries = full.candidate_summaries
    baseline = next(item for item in summaries if item.candidate_id == plan.baseline_candidate_id)
    baseline_quality = _quality_values(baseline)
    baseline_efficiency = _efficiency_values(baseline)
    security_status = security_gate.status if security_gate else SupplementalGateStatus.INCONCLUSIVE
    context_status = context_tool_gate.status if context_tool_gate else SupplementalGateStatus.INCONCLUSIVE
    gates_pass = security_status == context_status == SupplementalGateStatus.PASS
    gate_candidate_statuses = {
        item.candidate_id: (item.status if gates_pass else SupplementalGateStatus.INCONCLUSIVE)
        for receipt in (security_gate, context_tool_gate) if receipt is not None
        for item in receipt.candidates
    }
    full_by_id = {item.candidate_id: item for item in summaries}
    safety_blocked = sorted(
        item.candidate_id for item in summaries
        if item.hard_safety_violations > 0 or item.unsupported_confirmations > 0
        or gate_candidate_statuses.get(item.candidate_id) == SupplementalGateStatus.HARD_FAIL
    )
    reliability_blocked = sorted(
        item.candidate_id for item in summaries
        if item.provider_failures or item.harness_failures or item.identity_failures
        or item.status == CampaignCandidateStatus.RELIABILITY_BLOCKED
    )
    quality_eligible: list[str] = []
    inconclusive: list[str] = []
    for item in summaries:
        if item.candidate_id == plan.baseline_candidate_id:
            continue
        candidate_quality = _quality_values(item)
        if item.candidate_id in safety_blocked or item.candidate_id in reliability_blocked:
            continue
        if item.status != CampaignCandidateStatus.QUALITY_ELIGIBLE or candidate_quality is None or baseline_quality is None:
            inconclusive.append(item.candidate_id)
            continue
        if any(new < old for new, old in zip(candidate_quality, baseline_quality, strict=True)):
            inconclusive.append(item.candidate_id)
            continue
        quality_eligible.append(item.candidate_id)

    pareto: list[str] = []
    human_review: list[str] = []
    sample_results: list[CampaignReviewSample] = []
    if gates_pass and not safety_blocked and not reliability_blocked:
        candidate_ids = sorted(full_candidate_ids)
        for candidate_id in candidate_ids:
            rows = [item for item in full.unit_results if item.unit.candidate_id == candidate_id and item.report is not None]
            failures = [
                item for item in rows
                if not any(
                    trial.task_success is True
                    for case in item.report.case_results for trial in case.trials
                )
            ]
            pool = failures or rows
            if pool:
                selected = min(
                    pool,
                    key=lambda item: canonical_digest({
                        "seed": plan.schedule_seed,
                        "candidate_id": candidate_id,
                        "case_id": item.unit.case_id,
                        "trial_number": item.unit.trial_number,
                        "purpose": "review-sample/1.0",
                    }),
                )
                sample_results.append(_review_sample(plan, selected))

        if baseline_quality is not None and baseline_efficiency is not None and _complete_summary(baseline):
            pareto.append(plan.baseline_candidate_id)
            for candidate_id in quality_eligible:
                candidate = full_by_id[candidate_id]
                quality_values = _quality_values(candidate)
                efficiency_values = _efficiency_values(candidate)
                if quality_values is None or efficiency_values is None:
                    continue
                if any(new < old for new, old in zip(quality_values, baseline_quality, strict=True)):
                    continue
                dominated = False
                for other_id in quality_eligible:
                    if other_id == candidate_id:
                        continue
                    if _dominates(full_by_id[other_id], candidate):
                        dominated = True
                        break
                if not dominated:
                    pareto.append(candidate_id)
                improved = any(new > old for new, old in zip(quality_values, baseline_quality, strict=True)) or any(
                    new < old for new, old in zip(efficiency_values, baseline_efficiency, strict=True)
                )
                if not dominated and improved:
                    human_review.append(candidate_id)

    payload = {
        "campaign_id": plan.campaign_id,
        "plan_digest": plan.plan_digest,
        "source_revision": plan.source_revision,
        "stage_report_digests": [item.report_digest for item in stages]
        + ([security_gate.report_digest] if security_gate else [])
        + ([context_tool_gate.report_digest] if context_tool_gate else []),
        "review_sample_digests": [item.sample_digest for item in sample_results],
        "candidate_summaries": [item.model_dump(mode="json") for item in summaries],
        "pairwise_comparisons": [item.model_dump(mode="json") for item in full.pairwise_comparisons],
        "quality_eligible_candidate_ids": sorted(quality_eligible),
        "safety_blocked_candidate_ids": safety_blocked,
        "reliability_blocked_candidate_ids": reliability_blocked,
        "inconclusive_candidate_ids": sorted(inconclusive),
        "pareto_candidate_ids": sorted(set(pareto)),
        "security_gate_status": security_status.value,
        "security_gate_digest": security_gate.report_digest if security_gate else None,
        "context_tool_gate_status": context_status.value,
        "context_tool_gate_digest": context_tool_gate.report_digest if context_tool_gate else None,
        "human_review_eligible_candidate_ids": sorted(set(human_review)),
        "review_status": "NOT_REVIEWED",
    }
    report = build_digested_model(CampaignAnalysisReport, payload, "report_digest")
    return report, sample_results


__all__ = ["build_analysis_report", "summarize_stage"]
