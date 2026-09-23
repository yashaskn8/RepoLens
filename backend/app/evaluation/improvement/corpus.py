"""Build an attribution-led, public-DEV-only and content-minimized corpus."""

from __future__ import annotations

from app.evaluation.ground_truth.loader import compute_canonical_benchmark_hash
from app.evaluation.ground_truth.public_dev import (
    PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS,
    load_public_dev_repository_cases,
)
from app.evaluation.improvement.contracts import (
    ImprovementCorpus,
    ImprovementExample,
    SafeImprovementEvent,
)
from app.evaluation.improvement.digest import canonical_digest
from app.evaluation.improvement.policy import ImprovementPolicy
from app.evaluation.system.schemas import EvaluationRunStatus, FailureClass, SystemEvaluationReport
from app.security.redaction import redact_secrets


FAILURE_TARGETS: dict[FailureClass, str] = {
    FailureClass.VERIFIER_FALSE_REJECTION: "verifier-agent",
    FailureClass.VERIFIER_FALSE_CONFIRMATION: "verifier-agent",
    FailureClass.INVESTIGATOR_INSUFFICIENT_EVIDENCE: "evidence-investigator",
    FailureClass.REVISION_FAILED_TO_REPAIR: "revision-agent",
}


def assert_public_dev_report_inventory(report: SystemEvaluationReport) -> None:
    """Reject report references outside public DEV before serializing trial data."""
    allowed = set(PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS)
    if set(report.expected_case_ids) != allowed or set(report.evaluated_case_ids) != allowed:
        raise ValueError("baseline report references cases outside the public DEV repository-scan inventory")
    if len(report.expected_case_ids) != len(allowed) or len(report.evaluated_case_ids) != len(allowed):
        raise ValueError("baseline report contains duplicate or incomplete public DEV case references")
    if any(item.case_id not in allowed for item in report.case_results):
        raise ValueError("baseline report contains a non-public case result")
    if report.full_analysis is not None and any(
        item.case_id not in allowed for item in report.full_analysis.trial_details
    ):
        raise ValueError("baseline report contains a non-public trial detail")


def partition_public_dev_cases(
    case_ids: list[str],
    policy: ImprovementPolicy,
    *,
    family_by_case: dict[str, str] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Stable family-safe-by-case split. Validation labels never enter reflection."""
    families: dict[str, list[str]] = {}
    for case_id in case_ids:
        family = (family_by_case or {}).get(case_id, case_id)
        families.setdefault(family, []).append(case_id)
    ordered_families = sorted(
        families,
        key=lambda value: canonical_digest({"policy": policy.corpus_selection_policy, "case_family": value}),
    )
    if len(ordered_families) < 2:
        raise ValueError("prompt improvement needs at least two public DEV cases for a validation split")
    validation_count = max(1, round(len(ordered_families) * policy.validation_partition_percent / 100))
    validation_count = min(validation_count, len(ordered_families) - 1)
    validation_families = set(ordered_families[:validation_count])
    validation = tuple(sorted(case for family in validation_families for case in families[family]))
    optimization = tuple(sorted(case for family in set(families) - validation_families for case in families[family]))
    return optimization, validation


def _safe_events(events, policy: ImprovementPolicy) -> tuple[tuple[SafeImprovementEvent, ...], bool]:
    selected = events[-policy.max_trace_events_per_example:]
    normalized = tuple(
        SafeImprovementEvent(
            node=item.node,
            status=item.status,
            duration_ms=min(item.duration_ms, 1_000_000_000.0),
            model_identities=tuple(_short(value, 128) for value in item.model_identities[:8]),
            model_execution_count=item.model_execution_count or 0,
            tool_names=tuple(_short(value, 64) for value in item.tool_names[:8]),
            tool_execution_count=item.tool_execution_count,
            evidence_count=min(item.evidence_count, 1_000_000),
            failure_codes=tuple(_short(value, 128) for value in item.failure_codes[:8]),
        )
        for item in selected
    )
    truncated = len(events) > policy.max_trace_events_per_example or any(
        len(item.model_identities) > 8 or len(item.tool_names) > 8 or len(item.failure_codes) > 8
        or item.duration_ms > 1_000_000_000.0 or item.evidence_count > 1_000_000
        or any(len(redact_secrets(value)) > 128 for value in item.model_identities[:8])
        or any(len(redact_secrets(value)) > 64 for value in item.tool_names[:8])
        or any(len(redact_secrets(value)) > 128 for value in item.failure_codes[:8])
        for item in selected
    )
    return normalized, truncated


def _short(value: str, limit: int = 512) -> str:
    return _short_bounded(value, limit)[0]


def _short_bounded(value: str, limit: int) -> tuple[str, bool]:
    sanitized = redact_secrets(value).replace("\r", " ").replace("\n", " ")
    return sanitized[:limit], len(sanitized) > limit


def build_improvement_corpus(
    report: SystemEvaluationReport,
    *,
    policy: ImprovementPolicy | None = None,
    require_live: bool = False,
) -> ImprovementCorpus:
    """Use only current canonical public DEV full-analysis reports.

    No dataset path is accepted and no holdout loader is called. The report itself
    is integrity-validated by its immutable Pydantic contract before selection.
    """
    selected_policy = policy or ImprovementPolicy()
    if report.scope != "FULL_ANALYSIS_GRAPH" or report.full_analysis is None:
        raise ValueError("improvement corpus requires a full-analysis report")
    if report.suite.value != "ALL" or report.execution_status != EvaluationRunStatus.COMPLETED:
        raise ValueError("improvement corpus requires a completed full DEV ALL-suite report")
    if require_live and report.mode.value != "LIVE":
        raise ValueError("semantic prompt optimization requires a genuine LIVE baseline; scripted runs are harness validation")
    if report.full_analysis.dataset_split != "DEV" or report.full_analysis.target_pipeline != "REPOSITORY_SCAN":
        raise ValueError("only public DEV repository-scan reports are eligible")
    assert_public_dev_report_inventory(report)
    SystemEvaluationReport.model_validate(report.model_dump(mode="json"))

    public_cases = load_public_dev_repository_cases()
    public_ids = [item.case_id for item in public_cases]
    if report.expected_case_ids != public_ids or report.evaluated_case_ids != public_ids:
        raise ValueError("baseline does not cover the current canonical public DEV repository-scan case inventory")
    if report.dataset_hash != compute_canonical_benchmark_hash(public_cases):
        raise ValueError("baseline dataset digest is stale or incompatible")
    if report.full_analysis.dataset_case_count != len(public_cases):
        raise ValueError("baseline full-analysis case count is incomplete")

    optimization_ids, validation_ids = partition_public_dev_cases(
        public_ids,
        selected_policy,
        family_by_case={item.case_id: item.case_family for item in public_cases},
    )
    optimization_set = set(optimization_ids)
    detail_by_trial = {
        (item.case_id, item.trial_number): item
        for item in report.full_analysis.trial_details
    }
    grade_by_trial = {
        (case.case_id, grade.trial_number): grade
        for case in report.case_results for grade in case.trials
    }
    examples: list[ImprovementExample] = []
    example_keys: set[tuple[str, str, str]] = set()
    preserve_by_component: dict[str, dict[str, ImprovementExample]] = {}

    for key, grade in grade_by_trial.items():
        detail = detail_by_trial.get(key)
        if detail is None:
            raise ValueError("baseline trial inventory is incomplete")
        if grade.task_success is False and detail.failure_attribution is None:
            raise ValueError("baseline contains a failed trial without deterministic failure attribution")
        if key[0] not in optimization_set:
            continue
        if grade.task_success is False and detail.failure_attribution is not None:
            attribution = detail.failure_attribution
            target = FAILURE_TARGETS.get(attribution.failure_class)
            if target is None:
                continue
            example_key = (key[0], target, attribution.failure_class.value)
            if example_key in example_keys:
                continue
            example_keys.add(example_key)
            observed, observed_truncated = _short_bounded(attribution.observed_behavior, 512)
            expected, expected_truncated = _short_bounded(attribution.expected_behavior, 512)
            downstream, downstream_truncated = _short_bounded(attribution.downstream_effect, 512)
            bounded_evidence = tuple(
                _short(value, 160)
                for value in attribution.evidence_refs[:selected_policy.max_evidence_refs_per_example]
            )
            events, events_truncated = _safe_events(detail.workflow_trace, selected_policy)
            truncated_fields = []
            if observed_truncated:
                truncated_fields.append("observed_behavior")
            if expected_truncated:
                truncated_fields.append("expected_behavior")
            if downstream_truncated:
                truncated_fields.append("downstream_effect")
            if len(attribution.evidence_refs) > selected_policy.max_evidence_refs_per_example or any(
                len(redact_secrets(value)) > 160
                for value in attribution.evidence_refs[:selected_policy.max_evidence_refs_per_example]
            ):
                truncated_fields.append("evidence_refs")
            if events_truncated:
                truncated_fields.append("workflow_events")
            if len(detail.security_violation_codes) > 32 or any(
                len(redact_secrets(value)) > 128 for value in detail.security_violation_codes[:32]
            ):
                truncated_fields.append("safety_codes")
            examples.append(ImprovementExample(
                case_id=key[0],
                target_prompt_component=target,
                failure_class=attribution.failure_class,
                failure_stage=attribution.failure_stage,
                primary_node=attribution.primary_node,
                observed_behavior=observed,
                expected_behavior=expected,
                supporting_evidence_refs=bounded_evidence,
                downstream_effect=downstream,
                workflow_events=events,
                safety_codes=tuple(_short(value, 128) for value in detail.security_violation_codes[:32]),
                truncated_fields=tuple(truncated_fields),
                baseline_system_digest=report.system_identity.system_digest,
                baseline_report_digest=report.report_digest,
                outcome="FAILURE",
            ))
        elif grade.task_success is True:
            successful_nodes = {event.node for event in detail.workflow_trace}
            for target, node in (
                ("architecture-agent", "architecture"),
                ("security-agent", "security"),
                ("bug-agent", "bug"),
                ("verifier-agent", "verifier"),
                ("revision-agent", "revise"),
                ("evidence-investigator", "investigator_decide"),
            ):
                if node not in successful_nodes:
                    continue
                events, events_truncated = _safe_events(detail.workflow_trace, selected_policy)
                preserve_by_component.setdefault(target, {}).setdefault(key[0], ImprovementExample(
                    case_id=key[0],
                    target_prompt_component=target,
                    failure_class=None,
                    failure_stage="PRESERVED_SUCCESS",
                    primary_node=node,
                    observed_behavior="The complete public DEV trial met RepoLens deterministic task-success criteria.",
                    expected_behavior="Preserve the behavior that produced a successful task outcome.",
                    supporting_evidence_refs=(),
                    downstream_effect="No downstream failure was attributed in this successful trial.",
                    workflow_events=events,
                    safety_codes=(),
                    truncated_fields=("workflow_events",) if events_truncated else (),
                    baseline_system_digest=report.system_identity.system_digest,
                    baseline_report_digest=report.report_digest,
                    outcome="PRESERVE",
                ))

    examples.sort(key=lambda item: (item.target_prompt_component, item.case_id, item.failure_stage))
    preserve: list[ImprovementExample] = []
    for target in sorted(preserve_by_component):
        eligible = [item for item in preserve_by_component[target].values() if item.case_id in optimization_set]
        eligible.sort(key=lambda item: canonical_digest({"target": target, "case_id": item.case_id}))
        preserve.extend(eligible[:selected_policy.max_preserve_examples])
    selection_payload = {
        "policy": selected_policy.corpus_selection_policy,
        "optimization_case_digest": canonical_digest(list(optimization_ids)),
        "validation_case_digest": canonical_digest(list(validation_ids)),
        "failure_targets": {key.value: value for key, value in FAILURE_TARGETS.items()},
    }
    payload = {
        "schema_version": "improvement-corpus/1.0",
        "baseline_report_digest": report.report_digest,
        "baseline_system_digest": report.system_identity.system_digest,
        "optimization_examples": [item.model_dump(mode="json") for item in examples],
        "preserve_examples": [item.model_dump(mode="json") for item in preserve],
        "validation_case_ids": list(validation_ids),
        "selection_policy": selected_policy.corpus_selection_policy,
        "selection_digest": canonical_digest(selection_payload),
        "truncated": (
            len(examples) > selected_policy.max_reflection_examples
            or any(item.truncated_fields for item in (*examples, *preserve))
        ),
    }
    payload["optimization_examples"] = payload["optimization_examples"][:64]
    payload["preserve_examples"] = payload["preserve_examples"][:16]
    payload["corpus_digest"] = canonical_digest(payload)
    return ImprovementCorpus.model_validate(payload)


def examples_for_target(corpus: ImprovementCorpus, component: str, policy: ImprovementPolicy | None = None):
    selected_policy = policy or ImprovementPolicy()
    failures = [item for item in corpus.optimization_examples if item.target_prompt_component == component]
    failures.sort(key=lambda item: (item.failure_class.value if item.failure_class else "", item.case_id))
    grouped: dict[str, list[ImprovementExample]] = {}
    for item in failures:
        assert item.failure_class is not None
        grouped.setdefault(item.failure_class.value, []).append(item)
    prioritized = [item for group in sorted(grouped) for item in grouped[group]]
    seen: set[str] = set()
    unique: list[ImprovementExample] = []
    for item in prioritized:
        if item.case_id in seen:
            continue
        seen.add(item.case_id)
        unique.append(item)
    preserve = [item for item in corpus.preserve_examples if item.target_prompt_component == component]
    preserve.sort(key=lambda item: item.case_id)
    return (
        tuple(unique[:selected_policy.max_reflection_examples]),
        tuple(preserve[:selected_policy.max_preserve_examples]),
    )


__all__ = [
    "FAILURE_TARGETS", "assert_public_dev_report_inventory", "build_improvement_corpus",
    "examples_for_target", "partition_public_dev_cases",
]
