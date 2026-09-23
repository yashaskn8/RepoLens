"""Ground-truth-bounded closed intervention selection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.evaluation.ground_truth.matcher import EvaluatedFinding, IndependentBenchmarkJudge
from app.evaluation.ground_truth.schemas import BenchmarkCase, EvaluationStage
from app.evaluation.system.schemas import FailureAttribution, FailureClass


@dataclass(frozen=True)
class ReplayEligibility:
    eligible: bool
    reason_code: str
    intervention_kind: str | None = None
    target_node: str | None = None
    target_finding_id: str | None = None


def _value(item: Any, name: str, default: Any = None) -> Any:
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def _id(item: Any) -> str:
    return str(_value(item, "id", "") or "")


def _finding_evaluations(item: Any, stage: EvaluationStage) -> list[EvaluatedFinding]:
    evidences = _value(item, "evidences", []) or []
    rule_id = str(
        _value(item, "rule_id") or _value(item, "source_tool")
        or _value(item, "detector_id") or "UNCLASSIFIED"
    )[:256]
    return [
        EvaluatedFinding(
            rule_id=rule_id,
            file_path=str(_value(evidence, "file_path", "") or "")[:1024],
            start_line=_value(evidence, "start_line"),
            end_line=_value(evidence, "end_line"),
            stage=stage,
        )
        for evidence in evidences[:8]
        if _value(evidence, "file_path")
    ]


def _structurally_matched_candidate_ids(
    case: BenchmarkCase,
    candidates: list[Any],
    rejected_ids: set[str],
    judge: IndependentBenchmarkJudge,
) -> set[str]:
    manifest_files = set(case.fixture.files)
    line_counts = {path: len(content.splitlines()) for path, content in case.fixture.files.items()}
    matches: set[str] = set()
    for candidate in candidates[:128]:
        finding_id = _id(candidate)
        if not finding_id or finding_id not in rejected_ids:
            continue
        matched_claims: set[int] = set()
        for evaluated in _finding_evaluations(candidate, EvaluationStage.ANALYSIS_CANDIDATE):
            if not judge._check_reference_validity(evaluated, manifest_files, line_counts):
                continue
            for index, claim in enumerate(case.annotation.claims):
                if judge._matches_claim(evaluated, claim)[0]:
                    matched_claims.add(index)
        if len(matched_claims) == 1:
            matches.add(finding_id)
    return matches


def select_replay_intervention(
    case: BenchmarkCase,
    factual_state: Mapping[str, Any],
    attribution: FailureAttribution | None,
    *,
    judged: Any,
    published_judged: Any,
    judge: IndependentBenchmarkJudge,
) -> ReplayEligibility:
    """Derive one intervention from deterministic attribution and exact output.

    Benchmark labels are consumed only here and by grading; they are never
    copied into graph state or model context.
    """
    if attribution is None:
        return ReplayEligibility(False, "NO_DETERMINISTIC_ATTRIBUTION")
    if attribution.hard_safety_violation and attribution.failure_class != FailureClass.VERIFIER_FALSE_CONFIRMATION:
        return ReplayEligibility(False, "HARD_SAFETY_PRECEDENCE")
    if factual_state.get("status") == "FAILED" or factual_state.get("errors"):
        return ReplayEligibility(False, "FACTUAL_INFRASTRUCTURE_FAILURE")

    failure = attribution.failure_class
    if failure == FailureClass.VERIFIER_FALSE_REJECTION:
        trace = factual_state.get("workflow_trace", [])
        rejected_ids = {
            str(finding_id)
            for event in trace if isinstance(event, Mapping) and event.get("node") == "verifier"
            for finding_id in event.get("rejected_ids", [])
        }
        candidate_ids = _structurally_matched_candidate_ids(
            case, list(factual_state.get("candidate_findings", [])), rejected_ids, judge,
        )
        if len(candidate_ids) != 1:
            return ReplayEligibility(False, "AMBIGUOUS_OR_UNPROVEN_MATCHED_CANDIDATE")
        target_id = next(iter(candidate_ids))
        if not any(
            str(_value(item, "finding_id", "") or "") == target_id
            for item in factual_state.get("rejected_findings", [])
            if isinstance(item, Mapping)
        ):
            return ReplayEligibility(False, "TARGET_NOT_IN_VERIFIER_REJECTION_STATE")
        return ReplayEligibility(
            True,
            "ELIGIBLE_VERIFIER_FALSE_REJECTION",
            "VERIFIER_ACCEPT_MATCHED_FINDING",
            "verifier",
            target_id,
        )

    if failure == FailureClass.VERIFIER_FALSE_CONFIRMATION:
        verified = list(factual_state.get("verified_findings", []))
        false_positive_ids: set[str] = set()
        for finding in verified[:128]:
            finding_id = _id(finding)
            if not finding_id:
                continue
            evaluated = _finding_evaluations(finding, EvaluationStage.PUBLISHED_FINDING)
            if not evaluated:
                continue
            one_finding = judge.evaluate_case(
                case,
                evaluated,
                set(case.fixture.files),
                {path: len(content.splitlines()) for path, content in case.fixture.files.items()},
            )
            if one_finding.fp > 0 or one_finding.unsupported_claim_count > 0 or one_finding.invalid_reference_count > 0:
                false_positive_ids.add(finding_id)
        if len(false_positive_ids) != 1:
            return ReplayEligibility(False, "AMBIGUOUS_OR_UNPROVEN_UNSUPPORTED_TARGET")
        target_id = next(iter(false_positive_ids))
        return ReplayEligibility(
            True,
            "ELIGIBLE_VERIFIER_FALSE_CONFIRMATION",
            "VERIFIER_REJECT_UNSUPPORTED_FINDING",
            "verifier",
            target_id,
        )

    if failure == FailureClass.REVISION_FAILED_TO_REPAIR:
        candidate_ids = {_id(item) for item in factual_state.get("candidate_findings", [])[:128]}
        attributed_ids = set(attribution.evidence_refs) & candidate_ids
        if len(attributed_ids) != 1:
            return ReplayEligibility(False, "AMBIGUOUS_OR_MISSING_PRE_REVISION_CANDIDATE")
        target_id = next(iter(attributed_ids))
        return ReplayEligibility(
            True,
            "ELIGIBLE_REVISION_FAILED_TO_REPAIR",
            "REVISION_RESTORE_VALID_CANDIDATE",
            "revise",
            target_id,
        )

    if failure == FailureClass.SPECIALIST_MISSED_FINDING:
        return ReplayEligibility(False, "NO_FAITHFUL_SPECIALIST_ACTION_INTERVENTION")
    return ReplayEligibility(False, f"FAILURE_CLASS_NOT_SUPPORTED:{failure.value}")


__all__ = ["ReplayEligibility", "select_replay_intervention"]
