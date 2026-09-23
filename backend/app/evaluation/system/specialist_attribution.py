"""Proof checks for safe specialist attribution in full-analysis reports."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Sequence

from app.agents.specialist_provenance import SpecialistCandidateProvenance, SpecialistOpportunityRecord
from app.evaluation.ground_truth.matcher import (
    CaseEvaluationResult,
    EvaluatedFinding,
    IndependentBenchmarkJudge,
    normalize_symbol,
    normalize_repo_path,
)
from app.evaluation.ground_truth.schemas import BenchmarkCase, EvaluationStage
from app.evaluation.system.schemas import FailureAttribution, FailureClass, WorkflowNodeEvent
from app.llm.types import LLMProvider


SPECIALIST_PROMPT_COMPONENTS = {
    "architecture": "architecture-agent",
    "security": "security-agent",
    "bug": "bug-agent",
}

# Frozen benchmark runner semantics are deliberately projected into this
# evaluation-only attribution contract. The runner and production candidate
# generator remain untouched; unsupported kinds remain non-targetable.
SPECIALIST_CANDIDATE_RULE_CONTRACTS: dict[tuple[str, str], tuple[str, str]] = {
    ("security", "INPUT_TO_DATABASE"): ("INTERPROCEDURAL_FLOW_SQLI", "SECURITY"),
    ("security", "INPUT_TO_COMMAND"): ("INTERPROCEDURAL_FLOW_CMDI", "SECURITY"),
    ("security", "INPUT_TO_FILESYSTEM"): ("INTERPROCEDURAL_FLOW_PATH_TRAVERSAL", "SECURITY"),
    ("bug", "BROAD_EXCEPTION_SWALLOW"): ("BROAD_EXCEPTION_SWALLOW", "CORRECTNESS"),
    ("bug", "BLOCKING_CALL_IN_ASYNC"): ("BLOCKING_API_IN_ASYNC", "CORRECTNESS"),
    ("bug", "ASYNC_BLOCKING_CALL"): ("BLOCKING_API_IN_ASYNC", "CORRECTNESS"),
    ("bug", "UNAWAITED_ASYNC_CALL"): ("UNAWAITED_ASYNC_CALL", "CORRECTNESS"),
}


@dataclass(frozen=True, slots=True)
class SpecialistOpportunityMatch:
    node: str
    component: str
    candidate_id: str | None
    record_digest: str
    claim_id: str


@dataclass(frozen=True, slots=True)
class SpecialistAttributionEvidence:
    targetable: tuple[SpecialistOpportunityMatch, ...] = ()
    context_omissions: tuple[SpecialistOpportunityMatch, ...] = ()
    not_executed: tuple[SpecialistOpportunityMatch, ...] = ()
    input_gaps: tuple[SpecialistOpportunityMatch, ...] = ()


def snapshot_id_for_case(case: BenchmarkCase) -> str:
    payload = json.dumps(case.fixture.files, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def _claim_id(claim) -> str:
    return f"{claim.rule_id}@{claim.permitted_files[0]}"


def _matches_claim_location(
    finding: EvaluatedFinding,
    claim,
    judge: IndependentBenchmarkJudge,
) -> bool:
    """Apply the frozen judge's deterministic locator contract without grading.

    This intentionally checks only rule, permitted path, symbol, and span. It
    never changes the benchmark matcher or treats the location as semantic
    proof; the ordinary independent judge remains the only grading authority.
    """
    if finding.rule_id != claim.rule_id:
        return False
    if normalize_repo_path(finding.file_path) not in {
        normalize_repo_path(path) for path in claim.permitted_files
    }:
        return False
    symbol_matched = not claim.permitted_symbols
    if claim.permitted_symbols:
        allowed_symbols = {normalize_symbol(value) for value in claim.permitted_symbols if value}
        normalized_symbol = normalize_symbol(finding.symbol)
        if normalized_symbol and normalized_symbol in allowed_symbols:
            symbol_matched = True
        elif finding.symbol:
            return False
    if claim.permitted_spans:
        if finding.start_line is not None:
            if not any(
                start - judge.line_tolerance <= finding.start_line <= end + judge.line_tolerance
                for start, end in claim.permitted_spans
            ):
                return False
        elif not symbol_matched:
            return False
    return True


def _record(event: WorkflowNodeEvent, case: BenchmarkCase) -> SpecialistOpportunityRecord | None:
    record = event.specialist_opportunity
    if record is None or event.node not in SPECIALIST_PROMPT_COMPONENTS:
        return None
    if record.node != event.node or record.snapshot_id != snapshot_id_for_case(case):
        return None
    return record


def _proves_live_model_execution(
    event: WorkflowNodeEvent,
    record: SpecialistOpportunityRecord,
) -> bool:
    """Reject scripted harnesses and incomplete model provenance as prompt evidence."""
    if (
        not record.model_succeeded
        or record.model_execution_count < 1
        or event.model_execution_count != record.model_execution_count
        or not event.model_identities
    ):
        return False
    supported = {provider.value for provider in LLMProvider}
    for identity in event.model_identities:
        provider, separator, model = identity.partition(":")
        if not separator or provider.lower() not in supported or not model.strip():
            return False
    return True


def _candidate_matches_claim(
    candidate: SpecialistCandidateProvenance,
    *,
    node: str,
    case: BenchmarkCase,
    claim,
    judge: IndependentBenchmarkJudge,
    require_packed: bool,
) -> bool:
    rule_contract = SPECIALIST_CANDIDATE_RULE_CONTRACTS.get((node, candidate.candidate_kind))
    if rule_contract is None:
        return False
    rule_id, category = rule_contract
    if rule_id != claim.rule_id or category != case.category.value:
        return False

    locations: list[tuple[str, str | None, int | None, int | None]] = []
    if not require_packed and candidate.candidate_file_path:
        locations.append((candidate.candidate_file_path, candidate.related_symbol, candidate.candidate_line, None))
    if candidate.packed:
        packed_refs = set(candidate.packed_evidence_refs)
        locations.extend(
            (item.file_path, item.symbol or candidate.related_symbol, item.start_line, item.end_line)
            for item in candidate.packed_locations
            if item.evidence_id in packed_refs
        )
        if candidate.candidate_file_path and candidate.candidate_line is not None and any(
            normalize_repo_path(item.file_path) == normalize_repo_path(candidate.candidate_file_path)
            for item in candidate.packed_locations
            if item.evidence_id in packed_refs
        ):
            # The candidate metadata is part of the packed hypothesis. Its
            # exact source line is useful when a packed chunk spans many lines.
            locations.append((candidate.candidate_file_path, candidate.related_symbol, candidate.candidate_line, None))

    fixture_paths = {normalize_repo_path(path) for path in case.fixture.files}
    line_counts = {path: len(content.splitlines()) for path, content in case.fixture.files.items()}
    for path, symbol, start_line, end_line in locations:
        normalized = normalize_repo_path(path)
        if normalized not in fixture_paths:
            continue
        if start_line is not None and start_line > line_counts.get(path, line_counts.get(normalized, 0)) + 10:
            continue
        finding = EvaluatedFinding(
            rule_id=rule_id,
            file_path=path,
            symbol=symbol,
            start_line=start_line,
            end_line=end_line,
            stage=EvaluationStage.ANALYSIS_CANDIDATE,
        )
        if _matches_claim_location(finding, claim, judge):
            return True
    return False


def specialist_opportunity_evidence(
    case: BenchmarkCase,
    evaluation: CaseEvaluationResult,
    trace: Sequence[WorkflowNodeEvent],
    judge: IndependentBenchmarkJudge,
) -> SpecialistAttributionEvidence:
    """Find unique, evidence-packed specialist opportunities for unmatched claims."""
    unmatched = set(evaluation.unmatched_claim_ids)
    targetable: list[SpecialistOpportunityMatch] = []
    omissions: list[SpecialistOpportunityMatch] = []
    not_executed: list[SpecialistOpportunityMatch] = []
    for claim in case.annotation.claims:
        claim_id = _claim_id(claim)
        if claim_id not in unmatched:
            continue
        for event in trace:
            record = _record(event, case)
            if record is None:
                continue
            component = SPECIALIST_PROMPT_COMPONENTS[event.node]
            for candidate in record.candidates:
                if not _candidate_matches_claim(
                    candidate,
                    node=event.node,
                    case=case,
                    claim=claim,
                    judge=judge,
                    require_packed=False,
                ):
                    continue
                match = SpecialistOpportunityMatch(
                    node=event.node,
                    component=component,
                    candidate_id=candidate.candidate_id,
                    record_digest=record.record_digest,
                    claim_id=claim_id,
                )
                if not record.model_attempted or record.completion_reason == "ADMISSION_BLOCKED":
                    not_executed.append(match)
                    continue
                if not _proves_live_model_execution(event, record) or event.status != "COMPLETED" or event.failure_codes:
                    # Provider, budget, schema, and node failures are never
                    # converted into autonomous prompt blame.
                    continue
                if candidate.packed and not candidate.evidence_truncated and candidate.packed_evidence_refs and _candidate_matches_claim(
                    candidate,
                    node=event.node,
                    case=case,
                    claim=claim,
                    judge=judge,
                    require_packed=True,
                ):
                    emitted_claim = False
                    for ref in event.finding_refs:
                        finding_id = str(ref.get("finding_id") or "")
                        if finding_id not in record.model_output_candidate_ids:
                            continue
                        rule_id = str(ref.get("rule_id") or "")
                        evidences = ref.get("evidences", [])
                        if rule_id != claim.rule_id or not isinstance(evidences, list):
                            continue
                        for evidence in evidences[:8]:
                            if not isinstance(evidence, dict):
                                continue
                            emitted = EvaluatedFinding(
                                rule_id=rule_id,
                                file_path=str(evidence.get("file_path") or ""),
                                start_line=evidence.get("start_line"),
                                end_line=evidence.get("end_line"),
                                stage=EvaluationStage.ANALYSIS_CANDIDATE,
                            )
                            if _matches_claim_location(emitted, claim, judge):
                                emitted_claim = True
                                break
                        if emitted_claim:
                            break
                    if not emitted_claim:
                        targetable.append(match)
                else:
                    omissions.append(match)
    return SpecialistAttributionEvidence(
        targetable=tuple(targetable),
        context_omissions=tuple(omissions),
        not_executed=tuple(not_executed),
    )


def specialist_input_gap_evidence(
    case: BenchmarkCase,
    evaluation: CaseEvaluationResult,
    trace: Sequence[WorkflowNodeEvent],
    judge: IndependentBenchmarkJudge,
) -> tuple[SpecialistOpportunityMatch, ...]:
    """Prove an upstream input gap only from a complete snapshot-bound inventory."""
    unmatched = set(evaluation.unmatched_claim_ids)
    gaps: list[SpecialistOpportunityMatch] = []
    for claim in case.annotation.claims:
        claim_id = _claim_id(claim)
        if claim_id not in unmatched:
            continue
        contracts = [
            (node, candidate_kind)
            for (node, candidate_kind), (rule_id, category) in SPECIALIST_CANDIDATE_RULE_CONTRACTS.items()
            if rule_id == claim.rule_id and category == case.category.value
        ]
        nodes = {node for node, _ in contracts}
        if len(nodes) != 1:
            continue
        node = next(iter(nodes))
        node_events = [event for event in trace if event.node == node]
        if len(node_events) != 1:
            continue
        event = node_events[0]
        record = _record(event, case)
        if (
            record is None
            or event.status != "COMPLETED"
            or event.failure_codes
            or record.completion_reason != "NO_DETERMINISTIC_CANDIDATES"
            or record.candidate_source != "NONE"
            or record.candidate_count != 0
            or record.candidates
            or record.candidate_inventory_truncated
            or record.candidate_count != len(record.candidates)
            or record.model_attempted
            or record.model_succeeded
            or record.model_execution_count != 0
        ):
            continue
        candidate_kinds = {kind for _, kind in contracts}
        matching_hypotheses = [
            candidate
            for candidate in record.candidates
            if candidate.candidate_kind in candidate_kinds
            and _candidate_matches_claim(
                candidate,
                node=node,
                case=case,
                claim=claim,
                judge=judge,
                require_packed=False,
            )
        ]
        if matching_hypotheses:
            continue
        gaps.append(SpecialistOpportunityMatch(
            node=node,
            component=SPECIALIST_PROMPT_COMPONENTS[node],
            candidate_id=None,
            record_digest=record.record_digest,
            claim_id=claim_id,
        ))
    return tuple(gaps)


def validated_specialist_target(
    case: BenchmarkCase,
    trace: Sequence[WorkflowNodeEvent],
    attribution: FailureAttribution,
    judge: IndependentBenchmarkJudge,
) -> str | None:
    """Revalidate specialist-target proof before a report enters the lab corpus."""
    if attribution.failure_class != FailureClass.SPECIALIST_MISSED_FINDING:
        return None
    claim_refs = {_claim_id(claim) for claim in case.annotation.claims}
    declared_claims = [item for item in attribution.evidence_refs if item in claim_refs]
    if len(declared_claims) != 1:
        return None
    claim_id = declared_claims[0]
    synthetic_result = CaseEvaluationResult(
        case_id=case.case_id,
        case_family=case.case_family,
        split=case.split.value,
        category=case.category.value,
        difficulty=case.difficulty.value,
        evaluation_stage=case.evaluation_stage,
        expected_verdict=case.annotation.expected_verdict,
        evaluation_scope=case.annotation.evaluation_scope,
        fn=1,
        unmatched_claim_ids=[claim_id],
    )
    evidence = specialist_opportunity_evidence(case, synthetic_result, trace, judge)
    targetable = [item for item in evidence.targetable if item.claim_id == claim_id]
    if len(targetable) != 1:
        return None
    match = targetable[0]
    if (
        match.node != attribution.primary_node
        or match.component != attribution.target_prompt_component
        or match.record_digest != attribution.specialist_opportunity_digest
        or match.candidate_id not in attribution.evidence_refs
    ):
        return None
    return match.component


def specialist_unsupported_contributors(
    case: BenchmarkCase,
    published_evaluation: CaseEvaluationResult | None,
    trace: Sequence[WorkflowNodeEvent],
) -> list[dict[str, object]]:
    """Link a model-produced specialist candidate to a verified false positive."""
    if published_evaluation is None or not published_evaluation.false_positive_findings:
        return []
    verified_ids = {
        finding_id for event in trace if event.node == "verifier" for finding_id in event.verified_ids
    }
    contributors: list[dict[str, object]] = []
    for event in trace:
        # Unsupported-output attribution must be bound to the exact benchmark
        # fixture snapshot just like missed-finding attribution. A valid record
        # digest alone only proves integrity, not that it belongs to this case.
        record = _record(event, case)
        if (
            event.node not in SPECIALIST_PROMPT_COMPONENTS
            or record is None
            or not _proves_live_model_execution(event, record)
            or event.status != "COMPLETED"
            or event.failure_codes
        ):
            continue
        model_ids = set(record.model_output_candidate_ids)
        for ref in event.finding_refs:
            finding_id = str(ref.get("finding_id") or "")
            if finding_id not in verified_ids or finding_id not in model_ids:
                continue
            for unsupported in published_evaluation.false_positive_findings:
                if (
                    str(ref.get("rule_id") or "") == unsupported.rule_id
                    and any(
                        normalize_repo_path(str(item.get("file_path") or "")) == normalize_repo_path(unsupported.file_path)
                        and item.get("start_line") == unsupported.start_line
                        for item in ref.get("evidences", [])[:8]
                        if isinstance(item, dict)
                    )
                ):
                    contributors.append({
                        "node": event.node,
                        "finding_id": finding_id,
                        "opportunity_digest": record.record_digest,
                    })
                    break
    unique = {(item["node"], item["finding_id"]): item for item in contributors}
    return list(unique.values())[:8]


def specialist_preserve_proof(
    case: BenchmarkCase,
    detail,
    *,
    node: str,
    judge: IndependentBenchmarkJudge,
) -> tuple[str, tuple[str, ...]] | None:
    """Return proof only when the specialist's model behavior contributed to success."""
    if node not in SPECIALIST_PROMPT_COMPONENTS:
        return None
    published_claims = set(detail.published_matched_claim_ids)
    verifier_ids = {
        finding_id for event in detail.workflow_trace if event.node == "verifier" for finding_id in event.verified_ids
    }
    for event in detail.workflow_trace:
        if event.node != node or event.status != "COMPLETED" or event.failure_codes:
            continue
        record = _record(event, case)
        if record is None or not _proves_live_model_execution(event, record):
            continue
        model_ids = set(record.model_output_candidate_ids)
        if case.annotation.expected_verdict.value != "ISSUE":
            if not model_ids:
                return record.record_digest, (record.record_digest,)
            continue
        for candidate in record.candidates:
            rule_contract = SPECIALIST_CANDIDATE_RULE_CONTRACTS.get((node, candidate.candidate_kind))
            if rule_contract is None or not candidate.packed or candidate.evidence_truncated:
                continue
            rule_id, category = rule_contract
            if category != case.category.value:
                continue
            for ref in event.finding_refs:
                finding_id = str(ref.get("finding_id") or "")
                if finding_id not in model_ids or finding_id not in verifier_ids:
                    continue
                if str(ref.get("rule_id") or "") != rule_id:
                    continue
                for claim in case.annotation.claims:
                    claim_id = _claim_id(claim)
                    if claim_id not in published_claims or claim.rule_id != rule_id:
                        continue
                    for evidence in ref.get("evidences", [])[:8]:
                        if not isinstance(evidence, dict):
                            continue
                        finding = EvaluatedFinding(
                            rule_id=rule_id,
                            file_path=str(evidence.get("file_path") or ""),
                            start_line=evidence.get("start_line"),
                            end_line=evidence.get("end_line"),
                            stage=EvaluationStage.PUBLISHED_FINDING,
                        )
                        if _matches_claim_location(finding, claim, judge):
                            return record.record_digest, (record.record_digest, finding_id)
    return None


__all__ = [
    "SPECIALIST_PROMPT_COMPONENTS",
    "SPECIALIST_CANDIDATE_RULE_CONTRACTS",
    "SpecialistAttributionEvidence",
    "SpecialistOpportunityMatch",
    "snapshot_id_for_case",
    "specialist_opportunity_evidence",
    "specialist_input_gap_evidence",
    "specialist_preserve_proof",
    "specialist_unsupported_contributors",
    "validated_specialist_target",
]
