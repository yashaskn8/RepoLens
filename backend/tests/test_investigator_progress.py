"""Adversarial tests for semantic investigator progress and stagnation."""

from __future__ import annotations

import hashlib
import json

from app.agent_runtime.context import compact_observation, normalize_tool_result
from app.agent_runtime.schemas import (
    EvidenceLedgerEntry,
    InvestigatorFindingContext,
    InvestigatorObservation,
    InvestigatorProgressClass,
    InvestigatorRunState,
    InvestigatorTargetState,
    VerifierGap,
)
from app.agents.investigator import (
    route_after_investigator_complete,
    run_investigator_complete_node,
    run_investigator_compact_node,
)
from app.evaluation.system.schemas import (
    FullAnalysisTrialDetail,
    InvestigatorEfficiencyMetrics,
    WorkflowNodeEvent,
    derive_investigator_efficiency,
)
from app.agent_tools.schemas import (
    EvidenceRecord,
    EvidenceType,
    ToolError,
    ToolInvocationResult,
    ToolProvenance,
    ToolResultStatus,
)


SNAPSHOT = "a" * 40


def _target(finding_id: str = "finding-progress") -> InvestigatorTargetState:
    return InvestigatorTargetState(
        finding=InvestigatorFindingContext(
            finding_id=finding_id,
            title="Possible unsafe token use",
            category="security",
            description="A client-controlled token may reach a sensitive sink.",
            primary_file="auth.py",
            primary_start_line=1,
            primary_end_line=4,
            repository_snapshot=SNAPSHOT,
        ),
        verifier_gap=VerifierGap(
            finding_id=finding_id,
            reason="The verifier cannot determine whether every caller validates the token.",
            unresolved_claims=["all callers validate before the sink"],
        ),
    )


def _result(
    tool: str = "fixture_tool",
    *,
    status: ToolResultStatus = ToolResultStatus.SUCCESS,
    evidence: list[EvidenceRecord] | None = None,
    result: dict | None = None,
    warnings: list[ToolError] | None = None,
    snapshot: str | None = SNAPSHOT,
) -> ToolInvocationResult:
    provenance = None if snapshot is None else ToolProvenance(
        production_components=["fixture"],
        component_versions={"fixture": "1"},
        repository_snapshot=snapshot,
        snapshot_artifact_digest="c" * 64,
        analysis_stage="fixture",
    )
    return ToolInvocationResult(
        tool=tool,
        tool_version="2.0.0",
        status=status,
        result=result or {},
        evidence=evidence or [],
        provenance=provenance,
        warnings=warnings or [],
    )


def _record(
    *,
    evidence_type: EvidenceType = EvidenceType.AST_FACT,
    evidence_id: str = "evidence:one",
    file_path: str | None = "auth.py",
    symbol: str | None = "symbol:" + "1" * 64,
    start_line: int | None = 1,
    end_line: int | None = 3,
    relationship: str | None = None,
    source_id: str | None = None,
    target_id: str | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        source_component="fixture",
        file_path=file_path,
        symbol=symbol,
        start_line=start_line,
        end_line=end_line,
        relationship=relationship,
        source_id=source_id,
        target_id=target_id,
    )


def _compact(
    target: InvestigatorTargetState,
    result: ToolInvocationResult,
    *,
    step: int = 1,
    arguments: dict | None = None,
    fingerprint: str | None = None,
) -> InvestigatorTargetState:
    target.budget.step_number = step
    call_fingerprint = fingerprint or hashlib.sha256(f"call-{step}".encode()).hexdigest()
    target.pending_call_fingerprint = call_fingerprint
    observation = normalize_tool_result(result, step_number=step, arguments=arguments)
    target.pending_observation = observation
    return compact_observation(target, observation, call_fingerprint=call_fingerprint)


def _last(target: InvestigatorTargetState):
    return target.progress_history[-1]


def test_envelope_digest_churn_and_cross_tool_duplicate_facts_are_not_progress():
    target = _target()
    symbol = "symbol:" + "2" * 64
    target = _compact(target, _result("search_symbol", evidence=[_record(symbol=symbol)]))
    assert _last(target).progress_class == InvestigatorProgressClass.PROGRESS

    target = _compact(target, _result(
        "inspect_symbol",
        evidence=[_record(evidence_id="evidence:two", symbol=symbol)],
        result={"irrelevant_metadata": "changed"},
    ), step=2)
    assert _last(target).progress_class == InvestigatorProgressClass.NO_PROGRESS
    assert _last(target).result_digest != target.progress_history[0].result_digest
    assert target.call_fingerprints[-2:] == [hashlib.sha256(b"call-1").hexdigest(), hashlib.sha256(b"call-2").hexdigest()]


def test_same_file_new_structural_range_alone_does_not_count_as_progress():
    target = _target()
    target = _compact(target, _result(evidence=[_record(
        evidence_type=EvidenceType.SOURCE_LOCATION,
        symbol=None,
        start_line=10,
        end_line=12,
    )]))
    assert _last(target).progress_class == InvestigatorProgressClass.NO_PROGRESS
    assert _last(target).new_file_count == 0


def test_novel_symbol_file_and_relationship_facts_count_as_progress():
    target = _target()
    target = _compact(target, _result(evidence=[_record(
        evidence_type=EvidenceType.AST_FACT,
        file_path="handlers.py",
        symbol="symbol:" + "3" * 64,
    )]))
    assert _last(target).progress_class == InvestigatorProgressClass.PROGRESS
    assert _last(target).new_file_count == 1
    assert _last(target).new_symbol_count == 1

    target = _compact(target, _result(evidence=[_record(
        evidence_type=EvidenceType.CALL_RELATIONSHIP,
        evidence_id="edge:one",
        file_path="handlers.py",
        symbol=None,
        relationship="CALLS",
        source_id="symbol:" + "3" * 64,
        target_id="symbol:" + "4" * 64,
    )]), step=2)
    assert _last(target).new_relationship_count == 1
    assert _last(target).progress_class == InvestigatorProgressClass.PROGRESS


def test_complete_negative_result_counts_once_and_distinct_query_counts_again():
    target = _target()
    args = {"query": "sanitize_input", "match_mode": "EXACT", "snapshot_id": SNAPSHOT}
    target = _compact(target, _result(
        "search_symbol", status=ToolResultStatus.NOT_FOUND,
        result={"query": "sanitize_input", "matches": [], "truncated": False},
    ), arguments=args)
    assert _last(target).progress_class == InvestigatorProgressClass.NEGATIVE_PROGRESS
    target = _compact(target, _result(
        "other_symbol_lookup", status=ToolResultStatus.NOT_FOUND,
        result={"query": "sanitize_input", "matches": [], "request_id": "churn"},
    ), step=2, arguments=args)
    assert _last(target).progress_class == InvestigatorProgressClass.NO_PROGRESS
    target = _compact(target, _result(
        "search_symbol", status=ToolResultStatus.NOT_FOUND,
        result={"query": "verify_token", "matches": []},
    ), step=3, arguments={"query": "verify_token", "match_mode": "EXACT"})
    assert _last(target).progress_class == InvestigatorProgressClass.NEGATIVE_PROGRESS
    assert _last(target).new_negative_count == 1


def test_complete_empty_graph_result_is_a_negative_fact_and_repeat_is_not_progress():
    target = _target()
    arguments = {"symbol_id": "symbol:" + "7" * 64}
    target = _compact(target, _result(
        "find_callers",
        status=ToolResultStatus.SUCCESS,
        result={"relationships": [], "graph_complete": True, "truncated": False},
    ), arguments=arguments)
    assert _last(target).progress_class == InvestigatorProgressClass.NEGATIVE_PROGRESS
    assert any(
        entry.status == ToolResultStatus.NOT_FOUND.value
        and entry.coverage_complete is True
        for entry in target.evidence_ledger
    )
    target = _compact(target, _result(
        "find_callers",
        status=ToolResultStatus.SUCCESS,
        result={"relationships": [], "graph_complete": True, "request_id": "different"},
    ), step=2, arguments=arguments)
    assert _last(target).progress_class == InvestigatorProgressClass.NO_PROGRESS


def test_incomplete_coverage_is_retained_but_not_treated_as_negative_progress():
    target = _target()
    target = _compact(target, _result(
        "search_symbol",
        status=ToolResultStatus.INSUFFICIENT_EVIDENCE,
        result={"query": "sanitize_input", "matches": [], "manifest_scope_complete": False},
        warnings=[ToolError(code="MANIFEST_SCOPE_INCOMPLETE", message="Coverage is incomplete.")],
    ), arguments={"query": "sanitize_input"})
    assert _last(target).progress_class == InvestigatorProgressClass.INDETERMINATE
    assert any(entry.evidence_type == "COVERAGE_LIMITATION" for entry in target.evidence_ledger)
    assert not any(entry.coverage_complete is True for entry in target.evidence_ledger)


def test_changed_content_at_same_source_slice_is_contradiction_progress():
    target = _target()
    first = _record(
        evidence_type=EvidenceType.SOURCE_SLICE,
        evidence_id="source:first",
        symbol=None,
        start_line=10,
        end_line=11,
        source_id="b" * 64,
    )
    target = _compact(target, _result("read_source_slice", evidence=[first], result={"content": "token = x"}))
    second = _record(
        evidence_type=EvidenceType.SOURCE_SLICE,
        evidence_id="source:second",
        symbol=None,
        start_line=10,
        end_line=11,
        source_id="d" * 64,
    )
    target = _compact(target, _result("read_source_slice", evidence=[second], result={"content": "token = y"}), step=2)
    assert _last(target).progress_class == InvestigatorProgressClass.CONTRADICTION_PROGRESS
    assert _last(target).contradiction_count == 1
    assert "token = y" not in json.dumps(_last(target).model_dump(mode="json"))


def test_two_unchanged_knowledge_states_trigger_semantic_stagnation_cycle():
    target = _target()
    target = _compact(target, _result("inspect_symbol"))
    assert _last(target).progress_class == InvestigatorProgressClass.NO_PROGRESS
    assert _last(target).consecutive_no_progress == 1
    assert not _last(target).knowledge_state_cycle
    target = _compact(target, _result("find_callers"), step=2)
    assert _last(target).progress_class == InvestigatorProgressClass.NO_PROGRESS
    assert _last(target).consecutive_no_progress == 2
    assert _last(target).knowledge_state_cycle


def test_semantic_stagnation_is_a_terminal_fail_closed_graph_outcome():
    import asyncio

    first = _compact(_target(), _result("inspect_symbol"))
    first.budget.step_number = 2
    first.pending_call_fingerprint = hashlib.sha256(b"second-call").hexdigest()
    first.pending_observation = normalize_tool_result(
        _result("find_callers"),
        step_number=2,
        arguments={"symbol_id": "symbol:" + "1" * 64},
    )
    state = {"investigator": InvestigatorRunState(
        targets=[first.finding.finding_id],
        active=first,
    ).model_dump(mode="json")}
    compacted = asyncio.run(run_investigator_compact_node(state))
    state.update(compacted)
    assert state["investigator"]["active"]["stop_reason"] == "SEMANTIC_STAGNATION"
    completed = asyncio.run(run_investigator_complete_node(state))
    state.update(completed)
    assert route_after_investigator_complete(state) == "uncertain"
    result = state["investigator"]["results"]["finding-progress"]
    assert result["stop_reason"] == "SEMANTIC_STAGNATION"


def test_progress_and_tool_errors_break_consecutive_no_progress_window():
    target = _target()
    target = _compact(target, _result("inspect_symbol"))
    assert target.consecutive_no_progress == 1
    target = _compact(target, _result("search_symbol", evidence=[_record(symbol="symbol:" + "5" * 64)]), step=2)
    assert target.consecutive_no_progress == 0
    target = _compact(target, _result("find_callers"), step=3)
    assert target.consecutive_no_progress == 1
    failed = _result(
        "inspect_symbol",
        status=ToolResultStatus.INTERNAL_ERROR,
        warnings=[ToolError(code="TOOL_TIMEOUT", message="Timed out.")],
        snapshot=None,
    )
    target = _compact(target, failed, step=4)
    assert _last(target).progress_class == InvestigatorProgressClass.INDETERMINATE
    assert target.consecutive_no_progress == 0


def test_truncation_without_concrete_evidence_is_indeterminate():
    target = _target()
    result = _result(
        "find_callers",
        status=ToolResultStatus.RESOURCE_LIMIT,
        result={"relationships": [], "truncated": True},
        warnings=[ToolError(code="GRAPH_PARTIAL", message="Result truncated.")],
    )
    target = _compact(target, result)
    assert _last(target).progress_class == InvestigatorProgressClass.INDETERMINATE
    assert _last(target).new_evidence_count == 0
    assert _last(target).consecutive_no_progress == 0


def test_cross_snapshot_evidence_is_discarded_and_does_not_change_knowledge_state():
    target = _target()
    original = len(target.evidence_ledger)
    target = _compact(target, _result(
        "search_symbol",
        evidence=[_record(symbol="symbol:" + "6" * 64)],
        snapshot="b" * 40,
    ))
    assert _last(target).progress_class == InvestigatorProgressClass.INDETERMINATE
    assert len(target.evidence_ledger) == original
    assert not target.evidence_artifacts[-1].evidence_refs
    assert target.evidence_artifacts[-1].useful_result == {"status": "SNAPSHOT_MISMATCH", "evidence_ignored": True}


def test_progress_history_survives_checkpoint_round_trip_and_is_target_local():
    first = _compact(_target("finding-one"), _result("inspect_symbol"))
    run = InvestigatorRunState(
        targets=["finding-one"],
        active=first,
    )
    restored = InvestigatorRunState.model_validate(json.loads(run.model_dump_json()))
    assert restored.active is not None
    restored.active = _compact(restored.active, _result("find_callers"), step=2)
    assert _last(restored.active).knowledge_state_cycle

    other = _compact(_target("finding-two"), _result("find_callers"))
    assert len(other.progress_history) == 1
    assert other.progress_history[0].consecutive_no_progress == 1
    assert not other.progress_history[0].knowledge_state_cycle


def test_efficiency_metrics_are_trace_derived_and_separate_from_quality():
    finding = "finding-progress"

    def event(sequence: int, node: str, *, step: int | None = None, progress: str | None = None,
              executions: int = 0, stop: str | None = None, failures: list[str] | None = None,
              cycle: bool = False):
        return WorkflowNodeEvent(
            sequence=sequence,
            node=node,
            superstep=sequence,
            status="COMPLETED_WITH_ERRORS" if failures else "COMPLETED",
            duration_ms=1,
            input_digest="a" * 64,
            output_digest="b" * 64,
            tool_execution_count=executions,
            failure_codes=failures or [],
            investigator_finding_id=finding,
            investigator_step_number=step,
            investigator_progress_class=progress,
            investigator_stop_reason=stop,
            investigator_knowledge_state_cycle=cycle,
        )

    detail = FullAnalysisTrialDetail(
        case_id="case-progress",
        trial_number=1,
        workflow_status="COMPLETED",
        evaluation_stage="ANALYSIS_CANDIDATE",
        tp=1,
        fp=0,
        fn=0,
        duration_ms=1,
        workflow_trace=[
            event(1, "investigator_decide", step=1),
            event(2, "investigator_tool", step=1, executions=1),
            event(3, "investigator_compact", step=1, progress="NO_PROGRESS"),
            event(4, "investigator_decide", step=2),
            event(5, "investigator_tool", step=2, executions=1),
            event(6, "investigator_compact", step=2, progress="PROGRESS"),
            event(7, "investigator_decide", step=3),
            event(8, "investigator_complete", stop="EVIDENCE_GATHERED"),
        ],
    )
    metrics = derive_investigator_efficiency([detail])
    assert metrics.tool_calls.value == 2
    assert metrics.progress_tool_calls.value == 1
    assert metrics.no_progress_tool_calls.value == 1
    assert metrics.tool_calls_after_last_progress.value == 0
    assert metrics.model_decisions_after_last_progress.value == 1
    assert metrics.steps_to_first_progress.value == 2
    assert metrics.progress_call_rate.value == 0.5
    assert isinstance(metrics, InvestigatorEfficiencyMetrics)

    repeated_trial = FullAnalysisTrialDetail(
        case_id="case-progress",
        trial_number=2,
        workflow_status="COMPLETED",
        evaluation_stage="ANALYSIS_CANDIDATE",
        tp=1,
        fp=0,
        fn=0,
        duration_ms=1,
        workflow_trace=[
            event(1, "investigator_tool", step=2, executions=1, failures=["STAGNATION"]),
            event(
                2,
                "investigator_compact",
                step=2,
                progress="NO_PROGRESS",
                stop="SEMANTIC_STAGNATION",
                cycle=True,
            ),
        ],
    )
    repeated_metrics = derive_investigator_efficiency([detail, repeated_trial])
    assert repeated_metrics.exact_stuck_stops.value == 1
    assert repeated_metrics.semantic_stagnation_stops.value == 1
    assert repeated_metrics.knowledge_state_cycle_stops.value == 1

    second_case_trial = repeated_trial.model_copy(update={"case_id": "case-progress-2", "trial_number": 1})
    multi_run_metrics = derive_investigator_efficiency([repeated_trial, second_case_trial])
    assert multi_run_metrics.exact_stuck_stops.value == 2
    assert multi_run_metrics.semantic_stagnation_stops.value == 2
    assert multi_run_metrics.knowledge_state_cycle_stops.value == 2
