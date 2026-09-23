"""Proof-focused full-analysis specialist attribution regressions."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.agents.specialist_provenance import SpecialistOpportunityRecord, build_specialist_opportunity
import app.agents.specialist_provenance as provenance_module
from app.agents.helpers import validated_candidate_findings_payload
from app.context.slices import SpecialistContextPack
from app.evaluation.ground_truth.matcher import EvaluatedFinding, IndependentBenchmarkJudge
from app.evaluation.ground_truth.schemas import EvaluationStage
from app.evaluation.system.full_analysis import attribute_full_analysis_failure
from app.evaluation.system import full_analysis as full_analysis_module
from app.evaluation.system.schemas import FailureAttribution, FailureClass, WorkflowNodeEvent
from app.evaluation.system.specialist_attribution import (
    SPECIALIST_CANDIDATE_RULE_CONTRACTS,
    SpecialistOpportunityMatch,
    specialist_input_gap_evidence,
    specialist_opportunity_evidence,
    specialist_preserve_proof,
    specialist_unsupported_contributors,
    snapshot_id_for_case,
    validated_specialist_target,
)
from app.specialist_candidates import AnalysisCandidate


_CASE_PATH = (
    Path(__file__).resolve().parents[1]
    / "evaluation_data"
    / "ground_truth"
    / "v1"
    / "cases"
    / "correctness"
    / "BUG-EXCEPT-01A.json"
)


def _case(path: Path = _CASE_PATH):
    from app.evaluation.ground_truth.schemas import BenchmarkCase

    return BenchmarkCase.model_validate_json(path.read_text(encoding="utf-8"))


def _record(
    case,
    *,
    candidate_id: str = "candidate:opportunity-a",
    packed: bool = True,
    model_succeeded: bool = True,
    model_output_id: str | None = None,
    snapshot_id: str | None = None,
    evidence_truncated: bool = False,
    no_candidates: bool = False,
    node: str = "bug",
    candidate_kind: str = "BROAD_EXCEPTION_SWALLOW",
    candidate_path: str = "app/services/payment.py",
    candidate_line: int = 4,
    candidate_symbol: str = "process_transaction",
    model_attempted: bool | None = None,
    completion_reason: str | None = None,
):
    candidate = AnalysisCandidate(
        candidate_id=candidate_id,
        candidate_kind=candidate_kind,
        deterministic_reason="Raw source must never enter persisted provenance.",
        evidence_refs=["chunk:anchor-a"],
        related_symbol=candidate_symbol,
        metadata={"file_path": candidate_path, "source_line": candidate_line},
    )
    slices = ()
    evidence_index = {}
    truncated_ids = ()
    if packed and not no_candidates:
        slices = (SimpleNamespace(
            candidate_id=candidate_id,
            primary_evidence_refs=["chunk:anchor-a"],
            supporting_evidence_refs=[],
            counter_evidence_refs=[],
            graph_evidence_refs=[],
            contract_evidence_refs=[],
            scanner_evidence_refs=[],
            flow_evidence_refs=[],
            caller_evidence_refs=[],
            callee_evidence_refs=[],
            guard_evidence_refs=[],
            test_evidence_refs=[],
            config_evidence_refs=[],
        ),)
        evidence_index = {
            "chunk:anchor-a": {
                "file_path": candidate_path,
                "start_line": candidate_line,
                "end_line": 5,
                "symbol": candidate_symbol,
            }
        }
        truncated_ids = (candidate_id,) if evidence_truncated else ()
    context = SpecialistContextPack(
        text="PRIVATE_SOURCE_SNIPPET_NOT_PERSISTED",
        digest="d" * 64,
        evidence_index=evidence_index,
        slices=slices,
        estimated_tokens=20,
        packed_bytes=80,
        truncated_candidate_ids=truncated_ids,
    )
    output = [SimpleNamespace(id=model_output_id)] if model_output_id else []
    candidates = [] if no_candidates else [candidate]
    return build_specialist_opportunity(
        node=node,
        state={
            "scan_id": "scan-for-test",
            "commit_hash": snapshot_id or snapshot_id_for_case(case),
        },
        candidates=candidates,
        candidate_source="NONE" if no_candidates else "MAPPER",
        context=None if no_candidates else context,
        completion_reason=completion_reason or (
            "NO_DETERMINISTIC_CANDIDATES"
            if no_candidates
            else "MODEL_COMPLETED" if model_succeeded else "MODEL_FAILURE"
        ),
        model_attempted=(not no_candidates if model_attempted is None else model_attempted),
        model_succeeded=model_succeeded and not no_candidates,
        model_execution_count=1 if model_succeeded and not no_candidates else 0,
        model_output_findings=output,
    )


def _event(record, *, status="COMPLETED", failure_codes=(), finding_refs=(), verified_ids=(), model_identities=None, node="bug"):
    model_succeeded = record.get("model_succeeded", False)
    execution_count = record.get("model_execution_count", 0)
    return WorkflowNodeEvent(
        sequence=1,
        node=node,
        superstep=1,
        status=status,
        duration_ms=3.0,
        input_digest="a" * 64,
        output_digest="b" * 64,
        model_execution_count=execution_count,
        model_identities=(model_identities if model_identities is not None else (["gemini:model-a"] if model_succeeded else [])),
        finding_refs=list(finding_refs),
        verified_ids=list(verified_ids),
        failure_codes=list(failure_codes),
        specialist_opportunity=record,
    )


def _missing(case):
    judge = IndependentBenchmarkJudge()
    result = judge.evaluate_case(
        case,
        [],
        set(case.fixture.files),
        {path: len(content.splitlines()) for path, content in case.fixture.files.items()},
    )
    return judge, result


def test_specialist_provenance_is_content_free_bounded_and_digest_checked():
    case = _case()
    record = _record(case)
    encoded = json.dumps(record, sort_keys=True)
    assert "PRIVATE_SOURCE_SNIPPET_NOT_PERSISTED" not in encoded
    assert "Raw source must never enter" not in encoded
    assert record["node"] == "bug"
    assert record["snapshot_id"] == snapshot_id_for_case(case)
    assert record["candidates"][0]["packed_evidence_refs"] == ["chunk:anchor-a"]

    forged = dict(record)
    forged["snapshot_id"] = "0" * 40
    with pytest.raises(ValueError, match="digest does not match"):
        SpecialistOpportunityRecord.model_validate(forged)


def test_unique_packed_model_opportunity_is_attributed_and_revalidated_for_lab():
    case = _case()
    judge, missing = _missing(case)
    record = _record(case)
    trace = [_event(record)]
    attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"}, trace, judge,
    )

    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_MISSED_FINDING
    assert attribution.primary_node == "bug"
    assert attribution.target_prompt_component == "bug-agent"
    assert attribution.specialist_opportunity_digest == record["record_digest"]
    assert validated_specialist_target(case, trace, attribution, judge) == "bug-agent"

    forged = attribution.model_copy(update={"primary_node": "security"})
    assert validated_specialist_target(case, trace, forged, judge) is None


def test_unpacked_or_truncated_evidence_is_non_targetable_context_omission():
    case = _case()
    judge, missing = _missing(case)
    for record in (_record(case, packed=False), _record(case, evidence_truncated=True)):
        evidence = specialist_opportunity_evidence(case, missing, [_event(record)], judge)
        assert not evidence.targetable
        assert evidence.context_omissions
        attribution = attribute_full_analysis_failure(
            case, missing, {"status": "COMPLETED"}, [_event(record)], judge,
        )
        assert attribution is not None
        assert attribution.failure_class == FailureClass.SPECIALIST_CONTEXT_OMISSION
        assert attribution.primary_node == "bug"
        assert attribution.target_prompt_component is None


def _map_security_to_bug_contract(monkeypatch):
    monkeypatch.setitem(
        SPECIALIST_CANDIDATE_RULE_CONTRACTS,
        ("security", "BROAD_EXCEPTION_SWALLOW"),
        ("BROAD_EXCEPTION_SWALLOW", "CORRECTNESS"),
    )


def test_multiple_distinct_context_omissions_are_ambiguous_not_first_node(monkeypatch):
    case = _case()
    _map_security_to_bug_contract(monkeypatch)
    judge, missing = _missing(case)
    records = (
        _record(case, node="security", packed=False),
        _record(case, node="bug", candidate_id="candidate:bug", packed=False),
    )
    trace = [
        _event(records[0], node="security"),
        _event(records[1], node="bug"),
    ]

    attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"}, trace, judge,
    )

    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_ATTRIBUTION_AMBIGUOUS
    assert attribution.primary_node is None
    assert attribution.target_prompt_component is None
    assert set(attribution.evidence_refs) >= {
        "BROAD_EXCEPTION_SWALLOW@app/services/payment.py",
        "candidate:opportunity-a",
        "candidate:bug",
        records[0]["record_digest"],
        records[1]["record_digest"],
    }


def test_duplicate_identical_context_omission_is_deduplicated_not_ambiguous():
    case = _case()
    judge, missing = _missing(case)
    event = _event(_record(case, packed=False))

    evidence = specialist_opportunity_evidence(case, missing, [event, event], judge)
    attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"}, [event, event], judge,
    )

    assert len(evidence.context_omissions) == 1
    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_CONTEXT_OMISSION
    assert attribution.primary_node == "bug"
    assert attribution.target_prompt_component is None


def test_multiple_not_executed_specialists_are_ambiguous_not_first_node(monkeypatch):
    case = _case()
    _map_security_to_bug_contract(monkeypatch)
    judge, missing = _missing(case)
    security = _record(
        case, node="security", model_succeeded=False, model_attempted=False,
        completion_reason="ADMISSION_BLOCKED",
    )
    bug = _record(
        case, candidate_id="candidate:bug", node="bug", model_succeeded=False,
        model_attempted=False, completion_reason="ADMISSION_BLOCKED",
    )

    attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"},
        [_event(security, node="security"), _event(bug, node="bug")], judge,
    )

    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_ATTRIBUTION_AMBIGUOUS
    assert attribution.primary_node is None
    assert attribution.target_prompt_component is None


def test_single_non_executed_opportunity_keeps_specific_non_targetable_node():
    case = _case()
    judge, missing = _missing(case)
    record = _record(
        case, model_succeeded=False, model_attempted=False,
        completion_reason="ADMISSION_BLOCKED",
    )

    attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"}, [_event(record)], judge,
    )

    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_NOT_EXECUTED
    assert attribution.primary_node == "bug"
    assert attribution.target_prompt_component is None


def test_single_security_context_omission_keeps_security_as_non_targetable_node(monkeypatch):
    case = _case()
    _map_security_to_bug_contract(monkeypatch)
    judge, missing = _missing(case)
    event = _event(_record(case, node="security", packed=False), node="security")

    attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"}, [event], judge,
    )

    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_CONTEXT_OMISSION
    assert attribution.primary_node == "security"
    assert attribution.target_prompt_component is None


def test_targetable_plus_context_omission_is_ambiguous(monkeypatch):
    case = _case()
    _map_security_to_bug_contract(monkeypatch)
    judge, missing = _missing(case)
    targetable = _event(_record(case, node="bug", candidate_id="candidate:targetable"), node="bug")
    omitted = _event(
        _record(case, node="security", candidate_id="candidate:omitted", packed=False),
        node="security",
    )

    attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"}, [targetable, omitted], judge,
    )

    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_ATTRIBUTION_AMBIGUOUS
    assert attribution.primary_node is None
    assert attribution.target_prompt_component is None


def test_targetable_plus_input_gap_is_ambiguous(monkeypatch):
    case = _case()
    judge, missing = _missing(case)
    targetable = _event(_record(case, candidate_id="candidate:targetable"))
    gap = SpecialistOpportunityMatch(
        node="security", component="security-agent", candidate_id=None,
        record_digest="a" * 64, claim_id="BROAD_EXCEPTION_SWALLOW@app/services/payment.py",
    )
    monkeypatch.setattr(full_analysis_module, "specialist_input_gap_evidence", lambda *args: (gap,))

    attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"}, [targetable], judge,
    )

    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_ATTRIBUTION_AMBIGUOUS
    assert attribution.primary_node is None
    assert attribution.target_prompt_component is None


def test_snapshot_mismatch_model_failure_and_matching_emission_never_blame_specialist():
    case = _case()
    judge, missing = _missing(case)
    wrong_snapshot = _record(case, snapshot_id="f" * 40)
    failed = _record(case, model_succeeded=False)
    emitted = _record(case, model_output_id="finding:matched")
    matching_ref = {
        "finding_id": "finding:matched",
        "rule_id": "BROAD_EXCEPTION_SWALLOW",
        "evidences": [{
            "file_path": "app/services/payment.py",
            "start_line": 4,
            "end_line": 5,
        }],
    }
    for event in (
        _event(wrong_snapshot),
        _event(failed, status="COMPLETED_WITH_ERRORS", failure_codes=("NODE_ERROR",)),
        _event(emitted, finding_refs=(matching_ref,)),
    ):
        attribution = attribute_full_analysis_failure(
            case, missing, {"status": "COMPLETED"}, [event], judge,
        )
        assert attribution is not None
        assert attribution.failure_class != FailureClass.SPECIALIST_MISSED_FINDING


def test_scripted_harness_output_is_never_prompt_target_evidence():
    case = _case()
    judge, missing = _missing(case)
    scripted = _event(
        _record(case),
        model_identities=["scripted-evaluation:scripted-full-analysis-harness"],
    )
    attribution = attribute_full_analysis_failure(case, missing, {"status": "COMPLETED"}, [scripted], judge)
    assert attribution is not None
    assert attribution.failure_class != FailureClass.SPECIALIST_MISSED_FINDING
    assert attribution.target_prompt_component is None


def test_invalid_model_output_is_recorded_without_specialist_targeting():
    case = _case()
    judge, missing = _missing(case)
    invalid = _event(
        _record(case, model_succeeded=False),
        status="COMPLETED_WITH_ERRORS",
        failure_codes=("MODEL_INVALID_OUTPUT",),
    )
    attribution = attribute_full_analysis_failure(case, missing, {"status": "COMPLETED"}, [invalid], judge)
    assert attribution is not None
    assert attribution.failure_class == FailureClass.MODEL_INVALID_OUTPUT
    assert attribution.target_prompt_component is None


def test_missing_security_hypothesis_is_an_upstream_input_gap_not_a_prompt_miss():
    case = _case(
        Path(__file__).resolve().parents[1]
        / "evaluation_data"
        / "ground_truth"
        / "v1"
        / "cases"
        / "security"
        / "SEC-SQLI-01A.json"
    )
    judge, missing = _missing(case)
    event = _event(_record(case, node="security", no_candidates=True), node="security")
    attribution = attribute_full_analysis_failure(case, missing, {"status": "COMPLETED"}, [event], judge)

    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_INPUT_GAP
    assert attribution.primary_node == "security"
    assert attribution.target_prompt_component is None

    from app.evaluation.improvement.corpus import FAILURE_TARGETS

    assert FAILURE_TARGETS.get((FailureClass.SPECIALIST_INPUT_GAP, "security")) is None

    failed_node = _event(
        _record(case, node="security", no_candidates=True),
        node="security",
        status="COMPLETED_WITH_ERRORS",
        failure_codes=("NODE_ERROR",),
    )
    failed_attribution = attribute_full_analysis_failure(
        case, missing, {"status": "COMPLETED"}, [failed_node], judge,
    )
    assert failed_attribution is not None
    assert failed_attribution.failure_class != FailureClass.SPECIALIST_INPUT_GAP
    assert failed_attribution.target_prompt_component is None


def test_input_gap_requires_a_complete_consistent_zero_candidate_inventory():
    case = _case(
        Path(__file__).resolve().parents[1]
        / "evaluation_data"
        / "ground_truth"
        / "v1"
        / "cases"
        / "security"
        / "SEC-SQLI-01A.json"
    )
    judge, missing = _missing(case)
    complete = _record(case, node="security", no_candidates=True)
    assert len(specialist_input_gap_evidence(case, missing, [_event(complete, node="security")], judge)) == 1

    truncated_payload = dict(complete)
    truncated_payload.pop("record_digest")
    truncated_payload["candidate_count"] = 1
    truncated_payload["candidate_inventory_truncated"] = True
    truncated_payload["candidate_inventory_digest"] = provenance_module._digest({
        "count": 1,
        "candidates": [],
        "truncated": True,
    })
    truncated_payload["record_digest"] = provenance_module._digest(truncated_payload)
    truncated = SpecialistOpportunityRecord.model_validate(truncated_payload).model_dump(mode="json")

    inconsistent_payload = dict(complete)
    inconsistent_payload.pop("record_digest")
    inconsistent_payload["candidate_source"] = "MAPPER"
    inconsistent_payload["record_digest"] = provenance_module._digest(inconsistent_payload)
    inconsistent = SpecialistOpportunityRecord.model_validate(inconsistent_payload).model_dump(mode="json")

    for record in (truncated, inconsistent):
        assert specialist_input_gap_evidence(case, missing, [_event(record, node="security")], judge) == ()

    wrong_snapshot = _record(
        case, node="security", no_candidates=True, snapshot_id="f" * 40,
    )
    assert specialist_input_gap_evidence(
        case, missing, [_event(wrong_snapshot, node="security")], judge,
    ) == ()


def test_non_targetable_attribution_classes_are_absent_from_improvement_targets():
    from app.evaluation.improvement.corpus import FAILURE_TARGETS

    non_targetable = (
        FailureClass.SPECIALIST_CONTEXT_OMISSION,
        FailureClass.SPECIALIST_NOT_EXECUTED,
        FailureClass.SPECIALIST_INPUT_GAP,
        FailureClass.SPECIALIST_ATTRIBUTION_AMBIGUOUS,
        FailureClass.MODEL_INVALID_OUTPUT,
    )
    assert not any(failure in non_targetable for failure, _ in FAILURE_TARGETS)


def test_multiple_candidate_opportunities_are_explicitly_ambiguous():
    case = _case()
    judge, missing = _missing(case)
    trace = [_event(_record(case, candidate_id=f"candidate:{index}")) for index in (1, 2)]
    attribution = attribute_full_analysis_failure(case, missing, {"status": "COMPLETED"}, trace, judge)
    assert attribution is not None
    assert attribution.failure_class == FailureClass.SPECIALIST_ATTRIBUTION_AMBIGUOUS
    assert attribution.target_prompt_component is None


def test_specialist_preserve_examples_require_model_output_to_contribute_to_success():
    case = _case()
    model_id = "finding:correct"
    record = _record(case, model_output_id=model_id)
    finding_ref = {
        "finding_id": model_id,
        "rule_id": "BROAD_EXCEPTION_SWALLOW",
        "evidences": [{
            "file_path": "app/services/payment.py",
            "start_line": 4,
            "end_line": 5,
        }],
    }
    event = _event(record, finding_refs=(finding_ref,))
    detail = SimpleNamespace(
        workflow_trace=[event, WorkflowNodeEvent(
            sequence=2, node="verifier", superstep=2, status="COMPLETED", duration_ms=1.0,
            input_digest="c" * 64, output_digest="e" * 64, verified_ids=[model_id],
        )],
        published_matched_claim_ids=["BROAD_EXCEPTION_SWALLOW@app/services/payment.py"],
    )
    judge = IndependentBenchmarkJudge()
    assert specialist_preserve_proof(case, detail, node="bug", judge=judge)

    detail.published_matched_claim_ids = []
    assert specialist_preserve_proof(case, detail, node="bug", judge=judge) is None


def test_unsupported_model_specialist_is_only_a_non_targetable_contributor():
    case = _case()
    record = _record(case, model_output_id="finding:unsupported")
    finding_ref = {
        "finding_id": "finding:unsupported",
        "rule_id": "UNSUPPORTED_RULE",
        "evidences": [{"file_path": "app/services/payment.py", "start_line": 4, "end_line": 5}],
    }
    judge = IndependentBenchmarkJudge()
    false_positive = judge.evaluate_case(
        case,
        [EvaluatedFinding(
            rule_id="UNSUPPORTED_RULE",
            file_path="app/services/payment.py",
            start_line=4,
            end_line=5,
            stage=EvaluationStage.PUBLISHED_FINDING,
        )],
        set(case.fixture.files),
        {path: len(content.splitlines()) for path, content in case.fixture.files.items()},
    )
    trace = [_event(record, finding_refs=(finding_ref,)), WorkflowNodeEvent(
        sequence=2, node="verifier", superstep=2, status="COMPLETED", duration_ms=1.0,
        input_digest="c" * 64, output_digest="e" * 64, verified_ids=["finding:unsupported"],
    )]
    contributors = specialist_unsupported_contributors(case, false_positive, trace)
    assert contributors and contributors[0]["node"] == "bug"

    # A correctly digested specialist record from another repository snapshot
    # cannot contribute causal blame for this fixture.
    wrong_snapshot = _event(_record(case, model_output_id="finding:unsupported", snapshot_id="f" * 40), finding_refs=(finding_ref,))
    assert specialist_unsupported_contributors(case, false_positive, [wrong_snapshot, trace[1]]) == []

    attribution = attribute_full_analysis_failure(
        case, false_positive, {"status": "COMPLETED"}, trace, judge,
    )
    assert attribution is not None
    assert attribution.failure_class == FailureClass.VERIFIER_FALSE_CONFIRMATION
    assert attribution.primary_node == "verifier"
    assert attribution.contributing_causes
    assert attribution.contributing_causes[0].targetable is False


def test_architecture_targeting_requires_an_explicit_ground_truth_rule_contract():
    assert SPECIALIST_CANDIDATE_RULE_CONTRACTS.get(("architecture", "DEPENDENCY_CYCLE")) is None


def test_malformed_or_partially_ungrounded_candidate_output_is_not_a_successful_model_result():
    assert validated_candidate_findings_payload('{"confidence":0,"findings":[]}') == {
        "confidence": 0,
        "findings": [],
    }
    assert validated_candidate_findings_payload("not json") is None
    assert validated_candidate_findings_payload('{"findings":[]}') is None
    assert validated_candidate_findings_payload('{"confidence":true,"findings":[]}') is None
    assert validated_candidate_findings_payload('{"confidence":1e99999,"findings":[]}') is None
    assert validated_candidate_findings_payload(
        '{"confidence":0.5,"findings":[{"candidate_id":"x"}]}'
    ) is None
    unhashable_severity = {
        "confidence": 0.5,
        "findings": [{
            "candidate_id": "x", "title": "t", "description": "d", "severity": [],
            "category": "correctness", "evidence_refs": ["chunk:x"], "source_behavior": "s",
            "trigger_condition": "t", "failure_mechanism": "m", "impact_claim": "i",
            "counter_evidence_considered": [],
        }],
    }
    assert validated_candidate_findings_payload(json.dumps(unhashable_severity)) is None
