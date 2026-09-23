"""Security and integration tests for evaluator-only graph checkpoint replay."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.evaluation.counterfactual.checkpoints import locate_factual_checkpoint
from app.evaluation.counterfactual.contracts import ReplayOutcomeMetrics, canonical_digest
from app.evaluation.counterfactual.eligibility import select_replay_intervention
from app.evaluation.counterfactual.replay import (
    CounterfactualReplayCoordinator,
    _branch_tool_call_count,
    _classify_effect,
    _recorded_model_pairs,
)
from app.evaluation.ground_truth.matcher import IndependentBenchmarkJudge
from app.evaluation.ground_truth.schemas import BenchmarkCase, EvaluationStage
from app.evaluation.system.full_analysis import run_full_analysis_evaluation
from app.evaluation.system.identity import (
    full_analysis_evaluation_contract_hash,
    full_analysis_graph_identity_digest,
)
from app.evaluation.system.schemas import FailureAttribution, FailureClass, SystemEvalMode
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
import app.agents.graph as graph_module
import app.evaluation.system.full_analysis as full_analysis_module


_CASE_PATH = (
    Path(__file__).resolve().parents[1]
    / "evaluation_data"
    / "ground_truth"
    / "v1"
    / "cases"
    / "correctness"
    / "BUG-EXCEPT-01A.json"
)


def _case() -> BenchmarkCase:
    return BenchmarkCase.model_validate_json(_CASE_PATH.read_text(encoding="utf-8"))


def _clean_case() -> BenchmarkCase:
    path = _CASE_PATH.with_name("BUG-EXCEPT-01C.json")
    return BenchmarkCase.model_validate_json(path.read_text(encoding="utf-8"))


def _attribution(
    case: BenchmarkCase,
    failure_class: FailureClass,
    *,
    evidence_refs: list[str] | None = None,
    hard_safety_violation: bool = False,
) -> FailureAttribution:
    specialist = failure_class == FailureClass.SPECIALIST_MISSED_FINDING
    return FailureAttribution(
        case_id=case.case_id,
        failure_stage="VERIFIER",
        failure_class=failure_class,
        primary_node="bug" if specialist else "verifier",
        upstream_condition="Bounded test attribution.",
        observed_behavior="Bounded test observation.",
        expected_behavior="Bounded test expectation.",
        evidence_refs=evidence_refs or [],
        downstream_effect="Bounded test effect.",
        hard_safety_violation=hard_safety_violation,
        confidence_basis="Deterministic test fixture.",
        target_prompt_component="bug-agent" if specialist else None,
        specialist_opportunity_digest="a" * 64 if specialist else None,
    )


def _matched_candidate(case: BenchmarkCase, finding_id: UUID) -> Finding:
    claim = case.annotation.claims[0]
    return Finding(
        id=finding_id,
        scan_id=UUID("00000000-0000-0000-0000-000000000099"),
        title="Exception handling hides payment failure",
        description="A broad exception is suppressed in the payment handler.",
        severity=Severity.MEDIUM,
        status=FindingStatus.OPEN,
        rule_id=claim.rule_id,
        category="bug",
        evidences=[Evidence(
            file_path=claim.permitted_files[0],
            start_line=claim.permitted_spans[0][0],
            end_line=claim.permitted_spans[0][1],
        )],
    )


def test_replay_opt_in_uses_real_graph_and_preserves_factual_trial(monkeypatch):
    # The public case schema usually grades an earlier native candidate stage;
    # this in-memory test-only projection grades final publication so the
    # verifier intervention has a measurable downstream effect.
    case = _case().model_copy(update={"evaluation_stage": EvaluationStage.PUBLISHED_FINDING})
    claim = case.annotation.claims[0]
    monkeypatch.setattr(full_analysis_module, "load_public_dev_repository_cases", lambda: [case])

    async def emit_candidate(state, runtime=None):
        finding = Finding(
            id=UUID("00000000-0000-0000-0000-000000000041"),
            scan_id=UUID(str(state["scan_id"])),
            title="Exception handling hides payment failure",
            description="A broad exception is suppressed in the payment handler.",
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            rule_id=claim.rule_id,
            category="bug",
            evidences=[Evidence(
                file_path=claim.permitted_files[0],
                start_line=claim.permitted_spans[0][0],
                end_line=claim.permitted_spans[0][1],
            )],
        )
        return {"candidate_findings": [finding], "completed_nodes": ["bug"]}

    async def reject_candidate(state, runtime=None):
        finding = state["candidate_findings"][0]
        return {
            "verified_findings": [],
            "rejected_findings": [{
                "finding_id": str(finding.id),
                "verdict": VerificationVerdict.REJECTED.value,
                "reason": "Test-only verifier rejection for causal replay coverage.",
            }],
            "verification_decision": "verified",
            "revision_target_ids": [],
            "completed_nodes": ["verifier"],
        }

    emit_candidate.__name__ = "run_bug_agent"
    reject_candidate.__name__ = "run_verifier_agent"
    monkeypatch.setattr(graph_module, "run_bug_agent", emit_candidate)
    monkeypatch.setattr(graph_module, "run_verifier_agent", reject_candidate)

    report = asyncio.run(run_full_analysis_evaluation(
        mode=SystemEvalMode.SCRIPTED,
        max_cases=1,
        case_ids=[case.case_id],
        counterfactual_replay=True,
    ))

    assert report.schema_version == "agent-system-eval-report/1.3"
    assert report.full_analysis is not None
    artifact = report.full_analysis.counterfactual_replay
    assert artifact is not None
    factual_trace = report.full_analysis.trial_details[0].workflow_trace
    assert artifact.execution_mode == "SCRIPTED_HARNESS_VALIDATION_ONLY"
    assert artifact.factual_report_digest != report.report_digest
    assert artifact.system_identity_digest == report.system_identity.system_digest
    assert artifact.trial_results[0].reason_code == "CORRECTIVE_REPLAY_COMPLETED", artifact.trial_results[0].reason_code
    assert artifact.replayable_trials == 1, artifact.trial_results
    assert artifact.full_rescues == 1
    assert artifact.trial_results[0].effect.value == "FULL_RESCUE"
    assert artifact.trial_results[0].intervention is not None
    assert artifact.trial_results[0].intervention.target_node == "verifier"

    # The original graph result remains the factual false negative; the
    # counterfactual branch is a separate checkpoint lineage and report item.
    factual = report.full_analysis.trial_details[0]
    assert factual.fn == 1
    assert factual.failure_attribution is not None
    assert factual.failure_attribution.failure_class.value == "VERIFIER_FALSE_REJECTION"
    serialized = json.dumps(report.model_dump(mode="json"), sort_keys=True)
    assert case.fixture.files[claim.permitted_files[0]] not in serialized


def test_replay_rejects_one_unsupported_confirmation_and_regrades_clean_case(monkeypatch):
    case = _clean_case().model_copy(update={"evaluation_stage": EvaluationStage.PUBLISHED_FINDING})
    monkeypatch.setattr(full_analysis_module, "load_public_dev_repository_cases", lambda: [case])

    async def emit_unsupported_candidate(state, runtime=None):
        finding = Finding(
            id=UUID("00000000-0000-0000-0000-000000000042"),
            scan_id=UUID(str(state["scan_id"])),
            title="Unsupported broad exception finding",
            description="The fixture contains no broad exception claim.",
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            rule_id="BROAD_EXCEPTION_SWALLOW",
            category="bug",
            evidences=[Evidence(
                file_path="app/services/payment.py",
                start_line=1,
                end_line=1,
            )],
        )
        return {"candidate_findings": [finding], "completed_nodes": ["bug"]}

    async def confirm_candidate(state, runtime=None):
        finding = state["candidate_findings"][0].model_copy(deep=True)
        finding.verification_verdict = VerificationVerdict.CONFIRMED
        finding.verification_reason = "Test-only factual confirmation."
        return {
            "verified_findings": [finding],
            "rejected_findings": [],
            "verification_decision": "verified",
            "revision_target_ids": [],
            "completed_nodes": ["verifier"],
        }

    emit_unsupported_candidate.__name__ = "run_bug_agent"
    confirm_candidate.__name__ = "run_verifier_agent"
    monkeypatch.setattr(graph_module, "run_bug_agent", emit_unsupported_candidate)
    monkeypatch.setattr(graph_module, "run_verifier_agent", confirm_candidate)

    report = asyncio.run(run_full_analysis_evaluation(
        mode=SystemEvalMode.SCRIPTED,
        max_cases=1,
        case_ids=[case.case_id],
        counterfactual_replay=True,
    ))

    assert report.full_analysis is not None
    assert report.full_analysis.trial_details[0].fp == 1
    artifact = report.full_analysis.counterfactual_replay
    assert artifact is not None
    replay = artifact.trial_results[0]
    assert replay.reason_code == "CORRECTIVE_REPLAY_COMPLETED", replay.reason_code
    assert replay.effect.value == "FULL_RESCUE"
    assert replay.intervention is not None
    assert replay.intervention.intervention_kind.value == "VERIFIER_REJECT_UNSUPPORTED_FINDING"
    assert replay.factual is not None and replay.factual.hard_safety_violation
    assert replay.counterfactual is not None
    assert replay.counterfactual.success
    assert not replay.counterfactual.hard_safety_violation


def test_revision_restore_replays_only_from_revise_checkpoint(monkeypatch):
    case = _case().model_copy(update={"evaluation_stage": EvaluationStage.PUBLISHED_FINDING})
    claim = case.annotation.claims[0]
    monkeypatch.setattr(full_analysis_module, "load_public_dev_repository_cases", lambda: [case])

    finding_id = UUID("00000000-0000-0000-0000-000000000043")

    async def emit_candidate(state, runtime=None):
        finding = Finding(
            id=finding_id,
            scan_id=UUID(str(state["scan_id"])),
            title="Exception handling hides payment failure",
            description="A broad exception is suppressed in the payment handler.",
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            rule_id=claim.rule_id,
            category="bug",
            evidences=[Evidence(
                file_path=claim.permitted_files[0],
                start_line=claim.permitted_spans[0][0],
                end_line=claim.permitted_spans[0][1],
            )],
        )
        return {"candidate_findings": [finding], "completed_nodes": ["bug"]}

    async def revise_badly(state, runtime=None):
        candidate = state["candidate_findings"][0].model_copy(deep=True)
        candidate.evidences = [Evidence(
            file_path=claim.permitted_files[0],
            start_line=999,
            end_line=999,
        )]
        return {
            "revision_candidates": [candidate],
            "revision_count": 1,
            "completed_nodes": ["revise"],
            "status": "REVISED",
        }

    async def verifier_transitions(state, runtime=None):
        target = str(finding_id)
        if int(state.get("revision_count", 0) or 0) == 0:
            return {
                "verified_findings": [],
                "rejected_findings": [{
                    "finding_id": target,
                    "verdict": VerificationVerdict.POSSIBLE.value,
                    "reason": "The available evidence leaves one semantic detail uncertain.",
                }],
                "verification_decision": "needs_revision",
                "revision_target_ids": [target],
                "completed_nodes": ["verifier"],
            }
        revised = list(state.get("revision_candidates", []))
        if revised and revised[0].evidences[0].start_line == claim.permitted_spans[0][0]:
            accepted = revised[0].model_copy(deep=True)
            accepted.verification_verdict = VerificationVerdict.CONFIRMED
            return {
                "verified_findings": [accepted],
                "rejected_findings": [],
                "verification_decision": "verified",
                "revision_target_ids": [],
                "completed_nodes": ["verifier"],
            }
        # Model the factual downstream loss without falsely asserting a second
        # verifier rejection; deterministic attribution can then isolate the
        # failed revision transition.
        return {
            "verified_findings": [],
            "rejected_findings": [],
            "verification_decision": "verified",
            "revision_target_ids": [],
            "completed_nodes": ["verifier"],
        }

    emit_candidate.__name__ = "run_bug_agent"
    revise_badly.__name__ = "run_revision_agent"
    verifier_transitions.__name__ = "run_verifier_agent"
    monkeypatch.setattr(graph_module, "run_bug_agent", emit_candidate)
    monkeypatch.setattr(graph_module, "run_revision_agent", revise_badly)
    monkeypatch.setattr(graph_module, "run_verifier_agent", verifier_transitions)

    report = asyncio.run(run_full_analysis_evaluation(
        mode=SystemEvalMode.SCRIPTED,
        max_cases=1,
        case_ids=[case.case_id],
        counterfactual_replay=True,
    ))

    assert report.full_analysis is not None
    factual = report.full_analysis.trial_details[0]
    assert factual.fn == 1
    assert factual.failure_attribution is not None
    assert factual.failure_attribution.failure_class.value == "REVISION_FAILED_TO_REPAIR"
    artifact = report.full_analysis.counterfactual_replay
    assert artifact is not None
    replay = artifact.trial_results[0]
    assert replay.reason_code == "CORRECTIVE_REPLAY_COMPLETED", replay.reason_code
    assert replay.effect.value == "FULL_RESCUE"
    assert replay.intervention is not None
    assert replay.intervention.target_node == "revise"
    assert "revise" not in [item.node for item in replay.trace]
    assert "verifier" in [item.node for item in replay.trace]


def test_counterfactual_report_digest_and_factual_binding_reject_tampering(monkeypatch):
    case = _case()
    monkeypatch.setattr(full_analysis_module, "load_public_dev_repository_cases", lambda: [case])
    report = asyncio.run(run_full_analysis_evaluation(
        mode=SystemEvalMode.SCRIPTED,
        max_cases=1,
        case_ids=[case.case_id],
        counterfactual_replay=True,
    ))
    payload = report.model_dump(mode="json")
    payload["full_analysis"]["counterfactual_replay"]["total_tool_calls"] += 1
    with pytest.raises(ValidationError, match="digest does not match|aggregate counts"):
        type(report).model_validate(payload)


def test_replay_flag_is_cli_opt_in_and_full_analysis_only(capsys):
    from app.evaluation.system.cli import main

    result = main([
        "run", "--scope", "investigator", "--mode", "scripted",
        "--counterfactual-replay",
    ])
    assert result == 2
    assert "requires --scope full-analysis" in capsys.readouterr().out


def test_counterfactual_effects_use_whole_case_metrics():
    factual = ReplayOutcomeMetrics(
        success=False, tp=0, fp=0, fn=2, unsupported_claims=0,
        invalid_references=0, hard_safety_violation=False,
    )
    partial = ReplayOutcomeMetrics(
        success=False, tp=0, fp=0, fn=1, unsupported_claims=0,
        invalid_references=0, hard_safety_violation=False,
    )
    unchanged = factual.model_copy(deep=True)
    regression = ReplayOutcomeMetrics(
        success=False, tp=0, fp=1, fn=2, unsupported_claims=0,
        invalid_references=0, hard_safety_violation=False,
    )
    success_lost = factual.model_copy(update={"success": True})
    outcome_regression = partial.model_copy(update={"success": False, "fn": 2})
    assert _classify_effect(factual, partial).value == "PARTIAL_RESCUE"
    assert _classify_effect(factual, unchanged).value == "NO_EFFECT"
    assert _classify_effect(factual, regression).value == "REGRESSION"
    assert _classify_effect(success_lost, outcome_regression).value == "REGRESSION"


def test_live_replay_requires_complete_exact_factual_model_identity():
    class Execution:
        provider = "gemini"
        model_name = "registered-model-x"

    pairs, measured = _recorded_model_pairs({"model_executions": [Execution()]})
    assert measured
    assert pairs == {("gemini", "registered-model-x")}
    assert _recorded_model_pairs({"model_executions": []}) == (set(), False)

    class MissingProvider:
        model_name = "registered-model-x"

    assert _recorded_model_pairs({"model_executions": [MissingProvider()]}) == (set(), False)


def test_live_replay_stops_before_checkpoint_without_factual_provider_proof():
    from types import SimpleNamespace

    case = _case()
    finding_id = UUID("00000000-0000-0000-0000-000000000054")
    state = {
        "status": "COMPLETED",
        "commit_hash": "snapshot-current",
        "candidate_findings": [_matched_candidate(case, finding_id)],
        "verified_findings": [],
        "rejected_findings": [{"finding_id": str(finding_id), "verdict": "REJECTED"}],
        "workflow_trace": [{
            "node": "verifier",
            "superstep": 1,
            "status": "COMPLETED",
            "duration_ms": 0.0,
            "input_digest": "d" * 64,
            "output_digest": "e" * 64,
            "rejected_ids": [str(finding_id)],
        }],
    }
    judge = IndependentBenchmarkJudge()
    grade = judge.evaluate_case(
        case,
        [],
        set(case.fixture.files),
        {path: len(content.splitlines()) for path, content in case.fixture.files.items()},
    )
    coordinator = CounterfactualReplayCoordinator(
        mode=SystemEvalMode.LIVE,
        expected_provider="gemini",
        expected_model="registered-model-x",
        allowed_case_digests={case.case_id: canonical_digest(case.model_dump(mode="json"))},
    )
    result = asyncio.run(coordinator.replay_trial(
        case=case,
        trial_number=1,
        factual_state=state,
        attribution=_attribution(case, FailureClass.VERIFIER_FALSE_REJECTION),
        judged=grade,
        published_judged=grade,
        judge=judge,
        graph=None,
        factual_config={},
        runtime_context=None,
        fixture=SimpleNamespace(snapshot_id="snapshot-current"),
        system_identity=None,
    ))[0]
    assert result.effect.value == "INVALID_REPLAY"
    assert result.reason_code == "FACTUAL_MODEL_IDENTITY_UNVERIFIED"


def test_replay_tool_usage_counts_runtime_attempts_without_trace_double_count():
    from types import SimpleNamespace

    runtime = SimpleNamespace(mcp_executor=SimpleNamespace(execution_records=["old", "one", "two"]))
    assert _branch_tool_call_count(
        runtime,
        {"mcp_call_count": 1},
        [{"tool_execution_count": 1}],
    ) == 2
    assert _branch_tool_call_count(
        runtime,
        {"mcp_call_count": 1},
        [{"tool_execution_count": 3}],
    ) == 3


def test_replay_rejects_case_outside_run_public_dev_inventory():
    coordinator = CounterfactualReplayCoordinator(
        mode=SystemEvalMode.SCRIPTED,
        expected_provider=None,
        expected_model="scripted-full-analysis-harness",
        allowed_case_digests={},
    )
    result = asyncio.run(coordinator.replay_trial(
        case=type("ForeignCase", (), {"case_id": "PRIVATE-HOLDOUT-CASE"})(),
        trial_number=1,
        factual_state={},
        attribution=None,
        judged=None,
        published_judged=None,
        judge=None,
        graph=None,
        factual_config={},
        runtime_context=None,
        fixture=None,
        system_identity=None,
    ))[0]
    assert result.effect.value == "NOT_REPLAYABLE"
    assert result.reason_code == "CASE_OUTSIDE_PUBLIC_RUN_INVENTORY"


def test_checkpoint_locator_rejects_stale_and_ambiguous_history():
    target_id = "finding-target"

    def checkpoint(checkpoint_id: str, snapshot_id: str = "snapshot-current"):
        return type("Snapshot", (), {
            "values": {
                "commit_hash": snapshot_id,
                "workflow_trace": [{"node": "verifier"}],
                "candidate_findings": [{"id": target_id}],
                "verified_findings": [],
                "rejected_findings": [{"finding_id": target_id, "verdict": "REJECTED"}],
            },
            "config": {"configurable": {"checkpoint_id": checkpoint_id}},
            "next": ("finalize",),
        })()

    class HistoryGraph:
        def __init__(self, snapshots):
            self.snapshots = snapshots

        async def aget_state_history(self, config, *, limit):
            assert limit == 8
            for snapshot in self.snapshots:
                yield snapshot

    async def locate(snapshots):
        return await locate_factual_checkpoint(
            HistoryGraph(snapshots),
            {"configurable": {"thread_id": "ephemeral-eval-thread"}},
            target_node="verifier",
            target_finding_id=target_id,
            expected_snapshot_id="snapshot-current",
            max_history=8,
        )

    stale, stale_reason = asyncio.run(locate([checkpoint("stale", "snapshot-old")]))
    assert stale is None and stale_reason == "CHECKPOINT_NOT_FOUND"
    selected, selected_reason = asyncio.run(locate([checkpoint("exact")]))
    assert selected_reason == "SELECTED"
    assert selected.config["configurable"]["checkpoint_id"] == "exact"
    ambiguous, ambiguous_reason = asyncio.run(locate([checkpoint("a"), checkpoint("b")]))
    assert ambiguous is None and ambiguous_reason == "CHECKPOINT_AMBIGUOUS"


def test_intervention_selection_rejects_wrong_ambiguous_and_synthetic_targets():
    case = _case()
    judge = IndependentBenchmarkJudge()
    files = set(case.fixture.files)
    line_counts = {path: len(content.splitlines()) for path, content in case.fixture.files.items()}
    empty_grade = judge.evaluate_case(case, [], files, line_counts)
    first_id = UUID("00000000-0000-0000-0000-000000000051")
    second_id = UUID("00000000-0000-0000-0000-000000000052")
    first = _matched_candidate(case, first_id)

    wrong = first.model_copy(deep=True)
    wrong.evidences = [Evidence(file_path="outside.py", start_line=1, end_line=1)]
    wrong_result = select_replay_intervention(
        case,
        {
            "status": "COMPLETED",
            "candidate_findings": [wrong],
            "rejected_findings": [{"finding_id": str(first_id), "verdict": "REJECTED"}],
            "workflow_trace": [{"node": "verifier", "rejected_ids": [str(first_id)]}],
        },
        _attribution(case, FailureClass.VERIFIER_FALSE_REJECTION),
        judged=empty_grade,
        published_judged=empty_grade,
        judge=judge,
    )
    assert not wrong_result.eligible
    assert wrong_result.reason_code == "AMBIGUOUS_OR_UNPROVEN_MATCHED_CANDIDATE"

    ambiguous_result = select_replay_intervention(
        case,
        {
            "status": "COMPLETED",
            "candidate_findings": [first, _matched_candidate(case, second_id)],
            "rejected_findings": [
                {"finding_id": str(first_id), "verdict": "REJECTED"},
                {"finding_id": str(second_id), "verdict": "REJECTED"},
            ],
            "workflow_trace": [{"node": "verifier", "rejected_ids": [str(first_id), str(second_id)]}],
        },
        _attribution(case, FailureClass.VERIFIER_FALSE_REJECTION),
        judged=empty_grade,
        published_judged=empty_grade,
        judge=judge,
    )
    assert not ambiguous_result.eligible
    assert ambiguous_result.reason_code == "AMBIGUOUS_OR_UNPROVEN_MATCHED_CANDIDATE"

    specialist_miss = select_replay_intervention(
        case,
        {"status": "COMPLETED"},
        _attribution(case, FailureClass.SPECIALIST_MISSED_FINDING),
        judged=empty_grade,
        published_judged=empty_grade,
        judge=judge,
    )
    assert not specialist_miss.eligible
    assert specialist_miss.reason_code == "NO_FAITHFUL_SPECIALIST_ACTION_INTERVENTION"


def test_replay_rejects_current_graph_and_evaluation_contract_mismatch():
    from types import SimpleNamespace

    case = _case()
    finding_id = UUID("00000000-0000-0000-0000-000000000053")
    candidate = _matched_candidate(case, finding_id)
    state = {
        "status": "COMPLETED",
        "commit_hash": "snapshot-current",
        "candidate_findings": [candidate],
        "verified_findings": [],
        "rejected_findings": [{"finding_id": str(finding_id), "verdict": "REJECTED"}],
        "workflow_trace": [{
            "node": "verifier",
            "superstep": 1,
            "status": "COMPLETED",
            "duration_ms": 0.0,
            "input_digest": "d" * 64,
            "output_digest": "e" * 64,
            "rejected_ids": [str(finding_id)],
        }],
    }
    judge = IndependentBenchmarkJudge()
    grade = judge.evaluate_case(
        case,
        [],
        set(case.fixture.files),
        {path: len(content.splitlines()) for path, content in case.fixture.files.items()},
    )
    attribution = _attribution(case, FailureClass.VERIFIER_FALSE_REJECTION)
    graph_digest = full_analysis_graph_identity_digest()
    valid_identity = {
        "scope": "FULL_ANALYSIS_GRAPH",
        "system_digest": "a" * 64,
        "graph_identity_digest": graph_digest,
        "evaluation_contract_hash": full_analysis_evaluation_contract_hash(graph_digest),
    }

    async def run(identity):
        coordinator = CounterfactualReplayCoordinator(
            mode=SystemEvalMode.SCRIPTED,
            expected_provider=None,
            expected_model="scripted-full-analysis-harness",
            allowed_case_digests={case.case_id: canonical_digest(case.model_dump(mode="json"))},
        )
        return (await coordinator.replay_trial(
            case=case,
            trial_number=1,
            factual_state=state,
            attribution=attribution,
            judged=grade,
            published_judged=grade,
            judge=judge,
            graph=None,
            factual_config={},
            runtime_context=None,
            fixture=SimpleNamespace(snapshot_id="snapshot-current"),
            system_identity=identity,
        ))[0]

    graph_mismatch = asyncio.run(run(SimpleNamespace(**{
        **valid_identity,
        "graph_identity_digest": "b" * 64,
    })))
    assert graph_mismatch.effect.value == "INVALID_REPLAY"
    assert graph_mismatch.reason_code == "SYSTEM_IDENTITY_INVALID"
    contract_mismatch = asyncio.run(run(SimpleNamespace(**{
        **valid_identity,
        "evaluation_contract_hash": "c" * 64,
    })))
    assert contract_mismatch.effect.value == "INVALID_REPLAY"
    assert contract_mismatch.reason_code == "SYSTEM_IDENTITY_INVALID"
