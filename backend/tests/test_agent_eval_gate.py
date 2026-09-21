from pathlib import Path

import pytest

from app.evaluation.agent.contract import evaluation_contract_hash
from app.evaluation.agent.gate import AgentEvalGateError, assert_report_passes_gate, load_gate
from app.evaluation.agent.grading import AgentEvalGrade, AgentEvalMetrics
from app.evaluation.agent.report import AgentEvalReport, AgentEvalReportMode


_GATE_PATH = Path(__file__).parents[1] / "evaluation_data" / "agent" / "v1" / "regression_gate.json"


def _passing_report() -> AgentEvalReport:
    gate = load_gate(_GATE_PATH)
    return AgentEvalReport(
        mode=AgentEvalReportMode.SCRIPTED,
        dataset_version="agent-eval-v1",
        dataset_hash=gate.dataset_hash,
        grades=[AgentEvalGrade(case_id=f"case-{index}", passed=True, evidence_refs=["evidence:test"])
                for index in range(gate.expected_case_count)],
        metrics=AgentEvalMetrics(
            case_count=gate.expected_case_count,
            passed=gate.expected_case_count,
            failed=0,
            pass_rate=1.0,
            evidence_validity_rate=1.0,
            evidence_validity_all_cases=1.0,
            required_evidence_cases=gate.expected_case_count,
            required_evidence_success_rate=1.0,
            unsafe_tool_requests=0,
            unsafe_tool_executions=0,
            duplicate_tool_executions=0,
            checkpoint_resumed_cases=0,
            checkpoint_duplicate_tool_executions=0,
            context_budget_exceeded_cases=0,
            context_measurements=gate.expected_case_count,
            max_context_bytes=1,
            unsupported_finding_count=0,
            tool_calls=gate.expected_case_count,
            model_calls=gate.expected_case_count,
            tool_calls_per_case=1.0,
            model_calls_per_case=1.0,
            budget_exhaustion_rate=0.0,
        ),
    )


def test_committed_gate_accepts_current_contract():
    gate = load_gate(_GATE_PATH)
    assert_report_passes_gate(_passing_report(), gate)


@pytest.mark.parametrize(
    "change",
    [
        {"minimum_pass_rate": 0.0},
        {"maximum_unsupported_finding_count": 1},
        {"expected_case_count": 1},
        {"evaluation_contract_hash": "0" * 64},
    ],
)
def test_gate_policy_or_contract_tampering_is_rejected(change):
    gate = load_gate(_GATE_PATH).model_copy(update=change)
    with pytest.raises(AgentEvalGateError):
        assert_report_passes_gate(_passing_report(), gate)


def test_current_contract_hash_is_the_one_used_by_reports():
    assert _passing_report().evaluation_contract_hash == evaluation_contract_hash()
