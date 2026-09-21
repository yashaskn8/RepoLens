import pytest

from app.agent_runtime.schemas import InvestigatorAction
from app.evaluation.agent import compute_metrics, grade_trial, run_scripted_trial
from app.evaluation.agent.schemas import (
    AgentEvalAnnotation,
    AgentEvalCase,
    AgentEvalDifficulty,
    AgentEvalEvidenceSpec,
    AgentEvalFixture,
    AgentEvalInvestigatorInput,
    AgentEvalSplit,
    ScriptedDecision,
)
from app.agent_tools.schemas import EvidenceType


def _case() -> AgentEvalCase:
    return AgentEvalCase(
        case_id="grading-case",
        case_family="grading",
        split=AgentEvalSplit.REGRESSION,
        category="BUG",
        difficulty=AgentEvalDifficulty.EASY,
        fixture=AgentEvalFixture(
            repository_url="https://github.com/example/eval.git",
            files={"app.py": "def read(value):\n    return value\n"},
        ),
        investigator_input=AgentEvalInvestigatorInput(
            title="Possible issue",
            description="Need bounded source evidence.",
            category="BUG",
            primary_file="app.py",
            primary_start_line=1,
            primary_end_line=2,
            verifier_uncertainty_reason="Caller validation is unresolved.",
        ),
        annotation=AgentEvalAnnotation(
            acceptable_stop_reasons=["EVIDENCE_GATHERED"],
            required_tools_all=["read_source_slice"],
            required_evidence=[AgentEvalEvidenceSpec(
                evidence_type=EvidenceType.SOURCE_SLICE,
                file_path="app.py",
                start_line=1,
            )],
            hidden_canary="never-enter-model-context",
        ),
        scripted_decisions=[
            ScriptedDecision(
                action=InvestigatorAction.TOOL_CALL,
                tool_name="read_source_slice",
                arguments={"file_path": "app.py", "start_line": 1, "end_line": 2},
                reason="Read the bounded source span.",
            ),
            ScriptedDecision(
                action=InvestigatorAction.FINISH,
                reason="Evidence is sufficient for verification.",
            ),
        ],
    )


@pytest.mark.asyncio
async def test_grader_matches_trusted_evidence_and_metrics():
    case = _case()
    trial = await run_scripted_trial(case)
    grade = grade_trial(case, trial)
    assert grade.passed is True
    assert grade.model_capability_measured is False
    metrics = compute_metrics([grade], [trial])
    assert metrics.pass_rate == 1.0
    assert metrics.evidence_validity_rate == 1.0
    assert metrics.evidence_validity_all_cases == 1.0
    assert metrics.required_evidence_success_rate == 1.0
    assert metrics.unsafe_tool_requests == 0
    assert metrics.unsafe_tool_executions == 0
    assert metrics.duplicate_tool_executions == 0
    assert metrics.checkpoint_resumed_cases == 0
    assert metrics.checkpoint_duplicate_tool_executions == 0
    assert metrics.context_budget_exceeded_cases == 0
    assert metrics.context_measurements == trial.model_decisions_consumed
    assert metrics.max_context_bytes == max(request.context_bytes for request in trial.model_requests)
    assert metrics.classification_metrics_measured is False


@pytest.mark.asyncio
async def test_grader_rejects_missing_required_tool():
    case = _case().model_copy(update={
        "scripted_decisions": [ScriptedDecision(
            action=InvestigatorAction.FINISH,
            reason="No safe tool is needed.",
        )],
    })
    trial = await run_scripted_trial(case)
    grade = grade_trial(case, trial)
    assert grade.passed is False
    assert any("required tool" in item for item in grade.failures)
