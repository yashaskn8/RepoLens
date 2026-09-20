import pytest

from app.agent_runtime.schemas import InvestigatorAction
from app.evaluation.agent import run_scripted_trial
from app.evaluation.agent.schemas import (
    AgentEvalAnnotation,
    AgentEvalCase,
    AgentEvalDifficulty,
    AgentEvalFixture,
    AgentEvalInvestigatorInput,
    AgentEvalSplit,
    ScriptedDecision,
)


def _case(*decisions: ScriptedDecision) -> AgentEvalCase:
    return AgentEvalCase(
        case_id="production-node-sequence",
        case_family="trajectory",
        split=AgentEvalSplit.REGRESSION,
        category="BUG",
        difficulty=AgentEvalDifficulty.EASY,
        fixture=AgentEvalFixture(
            repository_url="https://github.com/example/eval.git",
            files={"app.py": "def read(value):\n    return value\n"},
        ),
        investigator_input=AgentEvalInvestigatorInput(
            title="Possible issue",
            description="Need bounded repository evidence.",
            category="BUG",
            primary_file="app.py",
            primary_start_line=1,
            primary_end_line=2,
            verifier_uncertainty_reason="Caller validation is unresolved.",
        ),
        annotation=AgentEvalAnnotation(
            acceptable_stop_reasons=["EVIDENCE_GATHERED"],
            hidden_canary="never-enter-model-context",
            durability_case=True,
        ),
        scripted_decisions=list(decisions),
    )


@pytest.mark.asyncio
async def test_runner_executes_real_nodes_and_model_script_selects_tools():
    case = _case(
        ScriptedDecision(
            action=InvestigatorAction.TOOL_CALL,
            tool_name="search_symbol",
            arguments={"query": "read", "match_mode": "EXACT"},
            reason="Discover the stable symbol identity.",
        ),
        ScriptedDecision(
            action=InvestigatorAction.TOOL_CALL,
            tool_name="inspect_file",
            arguments={"file_path": "app.py"},
            reason="Inspect the deterministic file facts.",
        ),
        ScriptedDecision(
            action=InvestigatorAction.TOOL_CALL,
            tool_name="read_source_slice",
            arguments={"file_path": "app.py", "start_line": 1, "end_line": 2},
            reason="Read the bounded source span.",
        ),
        ScriptedDecision(
            action=InvestigatorAction.FINISH,
            reason="Collected evidence is sufficient for independent verification.",
        ),
    )
    result = await run_scripted_trial(case)
    assert [event.tool_name for event in result.tool_events] == [
        "search_symbol", "inspect_file", "read_source_slice",
    ]
    trajectory = next(iter(result.final_state["investigator"]["results"].values()))
    assert trajectory["stop_reason"] == "EVIDENCE_GATHERED"
    assert result.model_decisions_consumed == 4
    assert result.final_state["investigation_evidence"]


@pytest.mark.asyncio
async def test_runner_checkpoint_resume_does_not_repeat_completed_tool():
    case = _case(
        ScriptedDecision(
            action=InvestigatorAction.TOOL_CALL,
            tool_name="read_source_slice",
            arguments={"file_path": "app.py", "start_line": 1, "end_line": 2},
            reason="Read the bounded source span.",
        ),
        ScriptedDecision(
            action=InvestigatorAction.FINISH,
            reason="Collected evidence is sufficient for independent verification.",
        ),
    )
    result = await run_scripted_trial(case, interrupt_after_tool=True)
    assert result.resumed is True
    assert len(result.tool_events) == 1
    assert result.model_decisions_consumed == 2
    assert result.final_state["investigator"]["results"]
