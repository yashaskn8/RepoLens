import pytest

from app.agent_runtime.schemas import InvestigatorAction
from app.evaluation.agent import (
    RecordingAgentToolRegistry,
    ScriptedEvaluationRouter,
    ScriptedRouterExhaustedError,
)
from app.evaluation.agent.fixtures import build_fixture_runtime
from app.evaluation.agent.schemas import (
    AgentEvalCase,
    AgentEvalDifficulty,
    AgentEvalFixture,
    AgentEvalInvestigatorInput,
    AgentEvalSplit,
    AgentEvalAnnotation,
    ScriptedDecision,
)
from app.llm.types import LLMRequest, LLMMessage


def _case() -> AgentEvalCase:
    return AgentEvalCase(
        case_id="recorder-case",
        case_family="unit",
        split=AgentEvalSplit.REGRESSION,
        category="BUG",
        difficulty=AgentEvalDifficulty.EASY,
        fixture=AgentEvalFixture(
            repository_url="https://github.com/example/eval.git",
            files={"app.py": "def read(value):\n    return value\n"},
        ),
        investigator_input=AgentEvalInvestigatorInput(
            title="Possible issue",
            description="Need one bounded observation.",
            category="BUG",
            primary_file="app.py",
            primary_start_line=1,
            primary_end_line=2,
            verifier_uncertainty_reason="Caller validation is unresolved.",
        ),
        annotation=AgentEvalAnnotation(
            acceptable_stop_reasons=["EVIDENCE_GATHERED"],
            hidden_canary="never-enter-model-context",
        ),
        scripted_decisions=[ScriptedDecision(
            action=InvestigatorAction.FINISH,
            reason="The existing evidence is enough for verification.",
        )],
    )


@pytest.mark.asyncio
async def test_scripted_router_emits_production_decision_and_refuses_reuse():
    router = ScriptedEvaluationRouter(_case().scripted_decisions)
    request = LLMRequest(messages=[LLMMessage(role="user", content="bounded")])
    response = await router.generate(request)
    assert response.provider.value == "gemini"
    assert response.metadata.extra_metadata["SCRIPTED_NOT_A_REAL_PROVIDER"] is True
    assert '"action":"FINISH"' in response.content
    with pytest.raises(ScriptedRouterExhaustedError):
        await router.generate(request)


def test_recording_registry_delegates_and_records_bounded_result():
    with build_fixture_runtime(_case()) as runtime:
        registry = RecordingAgentToolRegistry(runtime.registry)
        result = registry.invoke("read_source_slice", {
            "snapshot_id": runtime.snapshot.snapshot_id,
            "file_path": "app.py",
            "start_line": 1,
            "end_line": 2,
        })
        assert result.status.value == "SUCCESS"
        assert len(registry.events) == 1
        event = registry.events[0]
        assert event.tool_name == "read_source_slice"
        assert event.evidence_refs
        assert len(event.result_digest) == 64
        assert "return value" not in str(event)


def test_recording_registry_records_invalid_arguments_without_execution():
    with build_fixture_runtime(_case()) as runtime:
        registry = RecordingAgentToolRegistry(runtime.registry)
        result = registry.invoke("read_source_slice", {"file_path": "../secret"})
        assert result.status.value == "INVALID_INPUT"
        assert registry.events[0].validation_code is not None
