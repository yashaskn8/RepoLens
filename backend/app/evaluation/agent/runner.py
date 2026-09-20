"""Isolated evaluator runner that drives the production investigator nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from app.agents.investigator import (
    route_after_investigator_complete,
    route_after_investigator_compact,
    route_after_investigator_decide,
    run_investigator_compact_node,
    run_investigator_complete_node,
    run_investigator_decide_node,
    run_investigator_prepare_node,
    run_investigator_tool_node,
)
from app.agents.state import AnalysisState
from app.context.runtime import AnalysisRuntimeContext
from app.evaluation.agent.fixtures import build_fixture_runtime
from app.evaluation.agent.recorder import (
    RecordedToolEvent,
    RecordingAgentToolRegistry,
    ScriptedEvaluationRouter,
    ScriptedRequestRecord,
)
from app.evaluation.agent.schemas import AgentEvalCase
from app.security.redaction import redact_secrets


@dataclass(frozen=True, slots=True)
class ScriptedTrialResult:
    """Serializable result envelope for one isolated evaluator trial."""

    final_state: dict[str, Any]
    interrupted_state: dict[str, Any] | None
    tool_events: tuple[RecordedToolEvent, ...]
    model_requests: tuple[ScriptedRequestRecord, ...]
    model_decisions_consumed: int
    resumed: bool


@dataclass(frozen=True, slots=True)
class LiveTrialResult(ScriptedTrialResult):
    """One isolated real-provider trial; failures remain explicit and bounded."""

    error: str | None = None
    live_provider_used: bool = False


def build_investigator_eval_graph(*, checkpointer: Any, interrupt_after_tool: bool = False) -> Any:
    """Compile only the real investigator nodes for a deterministic trial.

    This is an evaluator harness, not a second investigator implementation: all
    node functions and routing predicates are imported from production.
    """

    builder = StateGraph(AnalysisState, context_schema=AnalysisRuntimeContext)
    builder.add_node("investigator_prepare", run_investigator_prepare_node)
    builder.add_node("investigator_decide", run_investigator_decide_node)
    builder.add_node("investigator_tool", run_investigator_tool_node)
    builder.add_node("investigator_compact", run_investigator_compact_node)
    builder.add_node("investigator_complete", run_investigator_complete_node)
    builder.add_edge(START, "investigator_prepare")
    builder.add_edge("investigator_prepare", "investigator_decide")
    builder.add_conditional_edges(
        "investigator_decide",
        route_after_investigator_decide,
        {"tool": "investigator_tool", "complete": "investigator_complete"},
    )
    builder.add_edge("investigator_tool", "investigator_compact")
    builder.add_conditional_edges(
        "investigator_compact",
        route_after_investigator_compact,
        {"decide": "investigator_decide", "complete": "investigator_complete"},
    )
    builder.add_edge("investigator_complete", END)
    return builder.compile(
        checkpointer=checkpointer,
        interrupt_after=["investigator_tool"] if interrupt_after_tool else None,
    )


async def run_scripted_trial(
    case: AgentEvalCase,
    *,
    interrupt_after_tool: bool = False,
) -> ScriptedTrialResult:
    """Run a case through production investigator nodes with no provider call."""

    with build_fixture_runtime(case) as fixture:
        registry = RecordingAgentToolRegistry(fixture.registry)
        router = ScriptedEvaluationRouter(case.scripted_decisions)
        context = AnalysisRuntimeContext(scan_runtime=object(), agent_tools=registry)  # type: ignore[arg-type]
        checkpointer = InMemorySaver()
        app = build_investigator_eval_graph(
            checkpointer=checkpointer,
            interrupt_after_tool=interrupt_after_tool,
        )
        config = {
            "configurable": {"thread_id": f"agent-eval-{case.case_id}"},
            "recursion_limit": 64,
        }
        with patch("app.agents.investigator.get_llm_router", return_value=router):
            first = await app.ainvoke(fixture.initial_state, config=config, context=context)
            interrupted_state = dict(first) if interrupt_after_tool else None
            resumed = False
            final_state = first
            if interrupt_after_tool:
                checkpoint = await app.aget_state(config)
                if checkpoint.next:
                    resumed = True
                    final_state = await app.ainvoke(None, config=config, context=context)
        return ScriptedTrialResult(
            final_state=dict(final_state),
            interrupted_state=interrupted_state,
            tool_events=registry.events,
            model_requests=tuple(router.requests),
            model_decisions_consumed=router.consumed,
            resumed=resumed,
        )


async def run_live_trial(case: AgentEvalCase) -> LiveTrialResult:
    """Run one fresh fixture/checkpoint through the production router.

    This is never called by the default CI command.  Provider failures are
    returned as a bounded status rather than converted into a passing result.
    """

    with build_fixture_runtime(case) as fixture:
        registry = RecordingAgentToolRegistry(fixture.registry)
        context = AnalysisRuntimeContext(scan_runtime=object(), agent_tools=registry)  # type: ignore[arg-type]
        app = build_investigator_eval_graph(checkpointer=InMemorySaver())
        config = {
            "configurable": {"thread_id": f"agent-live-eval-{case.case_id}"},
            "recursion_limit": 64,
        }
        final_state: dict[str, Any] = {}
        error: str | None = None
        try:
            final_state = dict(await app.ainvoke(fixture.initial_state, config=config, context=context))
        except Exception as exc:
            error = redact_secrets(str(exc))[:512] or type(exc).__name__
            final_state = dict(fixture.initial_state)
        model_executions = final_state.get("model_executions") or []
        live_provider_used = any(
            str(getattr(item, "provider", None) or (item.get("provider") if isinstance(item, dict) else "")) not in {"", "evaluation", "None"}
            for item in model_executions
        )
        return LiveTrialResult(
            final_state=final_state,
            interrupted_state=None,
            tool_events=registry.events,
            model_requests=(),
            model_decisions_consumed=len(model_executions),
            resumed=False,
            error=error,
            live_provider_used=live_provider_used,
        )


__all__ = ["LiveTrialResult", "ScriptedTrialResult", "build_investigator_eval_graph", "run_live_trial", "run_scripted_trial"]
