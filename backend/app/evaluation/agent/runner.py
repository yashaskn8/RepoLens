"""Isolated evaluator runner that drives the production investigator nodes."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any
from uuid import uuid4

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
    trajectory_steps: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class LiveTrialResult(ScriptedTrialResult):
    """One isolated real-provider trial; failures remain explicit and bounded."""

    error: str | None = None
    live_provider_used: bool = False
    duration_ms: float | None = None


async def _checkpoint_trajectory(app: Any, config: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Read bounded checkpointed investigator decisions without source payloads."""
    latest: dict[tuple[str, int], dict[str, Any]] = {}
    async for snapshot in app.aget_state_history(config, limit=128):
        values = getattr(snapshot, "values", None)
        run = values.get("investigator") if isinstance(values, dict) else None
        active = run.get("active") if isinstance(run, dict) else None
        if not isinstance(active, dict):
            continue
        finding = active.get("finding")
        finding_id = str(finding.get("finding_id", "unknown")) if isinstance(finding, dict) else "unknown"
        steps = active.get("trajectory")
        if not isinstance(steps, list):
            continue
        for raw in steps:
            if not isinstance(raw, dict):
                continue
            number = int(raw.get("step_number", 0) or 0)
            if number > 0:
                latest.setdefault((finding_id, number), dict(raw))
    return tuple(
        latest[key]
        for key in sorted(latest, key=lambda item: (item[0], item[1]))
    )


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
        context = AnalysisRuntimeContext(
            scan_runtime=object(),  # type: ignore[arg-type]
            agent_tools=registry,  # type: ignore[arg-type]
            llm_router=router,  # type: ignore[arg-type]
        )
        checkpointer = InMemorySaver()
        app = build_investigator_eval_graph(
            checkpointer=checkpointer,
            interrupt_after_tool=interrupt_after_tool,
        )
        config = {
            "configurable": {"thread_id": f"agent-eval-{case.case_id}-{uuid4().hex}"},
            "recursion_limit": 64,
        }
        first = await app.ainvoke(fixture.initial_state, config=config, context=context)
        interrupted_state = dict(first) if interrupt_after_tool else None
        resumed = False
        final_state = first
        if interrupt_after_tool:
            checkpoint = await app.aget_state(config)
            if checkpoint.next:
                resumed = True
                final_state = await app.ainvoke(None, config=config, context=context)
        trajectory_steps = await _checkpoint_trajectory(app, config)
        return ScriptedTrialResult(
            final_state=dict(final_state),
            interrupted_state=interrupted_state,
            tool_events=registry.events,
            model_requests=tuple(router.requests),
            model_decisions_consumed=router.consumed,
            resumed=resumed,
            trajectory_steps=trajectory_steps,
        )


async def run_live_trial(
    case: AgentEvalCase,
    *,
    provider: Any = None,
    model: str | None = None,
    router: Any = None,
    interrupt_after_tool: bool = False,
) -> LiveTrialResult:
    """Run one fresh fixture/checkpoint through the production router.

    This is never called by the default CI command.  Provider failures are
    returned as a bounded status rather than converted into a passing result.
    """

    started = time.perf_counter()
    with build_fixture_runtime(case) as fixture:
        registry = RecordingAgentToolRegistry(fixture.registry)
        context = AnalysisRuntimeContext(
            scan_runtime=object(),  # type: ignore[arg-type]
            agent_tools=registry,  # type: ignore[arg-type]
            llm_router=router,
        )
        checkpointer = InMemorySaver()
        app = build_investigator_eval_graph(
            checkpointer=checkpointer,
            interrupt_after_tool=interrupt_after_tool,
        )
        config = {
            "configurable": {"thread_id": f"agent-live-eval-{case.case_id}-{uuid4().hex}"},
            "recursion_limit": 64,
        }
        final_state: dict[str, Any] = {}
        error: str | None = None
        resumed = False
        try:
            if provider is None and model is None:
                final_state = dict(await app.ainvoke(fixture.initial_state, config=config, context=context))
            elif provider is None or not model:
                raise ValueError("Evaluation route requires both provider and model.")
            else:
                from app.llm.evaluation_route import evaluation_model_route

                with evaluation_model_route(provider, model):
                    final_state = dict(await app.ainvoke(fixture.initial_state, config=config, context=context))
                    if interrupt_after_tool:
                        checkpoint = await app.aget_state(config)
                        if checkpoint.next:
                            resumed = True
                            final_state = dict(await app.ainvoke(None, config=config, context=context))
        except Exception as exc:
            error = f"{type(exc).__name__}: {redact_secrets(str(exc))[:480]}"[:512]
            final_state = dict(fixture.initial_state)
        trajectory_steps = await _checkpoint_trajectory(app, config)
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
            resumed=resumed,
            trajectory_steps=trajectory_steps,
            error=error,
            live_provider_used=live_provider_used,
            duration_ms=max(0.0, (time.perf_counter() - started) * 1000.0),
        )


__all__ = ["LiveTrialResult", "ScriptedTrialResult", "build_investigator_eval_graph", "run_live_trial", "run_scripted_trial"]
