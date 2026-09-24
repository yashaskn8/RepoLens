"""First-decision tool-selection probe using the production investigator nodes."""

from __future__ import annotations

import hashlib
from typing import Any, Sequence
from uuid import uuid4

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from app.agent_runtime.policy import InvestigatorPolicyViolation, authorize_decision, permitted_tool_names
from app.agent_runtime.schemas import InvestigatorAction, InvestigatorRunState
from app.agent_tools.registry import AgentToolRegistry
from app.agents.investigator import run_investigator_decide_node, run_investigator_prepare_node
from app.agents.state import AnalysisState
from app.context.runtime import AnalysisRuntimeContext
from app.evaluation.agent.fixtures import build_fixture_runtime
from app.evaluation.agent.loader import load_agent_dataset
from app.evaluation.agent.recorder import ScriptedEvaluationRouter
from app.evaluation.agent.schemas import AgentEvalCase, ScriptedDecision
from app.evaluation.context_tool.contracts import (
    ToolSelectionGrade,
    ToolSelectionProbe,
)
from app.evaluation.context_tool.overlay import evaluation_context_tool_overlay
from app.evaluation.system.schemas import SystemEvalMode
from app.llm.economy import WorkflowCloudBudget, bind_workflow_cloud_budget, reset_workflow_cloud_budget
from app.llm.evaluation_route import evaluation_model_route
from app.llm.router import get_llm_router
from app.llm.types import LLMProvider


MAX_PROBE_CASES = 16


def _decision_graph() -> Any:
    """A short evaluation graph that ends after the real first decision node."""
    builder = StateGraph(AnalysisState, context_schema=AnalysisRuntimeContext)
    builder.add_node("investigator_prepare", run_investigator_prepare_node)
    builder.add_node("investigator_decide", run_investigator_decide_node)
    builder.add_edge(START, "investigator_prepare")
    builder.add_edge("investigator_prepare", "investigator_decide")
    builder.add_edge("investigator_decide", END)
    return builder.compile(checkpointer=InMemorySaver())


def _selection_case_label(case: AgentEvalCase) -> tuple[set[str], bool, bool]:
    """Return only evaluator-authored first-action labels; never infer from model behavior."""
    if case.annotation.expected_abstention:
        return set(), True, True
    if case.scripted_decisions:
        first = case.scripted_decisions[0]
        if first.action != InvestigatorAction.TOOL_CALL:
            return set(), True, True
        return {first.tool_name or ""}, True, False
    if case.annotation.required_tools_any:
        return set(case.annotation.required_tools_any), True, False
    if case.annotation.required_tools_all:
        return {case.annotation.required_tools_all[0]}, True, False
    return set(), False, False


def _grade_probe(
    case: AgentEvalCase,
    *,
    decision: Any,
    registry: AgentToolRegistry,
    visible_tools: set[str],
    model_execution: Any = None,
) -> ToolSelectionProbe:
    if decision is None:
        return ToolSelectionProbe(case_id=case.case_id, grade=ToolSelectionGrade.INVALID_OUTPUT)
    action = decision.action.value
    name = decision.tool_name
    arguments_digest = hashlib.sha256(
        __import__("json").dumps(
            decision.arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest() if action == InvestigatorAction.TOOL_CALL.value else None
    permitted = set(permitted_tool_names(case.category))
    is_forbidden = bool(name and name not in permitted)
    hidden = bool(name and name in permitted and name not in visible_tools)
    valid_arguments: bool | None = None
    if action == InvestigatorAction.TOOL_CALL.value and name:
        try:
            authorize_decision(decision, category=case.category, registry=registry)
            valid_arguments = registry.validate_arguments(name, decision.arguments) is None
        except InvestigatorPolicyViolation:
            valid_arguments = False
    expected, labeled, no_tool_expected = _selection_case_label(case)
    if is_forbidden:
        grade = ToolSelectionGrade.FORBIDDEN_TOOL_REQUEST
    elif hidden:
        grade = ToolSelectionGrade.HIDDEN_TOOL_REQUEST
    elif action == InvestigatorAction.TOOL_CALL.value and valid_arguments is False:
        grade = ToolSelectionGrade.INVALID_ARGUMENTS
    elif not labeled:
        grade = ToolSelectionGrade.UNLABELED
    elif action == InvestigatorAction.TOOL_CALL.value:
        if no_tool_expected:
            grade = ToolSelectionGrade.UNNECESSARY_TOOL
        elif name in expected:
            grade = ToolSelectionGrade.EXPECTED_TOOL if len(expected) == 1 else ToolSelectionGrade.ACCEPTABLE_TOOL
        else:
            grade = ToolSelectionGrade.WRONG_TOOL
    elif no_tool_expected:
        grade = ToolSelectionGrade.NO_TOOL_EXPECTED
    else:
        grade = ToolSelectionGrade.NO_TOOL_WHEN_REQUIRED
    def metadata_value(name: str) -> Any:
        if isinstance(model_execution, dict):
            return model_execution.get(name)
        return getattr(model_execution, name, None)

    extra = metadata_value("extra_metadata") or {}
    if not isinstance(extra, dict):
        extra = {}

    def nonnegative_int(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    def optional_float(value: Any) -> float | None:
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None

    return ToolSelectionProbe(
        case_id=case.case_id,
        selected_action=action,
        selected_tool=name,
        argument_digest=arguments_digest,
        arguments_valid=valid_arguments,
        hidden_tool_request=hidden,
        grade=grade,
        measured_input_tokens=nonnegative_int(metadata_value("prompt_tokens")),
        measured_output_tokens=nonnegative_int(metadata_value("completion_tokens")),
        measured_cost_usd=optional_float(extra.get("cost_usd")),
        retries=nonnegative_int(extra.get("retry_count")),
        fallbacks=nonnegative_int(extra.get("fallback_count")),
    )


async def run_tool_selection_micro_eval(
    *,
    mode: SystemEvalMode,
    overlay: Any = None,
    case_ids: Sequence[str] | None = None,
    provider: LLMProvider | str | None = None,
    model: str | None = None,
    allow_live: bool = False,
    allow_context_tool_experiments: bool = False,
    manifest_sink: Any = None,
) -> list[ToolSelectionProbe]:
    """Evaluate exactly the first production investigator decision, with no tool execution."""
    mode = SystemEvalMode(mode)
    if mode == SystemEvalMode.LIVE and not (
        allow_live and allow_context_tool_experiments and provider and model
    ):
        raise ValueError("live tool-selection probes require both experiment opt-ins and exact model identity")
    if mode == SystemEvalMode.SCRIPTED and (provider is not None or model is not None or allow_live):
        raise ValueError("scripted tool-selection probes do not accept model or live settings")
    dataset = load_agent_dataset()
    cases = list(dataset.cases)
    by_id = {case.case_id: case for case in cases}
    if case_ids is not None:
        if not case_ids or len(set(case_ids)) != len(case_ids) or not set(case_ids) <= set(by_id):
            raise ValueError("micro-eval case selection must use unique cases from the fixed public corpus")
        cases = [by_id[item] for item in sorted(case_ids)]
    else:
        cases = [case for case in cases if case.scripted_decisions or case.annotation.expected_abstention
                 or case.annotation.required_tools_any or case.annotation.required_tools_all]
        if mode == SystemEvalMode.SCRIPTED:
            cases = [case for case in cases if case.scripted_decisions or case.annotation.expected_abstention]
        cases = cases[:MAX_PROBE_CASES]
    if not cases or len(cases) > MAX_PROBE_CASES:
        raise ValueError("micro-eval case selection is empty or exceeds the fixed probe bound")

    results: list[ToolSelectionProbe] = []
    selected_provider = LLMProvider(provider) if provider is not None else None
    selected_model = str(model or "scripted-agent-eval")
    for case in cases:
        with build_fixture_runtime(case) as fixture:
            scripted_decisions = list(case.scripted_decisions)
            if mode == SystemEvalMode.SCRIPTED and not scripted_decisions and case.annotation.expected_abstention:
                scripted_decisions = [ScriptedDecision(
                    action=InvestigatorAction.ABSTAIN,
                    reason="Curated zero-key no-tool control.",
                )]
            router = ScriptedEvaluationRouter(scripted_decisions) if mode == SystemEvalMode.SCRIPTED else get_llm_router()
            context = AnalysisRuntimeContext(
                scan_runtime=object(),  # type: ignore[arg-type]
                agent_tools=fixture.registry,
                llm_router=router,
            )
            app = _decision_graph()
            config = {"configurable": {"thread_id": f"context-tool-probe-{case.case_id}-{uuid4().hex}"}, "recursion_limit": 8}
            manifests = []

            def collect_manifest(item: Any) -> None:
                manifests.append(item)
                if manifest_sink is not None:
                    manifest_sink(item)

            async def invoke() -> dict[str, Any]:
                with evaluation_context_tool_overlay(
                    overlay,
                    case_id=case.case_id,
                    trial_number=1,
                    evaluation_stage="MICRO_EVAL",
                    manifest_sink=collect_manifest,
                ):
                    return dict(await app.ainvoke(fixture.initial_state, config=config, context=context))

            if mode == SystemEvalMode.LIVE:
                assert selected_provider is not None and model
                with evaluation_model_route(selected_provider, selected_model):
                    budget = WorkflowCloudBudget.from_settings()
                    budget_token = bind_workflow_cloud_budget(budget)
                    try:
                        state = await invoke()
                    finally:
                        reset_workflow_cloud_budget(budget_token)
            else:
                state = await invoke()
            run = InvestigatorRunState.model_validate(state.get("investigator") or {})
            decision = run.active.pending_decision if run.active is not None else None
            executions = state.get("model_executions") or []
            results.append(_grade_probe(
                case,
                decision=decision,
                registry=fixture.registry,
                visible_tools=set(manifests[-1].visible_tool_names) if manifests else set(),
                model_execution=executions[-1] if executions else None,
            ))
    return results


__all__ = ["MAX_PROBE_CASES", "run_tool_selection_micro_eval"]
