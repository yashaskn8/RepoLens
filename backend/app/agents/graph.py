"""Durable LangGraph multi-agent workflow construction, SQLite checkpointer integration, and execution."""

import asyncio
import hashlib
import inspect
import json
import logging
import time
from typing import Any, Dict, List, Optional
from langgraph.graph import END, START, StateGraph

from app.agents.architecture import run_architecture_agent
from app.agents.bug import run_bug_agent
from app.agents.checkpointer import get_sqlite_checkpointer
from app.agents.integration import run_integration_agent
from app.agents.investigator import (
    route_after_investigator_compact,
    route_after_investigator_complete,
    route_after_investigator_decide,
    run_investigator_compact_node,
    run_investigator_complete_node,
    run_investigator_decide_node,
    run_investigator_prepare_node,
    run_investigator_tool_node,
)
from app.agents.mapper import run_repository_mapper
from app.agents.mcp_enrichment import run_mcp_enrichment_node
from app.agents.revision import run_revision_agent
from app.agents.security import run_security_agent
from app.agents.state import AnalysisState
from app.agents.verifier import run_verifier_agent
from app.agents.helpers import safe_to_uuid
from app.analysis.store import EvidenceStore
from app.agent_tools import AgentToolContext, RepositorySnapshot, create_agent_tool_registry
from app.agent_runtime.schemas import (
    MAX_INVESTIGATOR_STEPS,
    MAX_INVESTIGATOR_TARGETS,
    MAX_INVESTIGATOR_TOOL_CALLS,
)
from app.core.config import get_settings
from app.llm.admission import build_admission_map

from app.context.engine import ContextEngine
from app.context.runtime import (
    AnalysisRuntimeContext,
    ScanIntelligenceRuntime,
    register_scan_runtime,
    unregister_scan_runtime,
)
from app.graph.repository_graph import RepositoryGraph
from app.llm.economy import (
    WorkflowCloudBudget,
    bind_workflow_cloud_budget,
    current_workflow_cloud_budget,
    reset_workflow_cloud_budget,
)
from app.mcp.executor import MCPToolExecutor
from app.mcp.runtime_client import MCPRuntimeClient
from app.mcp.server import MCPRepositoryServer
from app.security.redaction import redact_secrets
from app.specialist_candidates import (
    build_architecture_candidates,
    build_bug_candidates,
    build_security_flow_candidates,
)

logger = logging.getLogger(__name__)

ANALYSIS_RECURSION_LIMIT = 10 + MAX_INVESTIGATOR_TARGETS * (
    2 + MAX_INVESTIGATOR_STEPS + 2 * MAX_INVESTIGATOR_TOOL_CALLS
)
MAX_WORKFLOW_TRACE_EVENTS = 128
_INVESTIGATOR_GRAPH_NODES = frozenset({
    "investigator_prepare",
    "investigator_decide",
    "investigator_tool",
    "investigator_compact",
    "investigator_complete",
})


class _WorkflowNodeExecutionError(RuntimeError):
    """Sanitized node failure carrying content-free attribution for the caller."""

    def __init__(self, node_name: str, trace_event: Dict[str, Any]):
        self.node_name = node_name
        self.trace_event = trace_event
        super().__init__(f"Workflow node {node_name} failed (NODE_ERROR)")


def run_finalize_node(state: AnalysisState) -> Dict[str, Any]:
    """Deterministic finalization for verified repository analysis."""
    return {
        "status": "COMPLETED",
        "completed_nodes": ["finalize"],
    }


def run_finalize_uncertain_node(state: AnalysisState) -> Dict[str, Any]:
    """Deterministic finalization for uncertain or revision-exhausted repository analysis."""
    new_errors: List[str] = []
    existing_errors = state.get("errors", [])
    if not any("uncertain" in err.lower() for err in existing_errors):
        new_errors.append("Scan completed with unconfirmed findings or exhausted revision budget.")
    return {
        "status": "COMPLETED_UNCERTAIN",
        "completed_nodes": ["finalize_uncertain"],
        "errors": new_errors,
    }


def route_after_verifier(state: AnalysisState) -> str:
    """Pure conditional routing function evaluating verification outcome and revision count."""
    decision = state.get("verification_decision")
    revision_count = state.get("revision_count", 0)

    if decision == "verified":
        return "finalize"
    elif decision == "needs_revision" and revision_count < 1:
        return "investigate" if state.get("agent_investigator_enabled", False) else "revise"
    return "finalize_uncertain"


def _checkpoint_requires_investigator(checkpoint_state: Any) -> bool:
    """Return whether a resumable checkpoint needs investigator services.

    The persisted workflow mode is authoritative for existing executions.  A
    node-level check is retained for older checkpoints that predate the mode
    field, or for a partially written checkpoint already inside the durable
    investigator loop.
    """

    values = getattr(checkpoint_state, "values", None)
    if not isinstance(values, dict) or not values:
        return False
    if bool(values.get("agent_investigator_enabled", False)):
        return True
    next_nodes = getattr(checkpoint_state, "next", ()) or ()
    return any(str(node) in _INVESTIGATOR_GRAPH_NODES for node in next_nodes)


async def _budgeted_node(fn: Any, state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    """Attach the current economy snapshot to every durable checkpoint write."""
    from app.observability import span

    function_name = getattr(fn, "__name__", "workflow_node")
    node_name = {
        "run_repository_mapper": "mapper",
        "run_architecture_agent": "architecture",
        "run_integration_agent": "integration",
        "run_security_agent": "security",
        "run_bug_agent": "bug",
        "run_verifier_agent": "verifier",
        "run_mcp_enrichment_node": "mcp_enrich",
        "run_investigator_prepare_node": "investigator_prepare",
        "run_investigator_decide_node": "investigator_decide",
        "run_investigator_tool_node": "investigator_tool",
        "run_investigator_compact_node": "investigator_compact",
        "run_investigator_complete_node": "investigator_complete",
        "run_revision_agent": "revise",
        "run_finalize_node": "finalize",
        "run_finalize_uncertain_node": "finalize_uncertain",
    }.get(function_name, function_name.removeprefix("run_").removesuffix("_agent"))
    operation = "invoke_agent" if node_name in {"architecture", "integration", "security", "bug", "investigator_decide"} else "workflow_node"
    span_attributes = {
        "repolens.workflow.operation": operation,
        "repolens.workflow.node": node_name,
        "repolens.workflow.step": len(state.get("completed_nodes", [])),
    }
    if operation != "workflow_node":
        span_attributes["gen_ai.operation.name"] = operation
    started = time.perf_counter()
    with span(
        f"workflow.{node_name}",
        attributes=span_attributes,
    ) as node_span:
        try:
            if len(inspect.signature(fn).parameters) > 1:
                result = fn(state, runtime)
            else:
                result = fn(state)
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            node_span.set_attribute("repolens.workflow.failure_code", "NODE_ERROR")
            trace_event = _workflow_node_event(
                node_name,
                state,
                {"errors": ["NODE_ERROR"]},
                time.perf_counter() - started,
            )
            raise _WorkflowNodeExecutionError(node_name, trace_event) from None
        node_span.set_attribute("repolens.workflow.result_keys", len(result or {}))
    result = dict(result or {})
    budget = current_workflow_cloud_budget()
    if budget is not None:
        result["ai_cloud_budget"] = budget.snapshot().as_dict()
    trace_event = _workflow_node_event(node_name, state, result, time.perf_counter() - started)
    if len(state.get("workflow_trace", [])) < MAX_WORKFLOW_TRACE_EVENTS:
        result["workflow_trace"] = [trace_event]
    return result


def _finding_ref(item: Any) -> Dict[str, Any] | None:
    """Extract only stable, non-source finding provenance for graph telemetry."""
    if isinstance(item, dict):
        get = item.get
    else:
        get = lambda key, default=None: getattr(item, key, default)
    finding_id = get("id") or get("finding_id")
    if finding_id is None:
        return None
    evidences = get("evidences", []) or []
    safe_evidence = []
    for evidence in evidences[:8]:
        if isinstance(evidence, dict):
            ev_get = evidence.get
        else:
            ev_get = lambda key, default=None: getattr(evidence, key, default)
        safe_evidence.append({
            "file_path": str(ev_get("file_path", ""))[:512],
            "start_line": ev_get("start_line"),
            "end_line": ev_get("end_line"),
        })
    return {
        "finding_id": str(finding_id)[:128],
        "rule_id": str(get("rule_id") or get("detector_id") or "")[:256],
        "category": str(get("category") or "")[:128],
        "verdict": str(get("verification_verdict") or "")[:32],
        "evidences": safe_evidence,
    }


def _safe_event_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _workflow_node_event(node: str, before: AnalysisState, output: Dict[str, Any], duration: float) -> Dict[str, Any]:
    """Return bounded, content-free per-node provenance safe for checkpoints/reports."""
    def ids(key: str) -> list[str]:
        values = output.get(key, [])
        return [str(getattr(item, "id", item.get("finding_id") if isinstance(item, dict) else ""))[:128]
                for item in values[:64] if getattr(item, "id", None) is not None or isinstance(item, dict)]

    refs: list[Dict[str, Any]] = []
    for key in ("candidate_findings", "revision_candidates", "verified_findings"):
        for item in output.get(key, [])[:64]:
            ref = _finding_ref(item)
            if ref is not None:
                refs.append(ref)
    model_executions = output.get("model_executions", [])
    model_execution_count = len(model_executions) if isinstance(model_executions, list) else 0
    # Preserve verdict-transition provenance without serializing rejected text/reasons.
    rejected_ids = []
    for item in output.get("rejected_findings", [])[:64]:
        if not isinstance(item, dict) or item.get("finding_id") is None:
            continue
        verdict = item.get("verdict")
        verdict_value = str(getattr(verdict, "value", verdict or "")).upper()
        if verdict_value == "REJECTED":
            rejected_ids.append(str(item["finding_id"])[:128])
    input_projection = {
        "candidate_ids": [str(getattr(item, "id", "")) for item in before.get("candidate_findings", [])[:64]],
        "verified_ids": [str(getattr(item, "id", "")) for item in before.get("verified_findings", [])[:64]],
        "revision_target_ids": list(before.get("revision_target_ids", []))[:64],
        "revision_count": int(before.get("revision_count", 0) or 0),
        "verification_decision": before.get("verification_decision"),
        "file_count": int((before.get("manifest_summary") or {}).get("total_files", 0) or 0),
        "trace_count": len(before.get("workflow_trace", [])),
    }
    output_projection = {
        "keys": sorted(str(key) for key in output.keys()),
        "candidate_ids": ids("candidate_findings"),
        "verified_ids": ids("verified_findings"),
        "revision_ids": ids("revision_candidates"),
        "rejected_ids": rejected_ids,
        "verification_decision": output.get("verification_decision"),
        "status": output.get("status"),
        "model_execution_count": model_execution_count,
        "finding_refs": refs[:64],
    }
    models = []
    for item in model_executions[:16] if isinstance(model_executions, list) else []:
        provider = getattr(item, "provider", None)
        model = getattr(item, "model_name", None) or getattr(item, "model", None)
        if provider and model:
            models.append(f"{getattr(provider, 'value', provider)}:{model}"[:320])
    tool_names: list[str] = []
    tool_call_digests: list[str] = []
    tool_execution_count = 0
    mcp_events = output.get("mcp_tool_events", [])
    for item in mcp_events[:16] if isinstance(mcp_events, list) else []:
        if isinstance(item, dict) and item.get("tool_name"):
            tool_names.append(str(item["tool_name"])[:128])
            tool_execution_count += 1
    investigator = output.get("investigator", {})
    before_investigator = before.get("investigator", {})
    if node == "investigator_tool" and isinstance(investigator, dict):
        active = investigator.get("active", {})
        before_active = before_investigator.get("active", {}) if isinstance(before_investigator, dict) else {}
        trajectory = active.get("trajectory", []) if isinstance(active, dict) else []
        if trajectory and isinstance(trajectory[-1], dict):
            step = trajectory[-1]
            if step.get("tool_name"):
                tool_names.append(str(step["tool_name"])[:128])
            if step.get("argument_digest"):
                tool_call_digests.append(str(step["argument_digest"])[:64])
        budget = active.get("budget", {}) if isinstance(active, dict) else {}
        prior_budget = before_active.get("budget", {}) if isinstance(before_active, dict) else {}
        try:
            tool_execution_count += max(
                0,
                int(budget.get("tool_calls", 0) or 0) - int(prior_budget.get("tool_calls", 0) or 0),
            )
        except (TypeError, ValueError):
            pass
    errors = output.get("errors", [])
    failure_codes = []
    for value in errors[:16] if isinstance(errors, list) else []:
        text = str(value).lower()
        failure_codes.append(
            "MODEL_PROVIDER_FAILURE" if any(word in text for word in ("provider", "api key", "timeout"))
            else "BUDGET_EXHAUSTION" if "budget" in text or "quota" in text
            else "NODE_ERROR"
        )
    if node == "investigator_tool" and isinstance(investigator, dict):
        active = investigator.get("active", {})
        trajectory = active.get("trajectory", []) if isinstance(active, dict) else []
        if trajectory and isinstance(trajectory[-1], dict):
            status = str(trajectory[-1].get("status", ""))
            if status in {"TOOL_NOT_PERMITTED", "TOOL_UNKNOWN", "TOOL_NOT_READ_ONLY"}:
                failure_codes.append("UNAUTHORIZED_TOOL_REQUEST_BLOCKED")
            elif status == "TOOL_ARGUMENT_INVALID":
                failure_codes.append("TOOL_ARGUMENT_INVALID")
            elif status == "TOOL_BUDGET_EXCEEDED":
                failure_codes.append("TOOL_BUDGET_EXHAUSTION")
            elif status in {"TOOL_TIMEOUT", "TOOL_FAILURE", "INTERNAL_ERROR"}:
                failure_codes.append("TOOL_FAILURE")
            elif status == "STUCK_LOOP":
                failure_codes.append("STAGNATION")
    output_projection["tool_names"] = list(dict.fromkeys(tool_names))[:16]
    output_projection["tool_call_digests"] = list(dict.fromkeys(tool_call_digests))[:16]
    output_projection["tool_execution_count"] = min(tool_execution_count, 16)
    cloud_budget = output.get("ai_cloud_budget", before.get("ai_cloud_budget", {}))
    evidence_count = sum(len(item.get("evidences", [])) for item in refs)
    return {
        "sequence": min(MAX_WORKFLOW_TRACE_EVENTS, len(before.get("workflow_trace", [])) + 1),
        "node": node[:64],
        "superstep": min(256, len(before.get("completed_nodes", [])) + 1),
        "status": "COMPLETED_WITH_ERRORS" if failure_codes else "COMPLETED",
        "duration_ms": round(max(0.0, duration) * 1000.0, 3),
        "input_digest": _safe_event_digest(input_projection),
        "output_digest": _safe_event_digest(output_projection),
        "candidate_ids": ids("candidate_findings"),
        "verified_ids": ids("verified_findings"),
        "rejected_ids": rejected_ids,
        "finding_refs": refs[:64],
        "model_identities": list(dict.fromkeys(models))[:16],
        "model_execution_count": model_execution_count,
        "tool_names": list(dict.fromkeys(tool_names))[:16],
        "tool_call_digests": list(dict.fromkeys(tool_call_digests))[:16],
        "tool_execution_count": min(tool_execution_count, 16),
        "evidence_count": evidence_count,
        "budget_exhausted": bool((cloud_budget or {}).get("exhausted", False)),
        "failure_codes": list(dict.fromkeys(failure_codes))[:16],
    }


async def _mapper_node(state: AnalysisState) -> Dict[str, Any]:
    return await _budgeted_node(run_repository_mapper, state)


async def _architecture_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_architecture_agent, state, runtime)


async def _integration_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_integration_agent, state, runtime)


async def _security_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_security_agent, state, runtime)


async def _bug_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_bug_agent, state, runtime)


async def _verifier_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_verifier_agent, state, runtime)


async def _mcp_enrich_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_mcp_enrichment_node, state, runtime)


async def _investigator_prepare_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_investigator_prepare_node, state, runtime)


async def _investigator_decide_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_investigator_decide_node, state, runtime)


async def _investigator_tool_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_investigator_tool_node, state, runtime)


async def _investigator_compact_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_investigator_compact_node, state, runtime)


async def _investigator_complete_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_investigator_complete_node, state, runtime)


async def _revise_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_revision_agent, state, runtime)


def build_analysis_graph(
    checkpointer: Optional[Any] = None,
    *,
    interrupt_after: Optional[List[str]] = None,
) -> Any:
    """Construct and compile the parallel specialist LangGraph analysis workflow with optional checkpointer."""
    workflow = StateGraph(AnalysisState, context_schema=AnalysisRuntimeContext)

    # 1. Register specialist and lifecycle nodes
    workflow.add_node("mapper", _mapper_node)
    workflow.add_node("architecture", _architecture_node)
    workflow.add_node("integration", _integration_node)
    workflow.add_node("security", _security_node)
    workflow.add_node("bug", _bug_node)
    workflow.add_node("verifier", _verifier_node)
    workflow.add_node("mcp_enrich", _mcp_enrich_node)
    workflow.add_node("investigator_prepare", _investigator_prepare_node)
    workflow.add_node("investigator_decide", _investigator_decide_node)
    workflow.add_node("investigator_tool", _investigator_tool_node)
    workflow.add_node("investigator_compact", _investigator_compact_node)
    workflow.add_node("investigator_complete", _investigator_complete_node)
    workflow.add_node("revise", _revise_node)
    workflow.add_node("finalize", _finalize_node)
    workflow.add_node("finalize_uncertain", _finalize_uncertain_node)

    # 2. Wire execution flow: START -> mapper -> parallel specialists -> verifier
    workflow.add_edge(START, "mapper")
    workflow.add_edge("mapper", "architecture")
    workflow.add_edge("mapper", "integration")
    workflow.add_edge("mapper", "security")
    workflow.add_edge("mapper", "bug")

    workflow.add_edge("architecture", "verifier")
    workflow.add_edge("integration", "verifier")
    workflow.add_edge("security", "verifier")
    workflow.add_edge("bug", "verifier")

    # 3. Conditional routing from verifier (route key "revise" enters bounded mcp_enrich)
    workflow.add_conditional_edges(
        "verifier",
        route_after_verifier,
        {
            "finalize": "finalize",
            "revise": "mcp_enrich",
            "investigate": "investigator_prepare",
            "finalize_uncertain": "finalize_uncertain",
        },
    )

    # 4. Loop mcp_enrich -> revise -> verifier (bounded to at most 1 attempt by route_after_verifier and revision_count)
    workflow.add_edge("mcp_enrich", "revise")
    workflow.add_edge("investigator_prepare", "investigator_decide")
    workflow.add_conditional_edges(
        "investigator_decide",
        route_after_investigator_decide,
        {"tool": "investigator_tool", "complete": "investigator_complete"},
    )
    workflow.add_edge("investigator_tool", "investigator_compact")
    workflow.add_conditional_edges(
        "investigator_compact",
        route_after_investigator_compact,
        {"decide": "investigator_decide", "complete": "investigator_complete"},
    )
    workflow.add_conditional_edges(
        "investigator_complete",
        route_after_investigator_complete,
        {
            "prepare": "investigator_prepare",
            "revise": "revise",
            "uncertain": "finalize_uncertain",
        },
    )
    workflow.add_edge("revise", "verifier")

    # 5. Terminal edges
    workflow.add_edge("finalize", END)
    workflow.add_edge("finalize_uncertain", END)

    return workflow.compile(checkpointer=checkpointer, interrupt_after=interrupt_after)


async def _finalize_node(state: AnalysisState) -> Dict[str, Any]:
    return await _budgeted_node(run_finalize_node, state)


async def _finalize_uncertain_node(state: AnalysisState) -> Dict[str, Any]:
    return await _budgeted_node(run_finalize_uncertain_node, state)


async def run_analysis_workflow(
    evidence_store: EvidenceStore,
    scan_id: str,
    repo_dir: str,
    checkpointer: Optional[Any] = None,
    resume_if_exists: bool = True,
    context_engine: Optional[ContextEngine] = None,
    repository_graph: Optional[RepositoryGraph] = None,
    llm_router: Any = None,
    interrupt_after: Optional[List[str]] = None,
    scan_runtime: Optional[ScanIntelligenceRuntime] = None,
) -> AnalysisState:
    """Execute or resume the durable LangGraph multi-agent analysis workflow using scan_id as thread identifier.
    
    Guarantees:
    - Automatically builds and registers canonical ScanIntelligenceRuntime and passes AnalysisRuntimeContext.
    - Large code files, service objects, and complex class instances remain outside msgpack state.
    - Checkpoint saves serializable state after every super-step.
    - An interrupted scan resumes from the last completed node without re-executing finished agents.
    - Failed nodes or terminal failures capture sanitized errors without corrupting the checkpointer.
    """
    from app.observability import span_event

    config = {
        "configurable": {"thread_id": scan_id},
        # Worst case is four sequential targets, each with prepare/complete,
        # six decisions, and five tool+compaction pairs, plus the base graph.
        "recursion_limit": ANALYSIS_RECURSION_LIMIT,
    }
    app = build_analysis_graph(checkpointer=checkpointer, interrupt_after=interrupt_after)

    # Assemble and register ScanIntelligenceRuntime for this scan_id
    try:
        if scan_runtime is not None:
            if scan_runtime.evidence_store is not evidence_store:
                raise ValueError("injected scan runtime must use the active EvidenceStore")
            runtime = scan_runtime
            register_scan_runtime(scan_id, runtime)
        elif context_engine is not None:
            runtime = ScanIntelligenceRuntime(
                evidence_store=evidence_store,
                repository_graph=repository_graph or ContextEngine(evidence_store).repository_graph,
                chunks=[],
                vector_index=None,
                embedding_provider=None,
                retrieval_service=None,
                context_engine=context_engine,
                repo_dir=repo_dir,
            )
            register_scan_runtime(scan_id, runtime)
        else:
            runtime = await ScanIntelligenceRuntime.build(
                evidence_store=evidence_store,
                repo_dir=repo_dir,
            )
            register_scan_runtime(scan_id, runtime)
    except Exception as exc:
        safe_msg = redact_secrets(str(exc))[:2048]
        logger.warning("Notice during ScanIntelligenceRuntime setup for scan %s: %s", scan_id, safe_msg)
        runtime = ScanIntelligenceRuntime(
            evidence_store=evidence_store,
            repository_graph=repository_graph or ContextEngine(evidence_store).repository_graph,
            chunks=[],
            vector_index=None,
            embedding_provider=None,
            retrieval_service=None,
            context_engine=context_engine or ContextEngine(evidence_store),
            repo_dir=repo_dir,
        )
        register_scan_runtime(scan_id, runtime)

    # Inspect an existing checkpoint before constructing transient investigator
    # services.  New scans use the current rollout flag; resumed scans use the
    # checkpointed execution mode (or their next investigator node) instead.
    current_state = None
    if checkpointer is not None and resume_if_exists:
        try:
            current_state = await app.aget_state(config)
        except Exception as exc:
            safe_msg = redact_secrets(str(exc))[:2048]
            logger.warning("Failed to retrieve existing checkpoint state for %s: %s", scan_id, safe_msg)

    checkpoint_values = getattr(current_state, "values", None) if current_state is not None else None
    checkpoint_has_values = isinstance(checkpoint_values, dict) and bool(checkpoint_values)
    checkpoint_completed = checkpoint_has_values and not (getattr(current_state, "next", ()) or ())
    investigator_runtime_required = bool(get_settings().AGENT_INVESTIGATOR_ENABLED)
    if checkpoint_has_values:
        investigator_runtime_required = (
            False if checkpoint_completed else _checkpoint_requires_investigator(current_state)
        )

    # Lazily initialized MCP runtime client & executor (connection opened only if mcp_enrich executes)
    mcp_server = MCPRepositoryServer(
        evidence_store=evidence_store,
        repo_dir=repo_dir,
        repository_graph=runtime.repository_graph,
        context_engine=runtime.context_engine,
    )
    mcp_client = MCPRuntimeClient(repo_server=mcp_server)
    mcp_executor = MCPToolExecutor(client=mcp_client)

    agent_tools = None
    if investigator_runtime_required:
        try:
            snapshot_id = evidence_store.manifest.commit_sha or evidence_store.manifest.commit_hash
            tool_snapshot = RepositorySnapshot.create(
                snapshot_id=snapshot_id,
                repository_root=repo_dir,
                evidence_store=evidence_store,
                graph=runtime.repository_graph,
                chunks=runtime.chunks or None,
                component_versions={"agent_tools": "2.0.0"},
                capture_source_digests=True,
            )
            agent_tools = create_agent_tool_registry(AgentToolContext.from_snapshot(tool_snapshot))
        except Exception as exc:
            safe_msg = redact_secrets(str(exc))[:512]
            logger.warning("Evidence Investigator tools unavailable for scan %s: %s", scan_id, safe_msg)

    runtime_context = AnalysisRuntimeContext(
        scan_runtime=runtime,
        agent_tools=agent_tools,
        mcp_executor=mcp_executor,
        llm_router=llm_router,
    )
    cloud_budget = WorkflowCloudBudget.from_settings()
    persistent_index = getattr(evidence_store, "persistent_index", None)
    index_authority = None if persistent_index is None else {
        "snapshot_id": persistent_index.snapshot_id,
        "producer_digest": persistent_index.producer,
        "tenant_id": persistent_index.tenant_id,
        "repository_id": persistent_index.repository_id,
        "commit_sha": persistent_index.commit_sha,
    }

    async def invoke_with_cloud_budget(payload: Any) -> AnalysisState:
        from app.observability import span

        token = bind_workflow_cloud_budget(cloud_budget)
        try:
            with span(
                "workflow.invoke",
                attributes={
                    "gen_ai.operation.name": "invoke_workflow",
                    "repolens.workflow.scan_id": scan_id,
                    "repolens.workflow.resume": payload is None,
                    "repolens.workflow.recursion_limit": ANALYSIS_RECURSION_LIMIT,
                },
            ):
                result = await app.ainvoke(payload, config=config, context=runtime_context)
        finally:
            reset_workflow_cloud_budget(token)
        result = dict(result)
        result["ai_cloud_budget"] = cloud_budget.snapshot().as_dict()
        return result

    try:
        # Check for existing checkpoint state for this scan_id thread
        if checkpointer is not None and resume_if_exists:
            if checkpoint_has_values:
                # Hydrate usage before any resumed node can reserve capacity;
                # checkpoint snapshots are authoritative and usage is merged
                # monotonically.
                cloud_budget.hydrate(current_state.values.get("ai_cloud_budget"))
                checkpoint_authority = (current_state.values.get("manifest_summary") or {}).get("index_authority")
                expected_commit = evidence_store.manifest.commit_hash
                checkpoint_commit = current_state.values.get("commit_hash")
                commit_incompatible = (
                    (checkpoint_commit is not None and checkpoint_commit != expected_commit)
                    or (checkpoint_commit is None and index_authority is None)
                )
                if index_authority != checkpoint_authority or commit_incompatible:
                    # Never apply checkpoint findings or evidence IDs to a different
                    # generation, including legacy checkpoints without provenance.
                    return {
                        "scan_id": scan_id,
                        "status": "FAILED",
                        "errors": ["Checkpoint evidence generation is incompatible; start a new scan."],
                        "ai_cloud_budget": cloud_budget.snapshot().as_dict(),
                    }
                # If all nodes already finished, return the completed state directly
                if not current_state.next:
                    span_event("checkpoint_resume", {"repolens.workflow.scan_id": scan_id, "repolens.workflow.checkpoint_already_complete": True})
                    logger.info("Scan %s already completed in checkpointer. Returning cached result.", scan_id)
                    completed_state = dict(current_state.values)
                    completed_state.setdefault("ai_cloud_budget", cloud_budget.snapshot().as_dict())
                    return completed_state

                # Interrupted scan: resume execution from last completed super-step
                logger.info("Resuming scan %s from checkpoint (next nodes: %s)...", scan_id, current_state.next)
                span_event(
                    "checkpoint_resume",
                    {
                        "repolens.workflow.scan_id": scan_id,
                        "repolens.workflow.checkpoint_already_complete": False,
                        "repolens.workflow.checkpoint_next_node_count": len(current_state.next or ()),
                    },
                )
                try:
                    resumed_result = await invoke_with_cloud_budget(None)
                    return resumed_result
                except Exception as exc:
                    safe_msg = redact_secrets(str(exc))[:2048]
                    logger.error("Terminal workflow failure during resume of scan %s: %s", scan_id, safe_msg)
                    failed_state = dict(current_state.values)
                    if isinstance(exc, _WorkflowNodeExecutionError):
                        try:
                            latest = await app.aget_state(config)
                            latest_values = getattr(latest, "values", None)
                            if isinstance(latest_values, dict) and latest_values:
                                failed_state = dict(latest_values)
                        except Exception:
                            logger.warning("Unable to load the latest checkpoint after resumed node failure for scan %s", scan_id)
                        events = list(failed_state.get("workflow_trace", []))
                        if len(events) < MAX_WORKFLOW_TRACE_EVENTS:
                            events.append(exc.trace_event)
                        failed_state["workflow_trace"] = events
                    failed_state["status"] = "FAILED"
                    failed_state.setdefault("errors", []).append(f"Terminal execution failure on resume: {safe_msg}")
                    failed_state["ai_cloud_budget"] = cloud_budget.snapshot().as_dict()
                    return failed_state

        # Fresh scan initialization (strictly JSON/msgpack serializable for checkpoints)
        summary = evidence_store.get_summary()
        graph_data = runtime.repository_graph.to_domain_data()
        graph_coverage = dict(graph_data.coverage or {})
        graph_coverage["complete"] = bool(graph_data.complete)
        contract_report = graph_data.contract_report
        contract_coverage = {
            "total_frontend_requests": getattr(contract_report, "total_frontend_requests", 0),
            "total_backend_routes": getattr(contract_report, "total_backend_routes", 0),
            "matched_count": getattr(contract_report, "matched_count", 0),
            "unmatched_count": getattr(contract_report, "unmatched_count", 0),
            "method_mismatch_count": getattr(contract_report, "method_mismatch_count", 0),
            "ambiguous_count": getattr(contract_report, "ambiguous_count", 0),
            "payload_mismatch_count": getattr(contract_report, "payload_mismatch_count", 0),
        }
        deterministic_correctness = build_bug_candidates(runtime.chunks)
        deterministic_security_flows = build_security_flow_candidates(
            evidence_store.manifest,
            runtime.chunks,
        )
        deterministic_architecture = build_architecture_candidates(
            runtime.repository_graph,
            runtime.chunks,
        )
        if persistent_index is not None:
            from app.indexing.facts import select_candidates, select_architecture_candidates
            deterministic_correctness = select_candidates(persistent_index, "bug")
            bug_selection = dict(persistent_index.query_coverage)
            deterministic_security_flows = select_candidates(persistent_index, "security")
            security_selection = dict(persistent_index.query_coverage)
            deterministic_architecture = select_architecture_candidates(persistent_index, runtime.repository_graph)
            unresolved_frontier = dict(
                getattr(runtime.repository_graph, "unresolved_frontier", {})
            )
            query_truncated = bool(
                getattr(runtime.repository_graph, "query_truncated", False)
            )
            summary["candidate_selection_coverage"] = {
                "bug": bug_selection, "security": security_selection,
                "architecture": {"selected": len(deterministic_architecture), "candidate_selection_partial": True,
                    "unresolved_frontier": unresolved_frontier},
            }
            summary["index_coverage"] = dict(persistent_index.stats)
            graph_coverage.update({
                "complete": bool(graph_data.complete) and not query_truncated,
                "unresolved_frontier": unresolved_frontier,
                "query_truncated": query_truncated,
            })
        summary = {
            **summary,
            "index_authority": index_authority,
            "graph_coverage": graph_coverage,
            "unresolved_graph_relationships": graph_coverage.get("unresolved_graph_relationships", 0),
            "route_contract_coverage": contract_coverage,
            "source_evidence_available": bool(evidence_store.manifest.files),
            "tool_coverage": summary.get("scanners_executed", {}),
        }
        initial_state: AnalysisState = {
            "scan_id": scan_id,
            "repository_url": evidence_store.manifest.repository_url,
            "commit_hash": evidence_store.manifest.commit_hash,
            "branch": evidence_store.manifest.branch,
            "repo_dir": repo_dir,
            "manifest_summary": summary,
            "languages": evidence_store.manifest.languages,
            "frameworks": [fw.name for fw in evidence_store.manifest.frameworks],
            "architecture_overview": None,
            "routes": [r.model_dump() for r in evidence_store.get_routes()],
            "frontend_calls": [c.model_dump() for c in evidence_store.get_http_calls()],
            "static_findings": [f.model_dump() for f in evidence_store.all_findings],
            "graph_coverage": graph_coverage,
            "deterministic_correctness_candidates": [
                candidate.model_dump(mode="json") for candidate in deterministic_correctness
            ],
            "deterministic_security_flow_candidates": [
                candidate.model_dump(mode="json") for candidate in deterministic_security_flows
            ],
            "deterministic_architecture_candidates": [
                candidate.model_dump(mode="json") for candidate in deterministic_architecture
            ],
            "route_contract_coverage": contract_coverage,
            "source_evidence_available": bool(evidence_store.manifest.files),
            "tool_coverage": summary.get("scanners_executed", {}),
            "ai_admission": {},
            "ai_cloud_budget": cloud_budget.snapshot().as_dict(),
            "candidate_findings": [],
            "revision_candidates": [],
            "verified_findings": [],
            "rejected_findings": [],
            "revision_count": 0,
            "verification_decision": None,
            "revision_target_ids": [],
            "agent_investigator_enabled": get_settings().AGENT_INVESTIGATOR_ENABLED,
            "investigator": {},
            "investigation_evidence": {},
            "mcp_revision_evidence": {},
            "mcp_tool_events": [],
            "mcp_call_count": 0,
            "completed_nodes": [],
            "workflow_trace": [],
            "model_executions": [],
            "errors": [],
            "status": "RUNNING",
        }
        initial_state["ai_admission"] = build_admission_map(initial_state)
        policy_keys = {
            "architecture": "architecture",
            "integration": "integration_code",
            "security": "security_reasoning",
            "bug": "bug_reasoning",
        }
        cloud_budget.set_schedule({
            policy_keys.get(name, name): int(plan.get("priority", 0))
            for name, plan in initial_state["ai_admission"].items()
            if str(plan.get("decision")) == "CLOUD_REQUIRED"
        } | {"verification": 95})

        try:
            final_state = await invoke_with_cloud_budget(initial_state)
            resumed_for_evaluation = False
            if interrupt_after:
                interrupted = await app.aget_state(config)
                if getattr(interrupted, "next", ()):
                    resumed_for_evaluation = True
                    final_state = await invoke_with_cloud_budget(None)
            if resumed_for_evaluation:
                final_state["_evaluation_resumed"] = True
            return final_state
        except Exception as exc:
            safe_msg = redact_secrets(str(exc))[:2048]
            logger.error("Terminal workflow failure for scan %s: %s", scan_id, safe_msg)
            failed_state = initial_state
            if isinstance(exc, _WorkflowNodeExecutionError):
                try:
                    checkpoint = await app.aget_state(config)
                    checkpoint_values = getattr(checkpoint, "values", None)
                    if isinstance(checkpoint_values, dict) and checkpoint_values:
                        failed_state = dict(checkpoint_values)
                except Exception:
                    logger.warning("Unable to load the latest checkpoint after node failure for scan %s", scan_id)
                events = list(failed_state.get("workflow_trace", []))
                if len(events) < MAX_WORKFLOW_TRACE_EVENTS:
                    events.append(exc.trace_event)
                failed_state["workflow_trace"] = events
            failed_state["status"] = "FAILED"
            failed_state.setdefault("errors", []).append(f"Terminal execution failure: {safe_msg}")
            failed_state["ai_cloud_budget"] = cloud_budget.snapshot().as_dict()
            return failed_state
    finally:
        try:
            await mcp_executor.aclose()
        except Exception as exc:
            logger.warning("Error closing MCP executor for scan %s: %s", scan_id, redact_secrets(str(exc))[:256])
        unregister_scan_runtime(scan_id)
