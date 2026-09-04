"""Durable LangGraph multi-agent workflow construction, SQLite checkpointer integration, and execution."""

import asyncio
import inspect
import logging
from typing import Any, Dict, List, Optional
from langgraph.graph import END, START, StateGraph

from app.agents.architecture import run_architecture_agent
from app.agents.bug import run_bug_agent
from app.agents.checkpointer import get_sqlite_checkpointer
from app.agents.integration import run_integration_agent
from app.agents.mapper import run_repository_mapper
from app.agents.mcp_enrichment import run_mcp_enrichment_node
from app.agents.revision import run_revision_agent
from app.agents.security import run_security_agent
from app.agents.state import AnalysisState
from app.agents.verifier import run_verifier_agent
from app.agents.helpers import safe_to_uuid
from app.analysis.store import EvidenceStore
from app.agents.deterministic import scanner_candidates
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

logger = logging.getLogger(__name__)


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
        return "revise"
    return "finalize_uncertain"


async def _budgeted_node(fn: Any, state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    """Attach the current economy snapshot to every durable checkpoint write."""
    if len(inspect.signature(fn).parameters) > 1:
        result = await fn(state, runtime)
    else:
        result = await fn(state)
    result = dict(result or {})
    budget = current_workflow_cloud_budget()
    if budget is not None:
        result["ai_cloud_budget"] = budget.snapshot().as_dict()
    return result


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


async def _revise_node(state: AnalysisState, runtime: Any = None) -> Dict[str, Any]:
    return await _budgeted_node(run_revision_agent, state, runtime)


def build_analysis_graph(checkpointer: Optional[Any] = None) -> Any:
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
    workflow.add_node("revise", _revise_node)
    workflow.add_node("finalize", run_finalize_node)
    workflow.add_node("finalize_uncertain", run_finalize_uncertain_node)

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
            "finalize_uncertain": "finalize_uncertain",
        },
    )

    # 4. Loop mcp_enrich -> revise -> verifier (bounded to at most 1 attempt by route_after_verifier and revision_count)
    workflow.add_edge("mcp_enrich", "revise")
    workflow.add_edge("revise", "verifier")

    # 5. Terminal edges
    workflow.add_edge("finalize", END)
    workflow.add_edge("finalize_uncertain", END)

    return workflow.compile(checkpointer=checkpointer)


async def run_analysis_workflow(
    evidence_store: EvidenceStore,
    scan_id: str,
    repo_dir: str,
    checkpointer: Optional[Any] = None,
    resume_if_exists: bool = True,
    context_engine: Optional[ContextEngine] = None,
    repository_graph: Optional[RepositoryGraph] = None,
) -> AnalysisState:
    """Execute or resume the durable LangGraph multi-agent analysis workflow using scan_id as thread identifier.
    
    Guarantees:
    - Automatically builds and registers canonical ScanIntelligenceRuntime and passes AnalysisRuntimeContext.
    - Large code files, service objects, and complex class instances remain outside msgpack state.
    - Checkpoint saves serializable state after every super-step.
    - An interrupted scan resumes from the last completed node without re-executing finished agents.
    - Failed nodes or terminal failures capture sanitized errors without corrupting the checkpointer.
    """
    config = {
        "configurable": {"thread_id": scan_id},
        "recursion_limit": 25,
    }
    app = build_analysis_graph(checkpointer=checkpointer)

    # Assemble and register ScanIntelligenceRuntime for this scan_id
    try:
        if context_engine is not None:
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

    # Lazily initialized MCP runtime client & executor (connection opened only if mcp_enrich executes)
    mcp_server = MCPRepositoryServer(
        evidence_store=evidence_store,
        repo_dir=repo_dir,
        repository_graph=runtime.repository_graph,
        context_engine=runtime.context_engine,
    )
    mcp_client = MCPRuntimeClient(repo_server=mcp_server)
    mcp_executor = MCPToolExecutor(client=mcp_client)

    runtime_context = AnalysisRuntimeContext(
        scan_runtime=runtime,
        mcp_executor=mcp_executor,
    )
    cloud_budget = WorkflowCloudBudget.from_settings()

    async def invoke_with_cloud_budget(payload: Any) -> AnalysisState:
        token = bind_workflow_cloud_budget(cloud_budget)
        try:
            result = await app.ainvoke(payload, config=config, context=runtime_context)
        finally:
            reset_workflow_cloud_budget(token)
        result = dict(result)
        result["ai_cloud_budget"] = cloud_budget.snapshot().as_dict()
        return result

    try:
        # Check for existing checkpoint state for this scan_id thread
        if checkpointer is not None and resume_if_exists:
            current_state = None
            try:
                current_state = await app.aget_state(config)
            except Exception as exc:
                safe_msg = redact_secrets(str(exc))[:2048]
                logger.warning("Failed to retrieve existing checkpoint state for %s: %s", scan_id, safe_msg)

            if current_state and current_state.values:
                # Hydrate usage before any resumed node can reserve capacity;
                # checkpoint snapshots are authoritative and usage is merged
                # monotonically.
                cloud_budget.hydrate(current_state.values.get("ai_cloud_budget"))
                # If all nodes already finished, return the completed state directly
                if not current_state.next:
                    logger.info("Scan %s already completed in checkpointer. Returning cached result.", scan_id)
                    completed_state = dict(current_state.values)
                    completed_state.setdefault("ai_cloud_budget", cloud_budget.snapshot().as_dict())
                    return completed_state

                # Interrupted scan: resume execution from last completed super-step
                logger.info("Resuming scan %s from checkpoint (next nodes: %s)...", scan_id, current_state.next)
                try:
                    resumed_result = await invoke_with_cloud_budget(None)
                    return resumed_result
                except Exception as exc:
                    safe_msg = redact_secrets(str(exc))[:2048]
                    logger.error("Terminal workflow failure during resume of scan %s: %s", scan_id, safe_msg)
                    failed_state = dict(current_state.values)
                    failed_state["status"] = "FAILED"
                    failed_state.setdefault("errors", []).append(f"Terminal execution failure on resume: {safe_msg}")
                    failed_state["ai_cloud_budget"] = cloud_budget.snapshot().as_dict()
                    return failed_state

        # Fresh scan initialization (strictly JSON/msgpack serializable for checkpoints)
        summary = evidence_store.get_summary()
        graph_data = runtime.repository_graph.to_domain_data()
        graph_coverage = dict(graph_data.coverage or {})
        contract_report = graph_data.contract_report
        contract_coverage = {
            "total_frontend_requests": getattr(contract_report, "total_frontend_requests", 0),
            "total_backend_routes": getattr(contract_report, "total_backend_routes", 0),
            "matched_count": getattr(contract_report, "matched_count", 0),
            "unmatched_count": getattr(contract_report, "unmatched_count", 0),
            "method_mismatch_count": getattr(contract_report, "method_mismatch_count", 0),
            "ambiguous_count": getattr(contract_report, "ambiguous_count", 0),
        }
        deterministic_candidates = scanner_candidates(
            [f.model_dump(mode="json") for f in evidence_store.all_findings],
            scan_id=safe_to_uuid(scan_id),
        )
        deterministic_correctness = [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
            for item in deterministic_candidates
            if str(getattr(item, "category", "")).lower() in {"correctness", "bug", "quality"}
        ]
        # No dedicated deterministic correctness detector ran in the mapper;
        # keep this unset so admission reports NOT_ANALYZED rather than
        # falsely asserting that zero bugs were proven.
        deterministic_correctness_value = deterministic_correctness or None
        summary = {
            **summary,
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
            "deterministic_correctness_candidates": deterministic_correctness_value,
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
            "mcp_revision_evidence": {},
            "mcp_tool_events": [],
            "mcp_call_count": 0,
            "completed_nodes": [],
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
            return final_state
        except Exception as exc:
            safe_msg = redact_secrets(str(exc))[:2048]
            logger.error("Terminal workflow failure for scan %s: %s", scan_id, safe_msg)
            initial_state["status"] = "FAILED"
            initial_state.setdefault("errors", []).append(f"Terminal execution failure: {safe_msg}")
            initial_state["ai_cloud_budget"] = cloud_budget.snapshot().as_dict()
            return initial_state
    finally:
        try:
            await mcp_executor.aclose()
        except Exception as exc:
            logger.warning("Error closing MCP executor for scan %s: %s", scan_id, redact_secrets(str(exc))[:256])
        unregister_scan_runtime(scan_id)
