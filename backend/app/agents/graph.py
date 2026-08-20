"""Durable LangGraph multi-agent workflow construction, SQLite checkpointer integration, and execution."""

import asyncio
import logging
from typing import Any, Dict, Optional
from langgraph.graph import END, START, StateGraph

from app.agents.architecture import run_architecture_agent
from app.agents.bug import run_bug_agent
from app.agents.checkpointer import get_sqlite_checkpointer
from app.agents.integration import run_integration_agent
from app.agents.mapper import run_repository_mapper
from app.agents.security import run_security_agent
from app.agents.state import AnalysisState
from app.agents.verifier import run_verifier_agent
from app.analysis.store import EvidenceStore

from app.context.engine import ContextEngine
from app.context.runtime import (
    ScanIntelligenceRuntime,
    register_scan_runtime,
    unregister_scan_runtime,
)
from app.graph.repository_graph import RepositoryGraph

logger = logging.getLogger(__name__)


def build_analysis_graph(checkpointer: Optional[Any] = None) -> Any:
    """Construct and compile the parallel specialist LangGraph analysis workflow with optional checkpointer."""
    workflow = StateGraph(AnalysisState)

    # 1. Register specialist nodes
    workflow.add_node("mapper", run_repository_mapper)
    workflow.add_node("architecture", run_architecture_agent)
    workflow.add_node("integration", run_integration_agent)
    workflow.add_node("security", run_security_agent)
    workflow.add_node("bug", run_bug_agent)
    workflow.add_node("verifier", run_verifier_agent)

    # 2. Wire execution flow: START -> mapper -> parallel specialists -> verifier -> END
    workflow.add_edge(START, "mapper")
    workflow.add_edge("mapper", "architecture")
    workflow.add_edge("mapper", "integration")
    workflow.add_edge("mapper", "security")
    workflow.add_edge("mapper", "bug")

    workflow.add_edge("architecture", "verifier")
    workflow.add_edge("integration", "verifier")
    workflow.add_edge("security", "verifier")
    workflow.add_edge("bug", "verifier")

    workflow.add_edge("verifier", END)

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
    - Automatically builds and registers canonical ScanIntelligenceRuntime.
    - Large code files and complex class instances remain outside msgpack state.
    - Checkpoint saves serializable state after every super-step.
    - An interrupted scan resumes from the last completed node without re-executing finished agents.
    - Failed nodes or terminal failures capture errors without corrupting the checkpointer.
    """
    config = {"configurable": {"thread_id": scan_id}}
    app = build_analysis_graph(checkpointer=checkpointer)

    # Assemble and register ScanIntelligenceRuntime for this scan_id
    try:
        if context_engine is not None:
            # If ContextEngine was explicitly provided, construct or register lightweight runtime
            runtime = ScanIntelligenceRuntime(
                evidence_store=evidence_store,
                repository_graph=repository_graph or ContextEngine(evidence_store).repository_graph,
                chunks=[],
                vector_index=None,
                embedding_provider=None,
                retrieval_service=None,
                context_engine=context_engine,
            )
            register_scan_runtime(scan_id, runtime)
        else:
            runtime = await ScanIntelligenceRuntime.build(
                evidence_store=evidence_store,
                repo_dir=repo_dir,
            )
            register_scan_runtime(scan_id, runtime)
    except Exception as exc:
        logger.warning("Notice during ScanIntelligenceRuntime setup for scan %s: %s", scan_id, str(exc))

    try:
        # Check for existing checkpoint state for this scan_id thread
        if checkpointer is not None and resume_if_exists:
            try:
                current_state = await app.aget_state(config)
                if current_state and current_state.values:
                    # If all nodes already finished, return the completed state directly
                    if not current_state.next:
                        logger.info("Scan %s already completed in checkpointer. Returning cached result.", scan_id)
                        return current_state.values

                    # Interrupted scan: resume execution from last completed super-step
                    logger.info("Resuming scan %s from checkpoint (next nodes: %s)...", scan_id, current_state.next)
                    resumed_result = await app.ainvoke(None, config=config)
                    return resumed_result
            except Exception as exc:
                logger.warning("Failed to check or resume existing checkpoint for %s: %s. Starting fresh.", scan_id, str(exc))

        # Fresh scan initialization (strictly JSON/msgpack serializable for SQLite checkpoints)
        summary = evidence_store.get_summary()
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
            "candidate_findings": [],
            "verified_findings": [],
            "rejected_findings": [],
            "completed_nodes": [],
            "model_executions": [],
            "errors": [],
            "status": "RUNNING",
        }

        try:
            final_state = await app.ainvoke(initial_state, config=config)
            return final_state
        except Exception as exc:
            logger.error("Terminal workflow failure for scan %s: %s", scan_id, str(exc))
            # Attempt to record failure in state
            initial_state["status"] = "FAILED"
            initial_state["errors"].append(f"Terminal execution failure: {str(exc)}")
            return initial_state
    finally:
        unregister_scan_runtime(scan_id)


