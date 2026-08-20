"""LangGraph multi-agent workflow construction and execution."""

import asyncio
from typing import Any, Dict, Optional
from langgraph.graph import END, START, StateGraph

from app.agents.architecture import run_architecture_agent
from app.agents.bug import run_bug_agent
from app.agents.integration import run_integration_agent
from app.agents.mapper import run_repository_mapper
from app.agents.security import run_security_agent
from app.agents.state import AnalysisState
from app.agents.verifier import run_verifier_agent
from app.analysis.store import EvidenceStore


def build_analysis_graph() -> Any:
    """Construct and compile the parallel specialist LangGraph analysis workflow."""
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

    return workflow.compile()


async def run_analysis_workflow(
    evidence_store: EvidenceStore,
    scan_id: str,
    repo_dir: str,
) -> AnalysisState:
    """Initialize state from EvidenceStore and execute the compiled LangGraph workflow."""
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
        "model_executions": [],
        "errors": [],
        "status": "RUNNING",
    }

    graph = build_analysis_graph()
    final_state = await graph.ainvoke(initial_state)
    return final_state
