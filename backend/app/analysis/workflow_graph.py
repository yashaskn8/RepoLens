"""Typed LangGraph Durable Workflow for Phase 6 Change Intelligence Analysis.

Defines the durable linear state graph:
REQUEST -> ACQUIRE -> DIFF -> IMPACT -> REVIEW -> VERIFY -> COMPLETE

Guarantees:
- Zero uncontrolled loops.
- Restart and resume from durable state without redundant computations.
- Deterministic nodes remain strictly deterministic.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, TypedDict
from uuid import UUID

from langgraph.graph import END, START, StateGraph

from app.analysis.diff_engine import get_diff_engine
from app.analysis.impact_engine import get_impact_engine
from app.analysis.review_verifier import get_review_verifier
from app.analysis.reviewer import get_change_reviewer
from app.graph.repository_graph import RepositoryGraph
from app.ingestion.comparison_snapshot import get_comparison_snapshot_service
from app.schemas.change_analysis import (
    BlastRadiusReport,
    ChangeReviewReport,
    StructuralDiffResult,
)

logger = logging.getLogger(__name__)


class ChangeAnalysisState(TypedDict, total=False):
    """Typed LangGraph state for change intelligence analysis workflow."""

    analysis_id: str
    repository_url: str
    base_commit_sha: str
    head_commit_sha: str
    base_ref: Optional[str]
    head_ref: Optional[str]
    base_workspace: Optional[str]
    head_workspace: Optional[str]
    diff_result: Optional[StructuralDiffResult]
    blast_radius: Optional[BlastRadiusReport]
    review_report: Optional[ChangeReviewReport]
    status: str
    error: Optional[str]
    completed_nodes: List[str]


async def run_acquire_node(state: ChangeAnalysisState) -> Dict[str, Any]:
    """Node 1: Acquire exact base and head workspaces if not already available."""
    completed = list(state.get("completed_nodes", []))
    if state.get("base_workspace") and state.get("head_workspace"):
        completed.append("acquire")
        return {"status": "DIFFING", "completed_nodes": completed}

    snapshot_service = get_comparison_snapshot_service()
    base_ws, head_ws = await snapshot_service.acquire_comparison_workspaces(
        repository_url=state["repository_url"],
        base_commit_sha=state["base_commit_sha"],
        head_commit_sha=state["head_commit_sha"],
        base_ref=state.get("base_ref"),
        head_ref=state.get("head_ref"),
    )

    completed.append("acquire")
    return {
        "base_workspace": base_ws,
        "head_workspace": head_ws,
        "status": "DIFFING",
        "completed_nodes": completed,
    }


async def run_diff_node(state: ChangeAnalysisState) -> Dict[str, Any]:
    """Node 2: Deterministic structural diff computation."""
    completed = list(state.get("completed_nodes", []))
    if state.get("diff_result"):
        completed.append("diff")
        return {"status": "ANALYZING", "completed_nodes": completed}

    diff_engine = get_diff_engine()
    diff_res = await asyncio.to_thread(
        diff_engine.compute_structural_diff,
        base_workspace=state["base_workspace"],
        head_workspace=state["head_workspace"],
        base_commit_sha=state["base_commit_sha"],
        head_commit_sha=state["head_commit_sha"],
        repository_url=state["repository_url"],
    )


    completed.append("diff")
    return {
        "diff_result": diff_res,
        "status": "ANALYZING",
        "completed_nodes": completed,
    }


async def run_impact_node(state: ChangeAnalysisState) -> Dict[str, Any]:
    """Node 3: Graph-aware blast radius analysis using canonical RepositoryGraph."""
    completed = list(state.get("completed_nodes", []))
    if state.get("blast_radius"):
        completed.append("impact")
        return {"status": "ANALYZING", "completed_nodes": completed}

    diff_res = state["diff_result"]
    impact_engine = get_impact_engine()

    # Build canonical base graph using production builder
    base_ws = state.get("base_workspace")
    base_graph: Optional[RepositoryGraph] = None
    if base_ws:
        try:
            from app.ingestion.manifest import build_manifest
            from app.graph.builder import build_repository_graph

            base_manifest = await asyncio.to_thread(
                build_manifest,
                repo_dir=base_ws,
                repository_url=state.get("repository_url", ""),
                commit_hash=state.get("base_commit_sha", ""),
                branch=state.get("base_ref"),
            )
            base_graph = await asyncio.to_thread(
                build_repository_graph,
                manifest=base_manifest,
            )
        except Exception as exc:
            logger.error(f"Canonical base graph build failed: {str(exc)}", exc_info=True)
            raise RuntimeError(f"GRAPH_BUILD_FAILED: Canonical base graph construction failed: {str(exc)}") from exc

    report = impact_engine.compute_blast_radius(
        analysis_id=UUID(state["analysis_id"]),
        diff_result=diff_res,
        base_graph=base_graph,
    )

    completed.append("impact")
    return {
        "blast_radius": report,
        "status": "ANALYZING",
        "completed_nodes": completed,
    }


async def run_review_node(state: ChangeAnalysisState) -> Dict[str, Any]:
    """Node 4: AI change reviewer with central LLMRouter."""
    completed = list(state.get("completed_nodes", []))
    if state.get("review_report"):
        completed.append("review")
        return {"status": "VERIFYING", "completed_nodes": completed}

    reviewer = get_change_reviewer()
    diff_res = state["diff_result"]
    blast_radius = state["blast_radius"]

    review_report = await reviewer.review_changes(
        analysis_id=UUID(state["analysis_id"]),
        diff_result=diff_res,
        blast_radius=blast_radius,
        base_workspace=state.get("base_workspace"),
        head_workspace=state.get("head_workspace"),
    )

    completed.append("review")
    return {
        "review_report": review_report,
        "status": "VERIFYING",
        "completed_nodes": completed,
    }


async def run_verify_node(state: ChangeAnalysisState) -> Dict[str, Any]:
    """Node 5: Deterministic verification of review findings."""
    completed = list(state.get("completed_nodes", []))
    verifier = get_review_verifier()
    diff_res = state["diff_result"]
    blast_radius = state["blast_radius"]
    review_report = state["review_report"]

    base_ws = state.get("base_workspace")
    base_graph: Optional[RepositoryGraph] = None
    if base_ws:
        try:
            from app.ingestion.manifest import build_manifest
            from app.graph.builder import build_repository_graph

            base_manifest = await asyncio.to_thread(
                build_manifest,
                repo_dir=base_ws,
                repository_url=state.get("repository_url", ""),
                commit_hash=state.get("base_commit_sha", ""),
                branch=state.get("base_ref"),
            )
            base_graph = await asyncio.to_thread(
                build_repository_graph,
                manifest=base_manifest,
            )
        except Exception as exc:
            logger.error(f"Canonical base graph build failed during verification: {str(exc)}", exc_info=True)
            raise RuntimeError(f"GRAPH_BUILD_FAILED: Canonical base graph verification construction failed: {str(exc)}") from exc

    verified_report = verifier.verify_report(
        report=review_report,
        diff_result=diff_res,
        blast_radius=blast_radius,
        base_graph=base_graph,
        base_workspace=state.get("base_workspace"),
        head_workspace=state.get("head_workspace"),
    )

    completed.append("verify")
    return {
        "review_report": verified_report,
        "status": "COMPLETED",
        "completed_nodes": completed,
    }


async def run_complete_node(state: ChangeAnalysisState) -> Dict[str, Any]:
    """Node 6: Finalize workflow execution."""
    completed = list(state.get("completed_nodes", []))
    completed.append("complete")
    return {
        "status": "COMPLETED",
        "completed_nodes": completed,
    }


def build_change_analysis_graph(checkpointer: Optional[Any] = None) -> Any:
    """Compile and return the Phase 6 LangGraph change analysis workflow."""
    workflow = StateGraph(ChangeAnalysisState)

    workflow.add_node("acquire", run_acquire_node)
    workflow.add_node("diff", run_diff_node)
    workflow.add_node("impact", run_impact_node)
    workflow.add_node("review", run_review_node)
    workflow.add_node("verify", run_verify_node)
    workflow.add_node("complete", run_complete_node)

    workflow.add_edge(START, "acquire")
    workflow.add_edge("acquire", "diff")
    workflow.add_edge("diff", "impact")
    workflow.add_edge("impact", "review")
    workflow.add_edge("review", "verify")
    workflow.add_edge("verify", "complete")
    workflow.add_edge("complete", END)

    return workflow.compile(checkpointer=checkpointer)
