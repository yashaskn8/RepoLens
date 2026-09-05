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
    impact_frontier: Dict[str, Any]


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


from app.security.redaction import redact_secrets


async def build_canonical_phase6_graph(
    workspace_path: Optional[str],
    repository_url: str,
    commit_sha: str,
    branch_ref: Optional[str] = None,
) -> Optional[RepositoryGraph]:
    """Canonical fail-closed graph builder shared across impact, review, and verify nodes.

    Guarantees:
    - Never persists graph objects to durable LangGraph state (ephemeral and reconstructable).
    - Redacts any sensitive data before logging on failure.
    - Fails closed with typed RuntimeError.
    """
    if not workspace_path:
        return None
    try:
        from pathlib import Path
        from app.execution.context import current_claim, new_execution_session
        claim = current_claim()
        if claim is not None and (Path(workspace_path) / ".git").exists():
            from app.indexing.persistent import IndexLimits, PersistentIndex
            from app.graph.persistent import PersistentRepositoryGraph
            db = new_execution_session()
            try:
                index = PersistentIndex(db, tenant_id=claim.tenant_id, repository_url=repository_url,
                    repo_dir=workspace_path, commit_sha=commit_sha,
                    limits=IndexLimits(max_files=256, manifest_files=128, max_seconds=30))
                index.build_manifest(branch=branch_ref)
                index.pin(claim.work_item_id, owner_kind="work")
                index.pin(claim.resource_id, owner_kind="change")
                graph = PersistentRepositoryGraph(index)
                graph._index_db = db
                return graph
            except Exception:
                db.close()
                raise
        from app.ingestion.manifest import build_manifest
        from app.graph.builder import build_repository_graph

        manifest = await asyncio.to_thread(
            build_manifest,
            repo_dir=workspace_path,
            repository_url=repository_url,
            commit_hash=commit_sha,
            branch=branch_ref,
        )
        graph = await asyncio.to_thread(
            build_repository_graph,
            manifest=manifest,
        )
        return graph
    except Exception as exc:
        safe_msg = redact_secrets(str(exc))
        logger.error(f"Canonical phase6 graph build failed: {safe_msg}", exc_info=False)
        raise RuntimeError(f"GRAPH_BUILD_FAILED: Canonical graph construction failed: {safe_msg}") from exc


async def run_impact_node(state: ChangeAnalysisState) -> Dict[str, Any]:
    """Node 3: Graph-aware blast radius analysis using canonical RepositoryGraph."""
    completed = list(state.get("completed_nodes", []))
    if state.get("blast_radius"):
        completed.append("impact")
        return {"status": "ANALYZING", "completed_nodes": completed}

    diff_res = state["diff_result"]
    impact_engine = get_impact_engine()

    base_graph = await build_canonical_phase6_graph(
        workspace_path=state.get("base_workspace"),
        repository_url=state.get("repository_url", ""),
        commit_sha=state.get("base_commit_sha", ""),
        branch_ref=state.get("base_ref"),
    )

    frontier = None
    index_db = getattr(base_graph, "_index_db", None)
    try:
        from app.analysis.impact_frontier import advance_frontier, frontier_graph
        # Recover exactly the original sealed view before using checkpoint IDs.
        prior = state.get("impact_frontier")
        if prior and getattr(base_graph, "index", None) is not None:
            base_graph.index.open_snapshot(prior["authority"]["snapshot"])
        frontier = advance_frontier(base_graph, diff_res, prior)
        if frontier["queue"] and not frontier["stopped"]:
            return {"impact_frontier": frontier, "status": "ANALYZING"}
        base_graph = frontier_graph(frontier)
        report = impact_engine.compute_blast_radius(
            analysis_id=UUID(state["analysis_id"]), diff_result=diff_res, base_graph=base_graph)
        if (frontier and frontier["partial"]) or diff_res.discovery_coverage.get("complete") is False:
            report.is_truncated = True
            report.truncation_reason = "PARTIAL_DISCOVERY_OR_IMPACT_FRONTIER"
    finally:
        if index_db is not None:
            index_db.close()

    completed.append("impact")
    return {
        "blast_radius": report,
        "impact_frontier": frontier or {},
        "status": "ANALYZING",
        "completed_nodes": completed,
    }


async def run_review_node(state: ChangeAnalysisState) -> Dict[str, Any]:
    """Node 4: AI change reviewer with central LLMRouter and graph parity."""
    completed = list(state.get("completed_nodes", []))
    if state.get("review_report"):
        completed.append("review")
        return {"status": "VERIFYING", "completed_nodes": completed}

    reviewer = get_change_reviewer()
    diff_res = state["diff_result"]
    blast_radius = state["blast_radius"]

    base_graph = await build_canonical_phase6_graph(
        workspace_path=state.get("base_workspace"),
        repository_url=state.get("repository_url", ""),
        commit_sha=state.get("base_commit_sha", ""),
        branch_ref=state.get("base_ref"),
    )

    try:
        review_report = await reviewer.review_changes(
            analysis_id=UUID(state["analysis_id"]), diff_result=diff_res, blast_radius=blast_radius,
            base_graph=base_graph, base_workspace=state.get("base_workspace"), head_workspace=state.get("head_workspace"))
    finally:
        if (index_db := getattr(base_graph, "_index_db", None)) is not None:
            index_db.close()

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

    base_graph = await build_canonical_phase6_graph(
        workspace_path=state.get("base_workspace"),
        repository_url=state.get("repository_url", ""),
        commit_sha=state.get("base_commit_sha", ""),
        branch_ref=state.get("base_ref"),
    )

    try:
        verified_report = verifier.verify_report(
            report=review_report, diff_result=diff_res, blast_radius=blast_radius,
            base_graph=base_graph, base_workspace=state.get("base_workspace"), head_workspace=state.get("head_workspace"))
    finally:
        if (index_db := getattr(base_graph, "_index_db", None)) is not None:
            index_db.close()

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
    workflow.add_conditional_edges("impact", lambda state: "impact" if (
        state.get("impact_frontier", {}).get("queue") and
        not state.get("impact_frontier", {}).get("stopped") and not state.get("blast_radius")
    ) else "review", {"impact": "impact", "review": "review"})
    workflow.add_edge("review", "verify")
    workflow.add_edge("verify", "complete")
    workflow.add_edge("complete", END)

    return workflow.compile(checkpointer=checkpointer)
