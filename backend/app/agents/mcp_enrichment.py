"""Deterministic MCP enrichment node providing evidence for targeted revision candidates."""

import logging
import re
from typing import Any, Dict, List, Optional

from langgraph.runtime import Runtime

from app.agents.state import AnalysisState
from app.context.runtime import AnalysisRuntimeContext
from app.mcp.executor import MAX_MCP_TARGETS_PER_REVISION, MCPToolExecutor

logger = logging.getLogger(__name__)

_ROUTE_REGEX = re.compile(r"(/[a-zA-Z0-9_\-/{}:]+)")


def _extract_potential_symbol(candidate: Any) -> Optional[str]:
    """Extract a likely function or class symbol name from finding title or evidence."""
    # Check title for symbol mentions like 'my_func()' or symbol names
    words = candidate.title.split()
    for w in words:
        clean = w.strip("`'\"():,")
        if clean.isidentifier() and len(clean) > 2:
            return clean
    return None


def _extract_potential_route(candidate: Any) -> Optional[str]:
    """Extract a route path from finding description or title."""
    match = _ROUTE_REGEX.search(candidate.title) or _ROUTE_REGEX.search(candidate.description)
    if match:
        return match.group(1).strip()
    return None


async def run_mcp_enrichment_node(
    state: AnalysisState,
    runtime: Optional[Runtime[AnalysisRuntimeContext]] = None,
) -> Dict[str, Any]:
    """Execute deterministic MCP evidence enrichment for findings targeted for semantic revision.

    Guarantees:
    - Executes only when revision_target_ids are present.
    - Zero LLM model calls: tools are chosen deterministically based on finding category and evidence.
    - Enforces target budget (MAX_MCP_TARGETS_PER_REVISION).
    - Dispatches through MCPToolExecutor which consumes call budgets and bounds inputs/outputs.
    - Returns only new tool events to prevent operator.add duplication.
    - Normalizes evidence into serializable dictionaries safe for checkpointing.
    """
    executor: Optional[MCPToolExecutor] = None
    if runtime is not None and getattr(runtime, "context", None) is not None:
        executor = runtime.context.mcp_executor

    target_ids = list(state.get("revision_target_ids", []))
    if not target_ids or executor is None:
        logger.debug("Skipping MCP enrichment: target_ids=%s, executor_available=%s", bool(target_ids), executor is not None)
        return {
            "mcp_revision_evidence": {},
            "mcp_tool_events": [],
            "completed_nodes": ["mcp_enrich"],
        }

    targets = target_ids[:MAX_MCP_TARGETS_PER_REVISION]
    all_candidates = state.get("candidate_findings", [])
    candidate_map = {str(c.id): c for c in all_candidates}

    new_tool_events: List[Dict[str, Any]] = []
    revision_evidence: Dict[str, List[Dict[str, Any]]] = {}

    for target_id in targets:
        candidate = candidate_map.get(target_id)
        if not candidate:
            continue

        target_ev_list: List[Dict[str, Any]] = []
        evidence = candidate.evidences[0] if candidate.evidences else None
        category = str(candidate.category or "").lower()

        # Tool 1: Base Evidence Expansion (repo_read_file)
        if evidence and evidence.file_path:
            start_l = max(1, (evidence.start_line or 1) - 25)
            end_l = (evidence.end_line or start_l) + 25
            read_args = {
                "file_path": evidence.file_path,
                "start_line": start_l,
                "end_line": end_l,
            }
            ev_obj, rec = await executor.execute_tool("repo_read_file", target_id, read_args)
            new_tool_events.append(rec.model_dump())
            if ev_obj:
                target_ev_list.append(ev_obj.model_dump())

        # Tool 2: Category-Specific Targeted Tool
        if category == "architecture":
            sym = _extract_potential_symbol(candidate)
            if sym:
                ev_obj, rec = await executor.execute_tool(
                    "repo_get_related_symbols",
                    target_id,
                    {"symbol_name": sym, "file_path": evidence.file_path if evidence else None},
                )
            else:
                ev_obj, rec = await executor.execute_tool(
                    "repo_retrieve_context",
                    target_id,
                    {"query": f"{candidate.title} architecture structure", "analysis_intent": "architecture", "max_chunks": 3},
                )
            new_tool_events.append(rec.model_dump())
            if ev_obj:
                target_ev_list.append(ev_obj.model_dump())

        elif category == "integration":
            route = _extract_potential_route(candidate)
            if route:
                ev_obj, rec = await executor.execute_tool(
                    "repo_trace_contract",
                    target_id,
                    {"route_or_url": route},
                )
            else:
                ev_obj, rec = await executor.execute_tool(
                    "repo_retrieve_context",
                    target_id,
                    {"query": f"{candidate.title} contract integration", "analysis_intent": "integration", "max_chunks": 3},
                )
            new_tool_events.append(rec.model_dump())
            if ev_obj:
                target_ev_list.append(ev_obj.model_dump())

        elif category == "security":
            ev_obj, rec = await executor.execute_tool(
                "repo_get_static_findings",
                target_id,
                {"file_path": evidence.file_path if evidence else None, "category": "security"},
            )
            new_tool_events.append(rec.model_dump())
            if ev_obj:
                target_ev_list.append(ev_obj.model_dump())

        else:
            # Bug / Quality / General
            sym = _extract_potential_symbol(candidate)
            if sym:
                ev_obj, rec = await executor.execute_tool(
                    "repo_get_related_symbols",
                    target_id,
                    {"symbol_name": sym, "file_path": evidence.file_path if evidence else None},
                )
            else:
                ev_obj, rec = await executor.execute_tool(
                    "repo_retrieve_context",
                    target_id,
                    {"query": f"{candidate.title} defect logic", "analysis_intent": "bug", "max_chunks": 3},
                )
            new_tool_events.append(rec.model_dump())
            if ev_obj:
                target_ev_list.append(ev_obj.model_dump())

        if target_ev_list:
            revision_evidence[target_id] = target_ev_list

    return {
        "mcp_revision_evidence": revision_evidence,
        "mcp_tool_events": new_tool_events,
        "mcp_call_count": state.get("mcp_call_count", 0) + len(new_tool_events),
        "completed_nodes": ["mcp_enrich"],
    }
