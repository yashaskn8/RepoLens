"""Integration specialist projecting deterministic route-contract facts."""

from typing import Any, Dict
from app.agents.helpers import safe_to_uuid
from app.agents.deterministic import contract_candidates
from app.agents.state import AnalysisState
from app.context.runtime import get_scan_context_engine


async def run_integration_agent(state: AnalysisState) -> Dict[str, Any]:
    """Analyze API contracts, frontend-backend alignment, and route consistency using targeted ContextBundle."""
    scan_id = safe_to_uuid(state["scan_id"])
    context_engine = state.get("context_engine") or get_scan_context_engine(str(scan_id))
    frontend_calls = state.get("frontend_calls", [])


    if not frontend_calls:
        return {
            "candidate_findings": [],
            "completed_nodes": ["integration"],
            "model_executions": [],
            "errors": [],
        }

    matches = []
    if context_engine:
        bundle = await context_engine.build_context_bundle(
            scan_id=str(scan_id),
            query="API endpoints client fetch axios route contract",
            analysis_intent="integration",
            context_budget=5_500,
            max_chunks=8,
        )
        matches = bundle.routes_and_contracts
    candidate_findings = contract_candidates(matches, scan_id=scan_id)

    return {
        "candidate_findings": candidate_findings,
        "completed_nodes": ["integration"],
        "model_executions": [],
        "errors": [],
    }
