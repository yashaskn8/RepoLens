"""Typed LangGraph shared state for multi-agent repository analysis workflow."""

import operator
from typing import Annotated, Any, Dict, List, Optional
from typing_extensions import TypedDict

from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata


def merge_cloud_budget(
    left: Dict[str, Any] | None,
    right: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Reducer that keeps monotonic usage when specialists finish together."""
    left = dict(left or {})
    right = dict(right or {})
    merged = {**left, **right}
    def _counter(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0
    for key in ("used_cloud_calls", "used_cloud_tokens"):
        if key in left or key in right:
            merged[key] = max(_counter(left.get(key)), _counter(right.get(key)))
    for key in ("max_cloud_calls", "max_cloud_tokens"):
        if key in left and key in right:
            merged[key] = min(_counter(left.get(key)), _counter(right.get(key)))
        elif key in left or key in right:
            merged[key] = _counter(left.get(key) if key in left else right.get(key))
    merged["exhausted"] = bool(left.get("exhausted") or right.get("exhausted"))
    return merged


class AnalysisState(TypedDict, total=False):
    """Explicit shared state schema for the LangGraph multi-agent analysis workflow.

    Strictly keeps large source code and runtime service objects out of state;
    stores identifiers, metadata, structured finding representations, and bounded
    orchestration tracking for safe SQLite / InMemory checkpoint persistence.
    """

    scan_id: str
    repository_url: str
    commit_hash: str
    branch: Optional[str]
    repo_dir: str

    # Structural facts populated by Repository Mapper
    manifest_summary: Dict[str, Any]
    languages: Dict[str, int]
    frameworks: List[str]
    architecture_overview: Optional[str]
    routes: List[Dict[str, Any]]
    frontend_calls: List[Dict[str, Any]]
    static_findings: List[Dict[str, Any]]
    graph_coverage: Dict[str, Any]
    deterministic_correctness_candidates: List[Dict[str, Any]]
    deterministic_security_flow_candidates: List[Dict[str, Any]]
    deterministic_architecture_candidates: List[Dict[str, Any]]
    route_contract_coverage: Dict[str, Any]
    source_evidence_available: bool
    tool_coverage: Dict[str, Any]

    # Deterministic admission decisions for specialist model work.
    ai_admission: Dict[str, Dict[str, Any]]
    ai_cloud_budget: Annotated[Dict[str, Any], merge_cloud_budget]

    # Candidate findings aggregated from parallel specialists (uses operator.add for fan-in)
    candidate_findings: Annotated[List[Finding], operator.add]

    # Bounded semantic revision candidates (no reducer - replaced on revision pass)
    revision_candidates: List[Finding]

    # Grounded findings verified by Verifier agent
    verified_findings: List[Finding]
    rejected_findings: List[Dict[str, Any]]

    # Bounded orchestration tracking
    revision_count: int
    verification_decision: Optional[str]
    revision_target_ids: List[str]

    # Runtime MCP enrichment tracking (serializable dicts, never runtime objects)
    mcp_revision_evidence: Dict[str, List[Dict[str, Any]]]
    mcp_tool_events: Annotated[List[Dict[str, Any]], operator.add]
    mcp_call_count: int

    # Checkpoint execution tracking
    completed_nodes: Annotated[List[str], operator.add]

    # Observability & telemetry
    model_executions: Annotated[List[ModelExecutionMetadata], operator.add]
    errors: Annotated[List[str], operator.add]
    status: str
