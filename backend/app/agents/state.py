"""Typed LangGraph shared state for multi-agent repository analysis workflow."""

import operator
from typing import Annotated, Any, Dict, List, Optional
from typing_extensions import TypedDict

from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata


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

    # Checkpoint execution tracking
    completed_nodes: Annotated[List[str], operator.add]

    # Observability & telemetry
    model_executions: Annotated[List[ModelExecutionMetadata], operator.add]
    errors: Annotated[List[str], operator.add]
    status: str
