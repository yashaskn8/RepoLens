"""Canonical schemas for evidence-grounded Context Engine."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.analysis.schemas import StaticFinding
from app.graph.schemas import GraphEdge, RouteContractMatch
from app.retrieval.schemas import RetrievalResult


class ContextBundle(BaseModel):
    """Targeted, evidence-grounded context bundle assembled for agent reasoning."""

    scan_id: str = Field(..., description="Scan identifier")
    query: str = Field(..., description="Targeted retrieval query that generated this bundle")
    analysis_intent: str = Field(..., description="Agent specialist role or analysis intent")
    relevant_chunks: List[RetrievalResult] = Field(default_factory=list, description="Targeted source code chunks")
    graph_relationships: List[GraphEdge] = Field(default_factory=list, description="Relevant relationship graph edges")
    routes_and_contracts: List[RouteContractMatch] = Field(default_factory=list, description="Relevant route contract matches")
    static_findings: List[StaticFinding] = Field(default_factory=list, description="Relevant deterministic scanner findings")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Context bundle origin and budget telemetry")
    retrieval_scores: Dict[str, float] = Field(default_factory=dict, description="Retrieval score per chunk ID")
    estimated_tokens: int = Field(default=0, ge=0, description="Approximate token count of bundle content")


class EvidenceSlice(BaseModel):
    """Bounded, commit-bound hypothesis context referencing canonical evidence IDs."""

    schema_version: str = "evidence-slice/1.0"
    scan_id: str
    commit_sha: str
    candidate_id: str
    candidate_kind: str
    deterministic_reason: str
    strength: str
    primary_evidence_refs: List[str] = Field(default_factory=list, max_length=6)
    supporting_evidence_refs: List[str] = Field(default_factory=list, max_length=6)
    counter_evidence_refs: List[str] = Field(default_factory=list, max_length=4)
    graph_evidence_refs: List[str] = Field(default_factory=list, max_length=20)
    contract_evidence_refs: List[str] = Field(default_factory=list, max_length=8)
    scanner_evidence_refs: List[str] = Field(default_factory=list, max_length=10)
    candidate_metadata: Dict[str, Any] = Field(default_factory=dict)
    bounds: Dict[str, int] = Field(default_factory=dict)
