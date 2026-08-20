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
