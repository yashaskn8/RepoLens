"""Canonical schemas for hybrid repository retrieval."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.indexing.schemas import CodeChunk


class RetrievalChannel(str, Enum):
    """Channels contributing to hybrid retrieval."""

    EXACT = "exact"
    LEXICAL = "lexical"
    DENSE = "dense"
    GRAPH = "graph"


class RetrievalQuery(BaseModel):
    """Query parameter payload for RetrievalService."""

    query: str = Field(..., min_length=1, description="Natural language or code search query")
    top_k: int = Field(default=10, ge=1, le=100, description="Maximum number of fused results to return")
    use_reranker: bool = Field(default=True, description="Whether to apply neural reranking if available")
    file_path_filter: Optional[str] = Field(default=None, description="Optional path substring filter")
    symbol_kind_filter: Optional[str] = Field(default=None, description="Optional symbol kind filter")


class RetrievalResult(BaseModel):
    """Single evidence-backed code retrieval result with provenance and channel tracing."""

    chunk_id: str = Field(..., description="Unique deterministic chunk identifier")
    score: float = Field(..., description="Normalized fused retrieval score")
    source_channels: List[RetrievalChannel] = Field(default_factory=list, description="Channels that identified this chunk")
    chunk: CodeChunk = Field(..., description="Canonical source code chunk payload")
    reranked_score: Optional[float] = Field(default=None, description="Neural reranker score if reranking succeeded")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Full repository origin and line provenance")


class RerankCandidate(BaseModel):
    """Candidate chunk passed to the neural cross-encoder reranker."""

    chunk_id: str
    content: str
    initial_score: float
