"""Hybrid repository retrieval package for RepoLens."""

from app.retrieval.fusion import reciprocal_rank_fusion
from app.retrieval.reranker import QwenReranker
from app.retrieval.schemas import (
    RerankCandidate,
    RetrievalChannel,
    RetrievalQuery,
    RetrievalResult,
)
from app.retrieval.service import RetrievalService
from app.retrieval.vector_index import (
    InMemoryVectorIndex,
    PgVectorIndex,
    VectorIndex,
    cosine_similarity,
    create_vector_index,
)

__all__ = [
    "RetrievalChannel",
    "RetrievalQuery",
    "RetrievalResult",
    "RerankCandidate",
    "VectorIndex",
    "InMemoryVectorIndex",
    "PgVectorIndex",
    "create_vector_index",
    "cosine_similarity",
    "reciprocal_rank_fusion",
    "QwenReranker",
    "RetrievalService",
]
