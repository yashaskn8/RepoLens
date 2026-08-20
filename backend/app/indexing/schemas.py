"""Canonical schemas for symbol-aware semantic code indexing."""

import hashlib
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


INDEX_VERSION: int = 1
"""Monotonically increasing version; bump when chunking logic changes."""


class ChunkSymbolKind(str, Enum):
    """Kind of symbol a code chunk represents."""

    FUNCTION = "FUNCTION"
    CLASS = "CLASS"
    METHOD = "METHOD"
    ROUTE = "ROUTE"
    FILE = "FILE"  # Bounded file-level fallback


def content_hash(content: str) -> str:
    """Deterministic SHA-256 hex digest of chunk content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class CodeChunk(BaseModel):
    """A single code chunk for embedding and retrieval.

    Chunks are generated primarily from Tree-sitter symbols
    (functions, classes, methods, routes). A bounded file-level
    fallback is used only when no useful symbol exists in a file.
    """

    chunk_id: str = Field(..., description="Deterministic unique identifier")
    commit_sha: str = Field(..., description="Repository commit SHA this chunk was extracted from")
    file_path: str = Field(..., description="Relative file path within the repository")
    language: Optional[str] = Field(default=None, description="Programming language")
    symbol: str = Field(..., description="Symbol name or file basename for file-level chunks")
    symbol_kind: ChunkSymbolKind = Field(..., description="Kind of symbol this chunk represents")
    start_line: int = Field(..., ge=1, description="Start line in file (1-indexed)")
    end_line: int = Field(..., ge=1, description="End line in file (1-indexed)")
    content: str = Field(..., description="Source code content of the chunk")
    content_hash: str = Field(..., description="SHA-256 hash of content for change detection")
    index_version: int = Field(default=INDEX_VERSION, description="Chunking logic version")


class EmbeddingRequest(BaseModel):
    """Request payload for an embedding provider."""

    texts: List[str] = Field(..., min_length=1, description="Texts to embed")
    input_type: str = Field(..., description="'passage' for indexing, 'query' for retrieval")
    model: str = Field(..., description="Embedding model identifier")


class EmbeddingResult(BaseModel):
    """Single embedding vector with metadata."""

    index: int = Field(..., ge=0, description="Position in the request batch")
    vector: List[float] = Field(..., description="Embedding vector")
    dimensions: int = Field(..., ge=1, description="Dimensionality of the vector")


class EmbeddingResponse(BaseModel):
    """Response from an embedding provider."""

    embeddings: List[EmbeddingResult] = Field(default_factory=list)
    model: str = Field(..., description="Model that produced these embeddings")
    provider: str = Field(..., description="Provider name")
    dimensions: int = Field(..., ge=1, description="Vector dimensions")
    total_tokens: Optional[int] = Field(default=None, description="Total tokens consumed")


class EmbeddingIndexMetadata(BaseModel):
    """Persisted metadata for a logical embedding index.

    Ensures vectors from different models or dimensions
    are never mixed in one logical index.
    """

    model: str = Field(..., description="Embedding model that produced vectors")
    provider: str = Field(..., description="Provider name")
    dimensions: int = Field(..., ge=1, description="Vector dimensionality")
    index_version: int = Field(default=INDEX_VERSION, description="Chunking logic version")
    total_chunks: int = Field(default=0, ge=0)
