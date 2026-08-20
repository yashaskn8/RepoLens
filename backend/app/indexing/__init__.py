"""Symbol-aware semantic code indexing package for RepoLens."""

from app.indexing.chunker import chunk_file, chunk_manifest
from app.indexing.embeddings import (
    EmbeddingProvider,
    HuggingFaceEmbeddingAdapter,
    NvidiaEmbeddingAdapter,
)
from app.indexing.schemas import (
    ChunkSymbolKind,
    CodeChunk,
    EmbeddingIndexMetadata,
    EmbeddingRequest,
    EmbeddingResponse,
    EmbeddingResult,
    INDEX_VERSION,
    content_hash,
)

__all__ = [
    "ChunkSymbolKind",
    "CodeChunk",
    "EmbeddingIndexMetadata",
    "EmbeddingProvider",
    "EmbeddingRequest",
    "EmbeddingResponse",
    "EmbeddingResult",
    "HuggingFaceEmbeddingAdapter",
    "INDEX_VERSION",
    "NvidiaEmbeddingAdapter",
    "chunk_file",
    "chunk_manifest",
    "content_hash",
]
