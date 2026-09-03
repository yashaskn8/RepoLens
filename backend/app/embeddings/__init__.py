"""Local Embeddings package — Sentence Transformers backend.

Re-exports the public API surface for convenience::

    from app.embeddings import LocalEmbeddingService, LocalEmbeddingAdapter
"""

from app.embeddings.adapter import LocalEmbeddingAdapter
from app.embeddings.constants import (
    DEFAULT_LOCAL_EMBEDDING_DEVICE,
    DEFAULT_LOCAL_EMBEDDING_MODEL,
    MAX_LOCAL_EMBEDDING_BATCH_SIZE,
    MAX_LOCAL_EMBEDDING_TEXT_CHARS,
)
from app.embeddings.service import LocalEmbeddingError, LocalEmbeddingService

__all__ = [
    "LocalEmbeddingAdapter",
    "LocalEmbeddingError",
    "LocalEmbeddingService",
    "DEFAULT_LOCAL_EMBEDDING_DEVICE",
    "DEFAULT_LOCAL_EMBEDDING_MODEL",
    "MAX_LOCAL_EMBEDDING_BATCH_SIZE",
    "MAX_LOCAL_EMBEDDING_TEXT_CHARS",
]
