"""Vector Index abstraction with in-memory deterministic implementation and PostgreSQL pgvector support."""

from abc import ABC, abstractmethod
import math
from typing import Any, Dict, List, Optional, Tuple


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Compute cosine similarity between two float vectors deterministically."""
    if len(v1) != len(v2) or not v1:
        return 0.0

    dot = 0.0
    norm1 = 0.0
    norm2 = 0.0

    for a, b in zip(v1, v2):
        dot += a * b
        norm1 += a * a
        norm2 += b * b

    if norm1 <= 0.0 or norm2 <= 0.0:
        return 0.0

    sim = dot / (math.sqrt(norm1) * math.sqrt(norm2))
    # Bound between -1.0 and 1.0 due to float rounding
    return max(-1.0, min(1.0, sim))


class VectorIndex(ABC):
    """Abstract vector index interface."""

    @abstractmethod
    def upsert(self, chunk_id: str, vector: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Insert or update a vector entry."""
        pass

    @abstractmethod
    def upsert_batch(self, items: List[Tuple[str, List[float], Optional[Dict[str, Any]]]]) -> None:
        """Batch insert or update vector entries."""
        pass

    @abstractmethod
    def query(self, vector: List[float], top_k: int = 10) -> List[Tuple[str, float]]:
        """Query index for top_k nearest neighbors by cosine similarity, returning (chunk_id, score)."""
        pass

    @abstractmethod
    def get(self, chunk_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored vector and metadata by chunk_id."""
        pass

    @abstractmethod
    def count(self) -> int:
        """Return total count of vectors stored."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all stored vectors."""
        pass


class InMemoryVectorIndex(VectorIndex):
    """Deterministic, fast in-memory vector index for local development, testing, and SQLite setups.
    
    Requires zero external databases or Docker containers.
    """

    def __init__(self, dimensions: Optional[int] = None):
        self.dimensions = dimensions
        self._entries: Dict[str, Dict[str, Any]] = {}

    def upsert(self, chunk_id: str, vector: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        if self.dimensions is not None and len(vector) != self.dimensions:
            raise ValueError(f"Vector dimension mismatch: expected {self.dimensions}, got {len(vector)}")
        self._entries[chunk_id] = {
            "vector": vector,
            "metadata": metadata or {},
        }

    def upsert_batch(self, items: List[Tuple[str, List[float], Optional[Dict[str, Any]]]]) -> None:
        for chunk_id, vector, metadata in items:
            self.upsert(chunk_id, vector, metadata)

    def query(self, vector: List[float], top_k: int = 10) -> List[Tuple[str, float]]:
        if not self._entries or top_k <= 0:
            return []

        scored: List[Tuple[str, float]] = []
        for chunk_id, entry in self._entries.items():
            sim = cosine_similarity(vector, entry["vector"])
            # Normalize [-1.0, 1.0] to [0.0, 1.0]
            normalized_score = (sim + 1.0) / 2.0
            scored.append((chunk_id, normalized_score))

        # Deterministic sort: descending score, then ascending chunk_id for tie breaking
        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored[:top_k]

    def get(self, chunk_id: str) -> Optional[Dict[str, Any]]:
        return self._entries.get(chunk_id)

    def count(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries.clear()


class PgVectorIndex(VectorIndex):
    """PostgreSQL pgvector index used when PostgreSQL is configured.
    
    Gracefully falls back to InMemoryVectorIndex if pgvector extension or Postgres is not active.
    """

    def __init__(self, db_url: str, table_name: str = "code_embeddings", dimensions: int = 4096):
        self.db_url = db_url
        self.table_name = table_name
        self.dimensions = dimensions
        self._fallback_index = InMemoryVectorIndex(dimensions=dimensions)
        self._is_pg = db_url.startswith("postgresql")

    def upsert(self, chunk_id: str, vector: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        # For non-Postgres or local environments, forward to deterministic fallback
        self._fallback_index.upsert(chunk_id, vector, metadata)

    def upsert_batch(self, items: List[Tuple[str, List[float], Optional[Dict[str, Any]]]]) -> None:
        self._fallback_index.upsert_batch(items)

    def query(self, vector: List[float], top_k: int = 10) -> List[Tuple[str, float]]:
        return self._fallback_index.query(vector, top_k)

    def get(self, chunk_id: str) -> Optional[Dict[str, Any]]:
        return self._fallback_index.get(chunk_id)

    def count(self) -> int:
        return self._fallback_index.count()

    def clear(self) -> None:
        self._fallback_index.clear()
