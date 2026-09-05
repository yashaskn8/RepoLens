"""Vector Index abstraction with in-memory deterministic implementation and real PostgreSQL pgvector support."""

from abc import ABC, abstractmethod
import json
import logging
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Compute cosine similarity between two float vectors deterministically.

    Returns 0.0 for degenerate inputs: mismatched dimensions, empty vectors,
    zero-norm vectors, or vectors containing NaN/Inf values.
    """
    if len(v1) != len(v2) or not v1:
        return 0.0

    dot = 0.0
    norm1 = 0.0
    norm2 = 0.0

    for a, b in zip(v1, v2):
        if not math.isfinite(a) or not math.isfinite(b):
            return 0.0
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
        """Return total count of vectors stored in this index namespace."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear stored vectors in this index namespace."""
        pass


class InMemoryVectorIndex(VectorIndex):
    """Deterministic, fast in-memory vector index for local development, testing, and SQLite setups.
    
    Requires zero external databases or Docker containers.
    """

    def __init__(
        self,
        dimensions: Optional[int] = None,
        namespace: str = "default",
        model_name: str = "default-embedding",
        index_version: str = "v1",
    ):
        self.dimensions = dimensions
        self.namespace = namespace
        self.model_name = model_name
        self.index_version = index_version
        self._entries: Dict[str, Dict[str, Any]] = {}

    def upsert(self, chunk_id: str, vector: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        if self.dimensions is not None and len(vector) != self.dimensions:
            raise ValueError(f"Vector dimension mismatch: expected {self.dimensions}, got {len(vector)}")
        self._entries[chunk_id] = {
            "vector": vector,
            "metadata": metadata or {},
            "namespace": self.namespace,
            "model_name": self.model_name,
            "index_version": self.index_version,
        }

    def upsert_batch(self, items: List[Tuple[str, List[float], Optional[Dict[str, Any]]]]) -> None:
        for chunk_id, vector, metadata in items:
            self.upsert(chunk_id, vector, metadata)

    def query(self, vector: List[float], top_k: int = 10) -> List[Tuple[str, float]]:
        if self.dimensions is not None and len(vector) != self.dimensions:
            raise ValueError(f"Query vector dimension mismatch: expected {self.dimensions}, got {len(vector)}")
        if not self._entries or top_k <= 0:
            return []

        scored: List[Tuple[str, float]] = []
        for chunk_id, entry in self._entries.items():
            if entry.get("namespace", "default") != self.namespace:
                continue
            sim = cosine_similarity(vector, entry["vector"])
            # Normalize [-1.0, 1.0] to [0.0, 1.0]
            normalized_score = (sim + 1.0) / 2.0
            scored.append((chunk_id, normalized_score))

        # Deterministic sort: descending score, then ascending chunk_id for tie breaking
        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored[:top_k]

    def get(self, chunk_id: str) -> Optional[Dict[str, Any]]:
        entry = self._entries.get(chunk_id)
        if entry and entry.get("namespace", "default") == self.namespace:
            return entry
        return None

    def count(self) -> int:
        return sum(1 for e in self._entries.values() if e.get("namespace", "default") == self.namespace)

    def clear(self) -> None:
        to_delete = [k for k, v in self._entries.items() if v.get("namespace", "default") == self.namespace]
        for k in to_delete:
            del self._entries[k]


class PgVectorIndex(VectorIndex):
    """Real PostgreSQL pgvector implementation for persistent vector storage and cosine similarity search.
    
    Operates against a PostgreSQL database with pgvector extension enabled.
    Enforces dimensions, model_name, and index_version compatibility on storage and queries.
    Confines operations strictly to the specified namespace.
    """

    def __init__(
        self,
        db_url: str,
        dimensions: int = 4096,
        table_name: str = "code_embeddings",
        namespace: str = "default",
        model_name: str = "text-embedding-3-large",
        index_version: str = "v1",
        engine: Optional[Engine] = None,
        auto_create_table: bool = True,
        statement_timeout_ms: int = 5_000,
        lock_timeout_ms: int = 2_000,
    ):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", table_name):
            raise ValueError("PgVectorIndex table_name must be a safe PostgreSQL identifier")
        if not namespace or len(namespace.encode("utf-8")) > 128:
            raise ValueError("PgVectorIndex namespace must be 1-128 UTF-8 bytes")
        if dimensions <= 0 or dimensions > 16_000:
            raise ValueError("PgVectorIndex dimensions must be between 1 and 16000")
        self.statement_timeout_ms = max(100, min(int(statement_timeout_ms), 300_000))
        self.lock_timeout_ms = max(100, min(int(lock_timeout_ms), 60_000))
        if not engine:
            normalized_url = str(db_url).lower()
            if not (
                normalized_url.startswith("postgresql")
                or normalized_url.startswith("postgres")
            ):
                raise ValueError(
                    f"PgVectorIndex requires a PostgreSQL database URL (e.g. 'postgresql://...'), but received: '{db_url}'"
                )
            try:
                driver_url = db_url
                if driver_url.startswith("postgresql://"):
                    driver_url = "postgresql+psycopg://" + driver_url.removeprefix("postgresql://")
                elif driver_url.startswith("postgres://"):
                    driver_url = "postgresql+psycopg://" + driver_url.removeprefix("postgres://")
                self.engine = create_engine(driver_url, pool_pre_ping=True, pool_timeout=5)
            except (ModuleNotFoundError, ImportError) as exc:
                raise RuntimeError(
                    f"PostgreSQL database driver is not installed: {str(exc)}. Please install psycopg or psycopg2."
                ) from exc
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to initialize PostgreSQL engine for '{db_url}': {str(exc)}"
                ) from exc
        else:
            self.engine = engine

        self.db_url = db_url
        self.dimensions = dimensions
        self.table_name = table_name
        self.namespace = namespace
        self.model_name = model_name
        self.index_version = index_version

        if auto_create_table:
            self._ensure_table_and_compatibility()

    def _apply_budgets(self, conn, *, writes: bool = False) -> None:
        conn.execute(text("SELECT set_config('statement_timeout', :budget, true)"),
                     {"budget": f"{self.statement_timeout_ms}ms"})
        if writes:
            conn.execute(text("SELECT set_config('lock_timeout', :budget, true)"),
                         {"budget": f"{self.lock_timeout_ms}ms"})

    @staticmethod
    def _validate_chunk_id(chunk_id: str) -> None:
        if not chunk_id or len(chunk_id.encode("utf-8")) > 256:
            raise ValueError("PgVectorIndex chunk_id must be 1-256 UTF-8 bytes")

    def _ensure_table_and_compatibility(self) -> None:
        """Verify pgvector extension, create table and index if needed, and verify namespace compatibility."""
        with self.engine.begin() as conn:
            # 1. Verify extension
            try:
                self._apply_budgets(conn, writes=True)
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
            except Exception as exc:
                raise RuntimeError(
                    f"PostgreSQL pgvector extension is unavailable or could not be loaded: {str(exc)}"
                ) from exc

            # 2. Verify / Create table
            create_sql = f"""
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                id VARCHAR(256) NOT NULL,
                namespace VARCHAR(128) NOT NULL,
                dimensions INTEGER NOT NULL,
                model_name VARCHAR(128) NOT NULL,
                index_version VARCHAR(32) NOT NULL,
                embedding vector({self.dimensions}),
                metadata JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, id)
            );
            """
            conn.execute(text(create_sql))
            conn.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{self.table_name}_namespace ON {self.table_name} (namespace)"))
            # A dimension-specific expression index keeps mixed embedding
            # namespaces compatible while giving each configured dimension an
            # ANN path. Older pgvector installations degrade to exact search.
            try:
                with conn.begin_nested():
                    conn.execute(text(
                        f"CREATE INDEX IF NOT EXISTS ix_{self.table_name}_cosine_{self.dimensions} "
                        f"ON {self.table_name} USING hnsw ((embedding::vector({self.dimensions})) vector_cosine_ops) "
                        f"WHERE dimensions = {self.dimensions}"
                    ))
            except Exception:
                logger.warning("pgvector HNSW index unavailable; bounded exact search remains active")

            # 3. Check namespace compatibility if records already exist
            check_sql = f"""
            SELECT dimensions, model_name, index_version
            FROM {self.table_name}
            WHERE namespace = :namespace
            LIMIT 1;
            """
            row = conn.execute(text(check_sql), {"namespace": self.namespace}).fetchone()
            if row:
                row_dims, row_model, row_version = row[0], row[1], row[2]
                if (
                    row_dims != self.dimensions
                    or row_model != self.model_name
                    or row_version != self.index_version
                ):
                    raise ValueError(
                        f"PgVectorIndex compatibility mismatch for namespace '{self.namespace}': "
                        f"existing records use dimensions={row_dims}, model='{row_model}', version='{row_version}', "
                        f"but initialized with dimensions={self.dimensions}, model='{self.model_name}', version='{self.index_version}'."
                    )

    def _format_vector(self, vector: List[float]) -> str:
        """Format Python float list into pgvector string representation: '[0.1, 0.2, ...]'."""
        return f"[{','.join(str(float(x)) for x in vector)}]"

    def upsert(self, chunk_id: str, vector: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        self._validate_chunk_id(chunk_id)
        if len(vector) != self.dimensions:
            raise ValueError(f"Vector dimension mismatch: expected {self.dimensions}, got {len(vector)}")

        upsert_sql = f"""
        INSERT INTO {self.table_name} (id, namespace, dimensions, model_name, index_version, embedding, metadata, updated_at)
        VALUES (:id, :namespace, :dimensions, :model_name, :index_version, CAST(:embedding AS vector), CAST(:metadata AS jsonb), CURRENT_TIMESTAMP)
        ON CONFLICT (namespace, id) DO UPDATE SET
            embedding = EXCLUDED.embedding,
            metadata = EXCLUDED.metadata,
            dimensions = EXCLUDED.dimensions,
            model_name = EXCLUDED.model_name,
            index_version = EXCLUDED.index_version,
            updated_at = CURRENT_TIMESTAMP;
        """
        params = {
            "id": chunk_id,
            "namespace": self.namespace,
            "dimensions": self.dimensions,
            "model_name": self.model_name,
            "index_version": self.index_version,
            "embedding": self._format_vector(vector),
            "metadata": json.dumps(metadata or {}),
        }
        with self.engine.begin() as conn:
            self._apply_budgets(conn, writes=True)
            conn.execute(text(upsert_sql), params)

    def upsert_batch(self, items: List[Tuple[str, List[float], Optional[Dict[str, Any]]]]) -> None:
        if not items:
            return

        for chunk_id, vector, _ in items:
            self._validate_chunk_id(chunk_id)
            if len(vector) != self.dimensions:
                raise ValueError(f"Vector dimension mismatch for '{chunk_id}': expected {self.dimensions}, got {len(vector)}")

        upsert_sql = f"""
        INSERT INTO {self.table_name} (id, namespace, dimensions, model_name, index_version, embedding, metadata, updated_at)
        VALUES (:id, :namespace, :dimensions, :model_name, :index_version, CAST(:embedding AS vector), CAST(:metadata AS jsonb), CURRENT_TIMESTAMP)
        ON CONFLICT (namespace, id) DO UPDATE SET
            embedding = EXCLUDED.embedding,
            metadata = EXCLUDED.metadata,
            dimensions = EXCLUDED.dimensions,
            model_name = EXCLUDED.model_name,
            index_version = EXCLUDED.index_version,
            updated_at = CURRENT_TIMESTAMP;
        """
        param_list = [
            {
                "id": chunk_id,
                "namespace": self.namespace,
                "dimensions": self.dimensions,
                "model_name": self.model_name,
                "index_version": self.index_version,
                "embedding": self._format_vector(vec),
                "metadata": json.dumps(meta or {}),
            }
            for chunk_id, vec, meta in items
        ]

        with self.engine.begin() as conn:
            self._apply_budgets(conn, writes=True)
            conn.execute(text(upsert_sql), param_list)

    def query(self, vector: List[float], top_k: int = 10) -> List[Tuple[str, float]]:
        if len(vector) != self.dimensions:
            raise ValueError(f"Query vector dimension mismatch: expected {self.dimensions}, got {len(vector)}")
        if top_k <= 0:
            return []

        # Cosine distance in pgvector is `<=>`.
        # Cosine similarity = 1.0 - distance.
        query_sql = f"""
        SELECT id, 1.0 - (embedding::vector({self.dimensions}) <=> CAST(:query_vec AS vector({self.dimensions}))) AS raw_sim
        FROM {self.table_name}
        WHERE namespace = :namespace AND dimensions = :dimensions
          AND model_name = :model_name AND index_version = :index_version
        ORDER BY embedding::vector({self.dimensions}) <=> CAST(:query_vec AS vector({self.dimensions})) ASC
        LIMIT :top_k;
        """
        params = {
            "query_vec": self._format_vector(vector),
            "namespace": self.namespace,
            "top_k": top_k,
            "dimensions": self.dimensions,
            "model_name": self.model_name,
            "index_version": self.index_version,
        }

        with self.engine.begin() as conn:
            self._apply_budgets(conn)
            rows = conn.execute(text(query_sql), params).fetchall()

        results: List[Tuple[str, float]] = []
        for row in rows:
            chunk_id = str(row[0])
            raw_sim = float(row[1]) if row[1] is not None else 0.0
            # Normalize [-1.0, 1.0] to [0.0, 1.0]
            norm_sim = max(0.0, min(1.0, (raw_sim + 1.0) / 2.0))
            results.append((chunk_id, norm_sim))

        return results

    def get(self, chunk_id: str) -> Optional[Dict[str, Any]]:
        self._validate_chunk_id(chunk_id)
        get_sql = f"""
        SELECT id, embedding, metadata, dimensions, model_name, index_version
        FROM {self.table_name}
        WHERE namespace = :namespace AND id = :id;
        """
        params = {"namespace": self.namespace, "id": chunk_id}

        with self.engine.begin() as conn:
            self._apply_budgets(conn)
            row = conn.execute(text(get_sql), params).fetchone()

        if not row:
            return None

        emb_raw = row[1]
        emb_list: List[float] = []
        if isinstance(emb_raw, list):
            emb_list = [float(x) for x in emb_raw]
        elif isinstance(emb_raw, str):
            cleaned = emb_raw.strip("[]")
            if cleaned:
                emb_list = [float(x.strip()) for x in cleaned.split(",") if x.strip()]
        elif hasattr(emb_raw, "tolist"):
            emb_list = [float(x) for x in emb_raw.tolist()]
        elif isinstance(emb_raw, tuple):
            emb_list = [float(x) for x in emb_raw]

        meta = row[2] if isinstance(row[2], dict) else (json.loads(row[2]) if row[2] else {})

        return {
            "id": row[0],
            "vector": emb_list,
            "metadata": meta,
            "dimensions": row[3],
            "model_name": row[4],
            "index_version": row[5],
            "namespace": self.namespace,
        }

    def count(self) -> int:
        count_sql = f"SELECT COUNT(*) FROM {self.table_name} WHERE namespace = :namespace;"
        with self.engine.begin() as conn:
            self._apply_budgets(conn)
            val = conn.execute(text(count_sql), {"namespace": self.namespace}).scalar()
            return int(val or 0)

    def clear(self) -> None:
        """Clear vectors only within this index's namespace."""
        delete_sql = f"DELETE FROM {self.table_name} WHERE namespace = :namespace;"
        with self.engine.begin() as conn:
            self._apply_budgets(conn, writes=True)
            conn.execute(text(delete_sql), {"namespace": self.namespace})


def create_vector_index(
    db_url: Optional[str] = None,
    dimensions: Optional[int] = 4096,
    namespace: str = "default",
    model_name: str = "text-embedding-3-large",
    index_version: str = "v1",
    enable_pgvector: bool = False,
    engine: Optional[Engine] = None,
) -> VectorIndex:
    """Truthful VectorIndex factory.
    
    - Defaults to InMemoryVectorIndex (zero-dependency, fast local execution).
    - If enable_pgvector is True and db_url is PostgreSQL, initializes real PgVectorIndex.
    - If enable_pgvector is True but db_url is not PostgreSQL, raises ValueError explicitly.
    """
    if enable_pgvector:
        target_url = db_url or ""
        norm_url = target_url.lower()
        if not (norm_url.startswith("postgresql") or norm_url.startswith("postgres")):
            raise ValueError(
                f"Cannot initialize PgVectorIndex: configured database URL '{target_url}' is not PostgreSQL."
            )
        return PgVectorIndex(
            db_url=target_url,
            dimensions=dimensions or 4096,
            namespace=namespace,
            model_name=model_name,
            index_version=index_version,
            engine=engine,
        )

    return InMemoryVectorIndex(
        dimensions=dimensions,
        namespace=namespace,
        model_name=model_name,
        index_version=index_version,
    )
