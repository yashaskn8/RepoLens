"""Tests for Phase 3.5M: Truthful PostgreSQL pgvector support and InMemoryVectorIndex."""

import json
import os
from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy.engine import Engine

from app.retrieval.vector_index import (
    InMemoryVectorIndex,
    PgVectorIndex,
    cosine_similarity,
    create_vector_index,
)


# =============================================================================
# 1. InMemoryVectorIndex Zero-Dependency Tests
# =============================================================================

def test_in_memory_vector_index_basic_and_dimension_validation():
    """Verify InMemoryVectorIndex enforces dimensions and computes accurate cosine similarities."""
    index = InMemoryVectorIndex(dimensions=3, namespace="scan-1", model_name="test-model", index_version="v1")

    # Valid upsert
    index.upsert("c1", [1.0, 0.0, 0.0], metadata={"symbol": "login", "file": "auth.py"})
    index.upsert("c2", [0.0, 1.0, 0.0], metadata={"symbol": "logout", "file": "auth.py"})
    assert index.count() == 2

    # Dimension mismatch raises ValueError
    with pytest.raises(ValueError, match="Vector dimension mismatch"):
        index.upsert("bad", [1.0, 0.0])

    with pytest.raises(ValueError, match="Query vector dimension mismatch"):
        index.query([1.0, 0.0])

    # Query
    results = index.query([1.0, 0.0, 0.0], top_k=2)
    assert len(results) == 2
    assert results[0][0] == "c1"
    assert pytest.approx(results[0][1], rel=1e-3) == 1.0

    # Get
    item = index.get("c1")
    assert item is not None
    assert item["metadata"]["symbol"] == "login"
    assert item["namespace"] == "scan-1"

    # Batch upsert
    index.upsert_batch([
        ("c3", [0.707, 0.707, 0.0], {"symbol": "mixed"}),
        ("c4", [0.0, 0.0, 1.0], {"symbol": "other"}),
    ])
    assert index.count() == 4


def test_in_memory_vector_index_namespace_isolation():
    """Verify InMemoryVectorIndex isolates operations per namespace."""
    ns1 = InMemoryVectorIndex(dimensions=2, namespace="ns1")
    ns2 = InMemoryVectorIndex(dimensions=2, namespace="ns2")

    # Shared storage simulation
    ns2._entries = ns1._entries

    ns1.upsert("doc1", [1.0, 0.0], {"tag": "1"})
    ns2.upsert("doc2", [0.0, 1.0], {"tag": "2"})

    assert ns1.count() == 1
    assert ns2.count() == 1

    assert ns1.get("doc1") is not None
    assert ns1.get("doc2") is None
    assert ns2.get("doc2") is not None
    assert ns2.get("doc1") is None

    # Clear ns1 only deletes ns1 entries
    ns1.clear()
    assert ns1.count() == 0
    assert ns2.count() == 1
    assert ns2.get("doc2") is not None


# =============================================================================
# 2. PgVectorIndex Truthfulness and Mocked PostgreSQL Engine Tests
# =============================================================================

def test_pgvector_index_rejects_non_postgres_urls():
    """Verify PgVectorIndex strictly rejects SQLite or other non-PostgreSQL URLs."""
    with pytest.raises(ValueError, match="requires a PostgreSQL database URL"):
        PgVectorIndex(db_url="sqlite:///./test.db", dimensions=128)

    with pytest.raises(ValueError, match="requires a PostgreSQL database URL"):
        PgVectorIndex(db_url="mysql://user:pass@localhost/db", dimensions=128)


def test_pgvector_index_handles_missing_extension_error():
    """Verify that failure to create pgvector extension raises a clear RuntimeError."""
    mock_engine = MagicMock(spec=Engine)
    mock_conn = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    mock_conn.execute.side_effect = Exception("extension 'vector' is not available")

    with pytest.raises(RuntimeError, match="PostgreSQL pgvector extension is unavailable"):
        PgVectorIndex(
            db_url="postgresql://user:pass@localhost:5432/db",
            dimensions=128,
            engine=mock_engine,
        )


def test_pgvector_index_detects_namespace_compatibility_mismatch():
    """Verify PgVectorIndex verifies dimension, model_name, and index_version compatibility."""
    mock_engine = MagicMock(spec=Engine)
    mock_conn = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn

    # Mock checking existing namespace records: returns (dimensions=1024, model='old-model', version='v1')
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1024, "old-model", "v1")
    mock_conn.execute.return_value = mock_cursor

    # Attempting to initialize with dimensions=4096 must raise ValueError
    with pytest.raises(ValueError, match="compatibility mismatch"):
        PgVectorIndex(
            db_url="postgresql://user:pass@localhost:5432/db",
            dimensions=4096,
            model_name="new-model",
            index_version="v2",
            namespace="scan-123",
            engine=mock_engine,
        )


def test_pgvector_index_upsert_and_query_sql_generation():
    """Verify that PgVectorIndex executes correct SQL statements for upsert, query, get, count, and clear."""
    mock_engine = MagicMock(spec=Engine)
    mock_conn = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    mock_engine.connect.return_value.__enter__.return_value = mock_conn

    # Check compatibility fetch returns None (clean namespace)
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_conn.execute.return_value = mock_cursor

    pg_idx = PgVectorIndex(
        db_url="postgresql://user:pass@localhost:5432/testdb",
        dimensions=3,
        namespace="repo-scan-1",
        model_name="nv-embedcode-7b",
        index_version="v1",
        engine=mock_engine,
    )

    # 1. Test upsert
    pg_idx.upsert("chunk-abc", [0.1, 0.2, 0.3], metadata={"file": "main.py"})
    executed_sqls = [str(call[0][0]) for call in mock_conn.execute.call_args_list]
    assert any("INSERT INTO code_embeddings" in sql for sql in executed_sqls)
    assert any("ON CONFLICT (namespace, id) DO UPDATE" in sql for sql in executed_sqls)

    # 2. Test upsert dimension mismatch
    with pytest.raises(ValueError, match="Vector dimension mismatch"):
        pg_idx.upsert("bad-chunk", [0.1, 0.2])

    # 3. Test query execution
    mock_query_cursor = MagicMock()
    mock_query_cursor.fetchall.return_value = [("chunk-abc", 0.95)]
    mock_conn.execute.return_value = mock_query_cursor

    results = pg_idx.query([0.1, 0.2, 0.3], top_k=5)
    assert len(results) == 1
    assert results[0][0] == "chunk-abc"
    assert results[0][1] > 0.9

    # 4. Test clear only targets namespace
    pg_idx.clear()
    last_call = mock_conn.execute.call_args_list[-1]
    assert "DELETE FROM code_embeddings WHERE namespace = :namespace" in str(last_call[0][0])
    assert last_call[0][1]["namespace"] == "repo-scan-1"


def test_create_vector_index_factory_truthfulness():
    """Verify create_vector_index truthful selection between InMemory and PgVector."""
    # 1. SQLite / local dev default gives InMemoryVectorIndex
    local_idx = create_vector_index(db_url="sqlite:///./repolens.db", enable_pgvector=False)
    assert isinstance(local_idx, InMemoryVectorIndex)

    # 2. Explicit enable_pgvector on non-Postgres fails clearly
    with pytest.raises(ValueError, match="Cannot initialize PgVectorIndex"):
        create_vector_index(db_url="sqlite:///./repolens.db", enable_pgvector=True)

    # 3. Explicit enable_pgvector on PostgreSQL with missing driver raises clear RuntimeError
    with patch.dict("sys.modules", {"psycopg2": None, "psycopg": None, "asyncpg": None}):
        with pytest.raises(RuntimeError, match="PostgreSQL database driver is not installed|Failed to initialize PostgreSQL engine"):
            create_vector_index(
                db_url="postgresql://user:pass@localhost:5432/db",
                dimensions=1024,
                enable_pgvector=True,
            )

    # 4. Explicit enable_pgvector with supplied mock engine creates PgVectorIndex truthfully
    mock_engine = MagicMock(spec=Engine)
    with patch("app.retrieval.vector_index.PgVectorIndex._ensure_table_and_compatibility"):
        pg_idx = create_vector_index(
            db_url="postgresql://user:pass@localhost:5432/db",
            dimensions=1024,
            enable_pgvector=True,
            engine=mock_engine,
        )
        assert isinstance(pg_idx, PgVectorIndex)
        assert pg_idx.dimensions == 1024


# =============================================================================
# 3. Optional Integration Test for Real PostgreSQL Environments
# =============================================================================

@pytest.mark.integration
def test_pgvector_real_postgres_integration():
    """Integration test executed only when a real PostgreSQL database is explicitly provided."""
    pg_url = os.environ.get("PGVECTOR_TEST_URL")
    if not pg_url:
        pytest.skip("Skipping real PostgreSQL integration test: PGVECTOR_TEST_URL not set.")

    index = PgVectorIndex(
        db_url=pg_url,
        dimensions=3,
        namespace="integration-test",
        table_name="test_code_embeddings",
    )

    try:
        index.clear()
        index.upsert("c1", [1.0, 0.0, 0.0], {"test": True})
        index.upsert("c2", [0.0, 1.0, 0.0], {"test": True})
        assert index.count() == 2

        res = index.query([1.0, 0.0, 0.0], top_k=1)
        assert len(res) == 1
        assert res[0][0] == "c1"
    finally:
        index.clear()
