"""Deterministic unit and integration tests for Phase 2C hybrid repository retrieval."""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.indexing.schemas import ChunkSymbolKind, CodeChunk, INDEX_VERSION, content_hash
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
    cosine_similarity,
    create_vector_index,
)


# =========================================================================
# 1. Cosine Similarity and VectorIndex Tests
# =========================================================================

def test_cosine_similarity_edge_cases():
    """Verify deterministic mathematical properties of cosine similarity."""
    # Identical vectors -> 1.0
    v1 = [1.0, 2.0, 3.0]
    assert pytest.approx(cosine_similarity(v1, v1), rel=1e-5) == 1.0

    # Orthogonal vectors -> 0.0
    v2 = [1.0, 0.0]
    v3 = [0.0, 1.0]
    assert pytest.approx(cosine_similarity(v2, v3), rel=1e-5) == 0.0

    # Opposite vectors -> -1.0
    v4 = [1.0, 1.0]
    v5 = [-1.0, -1.0]
    assert pytest.approx(cosine_similarity(v4, v5), rel=1e-5) == -1.0

    # Zero vector -> 0.0
    v_zero = [0.0, 0.0]
    assert cosine_similarity(v4, v_zero) == 0.0

    # Dimension mismatch -> 0.0
    assert cosine_similarity([1.0, 2.0], [1.0, 2.0, 3.0]) == 0.0


def test_in_memory_vector_index_operations():
    """Verify CRUD and nearest neighbor search in InMemoryVectorIndex."""
    index = InMemoryVectorIndex(dimensions=3)

    # Upsert single and batch
    index.upsert("chunk_a", [1.0, 0.0, 0.0], {"name": "A"})
    index.upsert_batch([
        ("chunk_b", [0.0, 1.0, 0.0], {"name": "B"}),
        ("chunk_c", [0.9, 0.1, 0.0], {"name": "C"}),
    ])

    assert index.count() == 3
    assert index.get("chunk_a")["metadata"]["name"] == "A"

    # Query nearest to [1.0, 0.0, 0.0]
    results = index.query([1.0, 0.0, 0.0], top_k=2)
    assert len(results) == 2
    # chunk_a should be rank 1 (exact match, normalized score 1.0)
    assert results[0][0] == "chunk_a"
    assert pytest.approx(results[0][1], rel=1e-3) == 1.0
    # chunk_c should be rank 2
    assert results[1][0] == "chunk_c"

    # Clear
    index.clear()
    assert index.count() == 0


def test_vector_index_factory_and_pgvector_validation():
    """Verify create_vector_index defaults to InMemoryVectorIndex and PgVectorIndex enforces PostgreSQL URL."""
    # 1. Default local factory gives InMemoryVectorIndex
    idx = create_vector_index(db_url="sqlite:///./repolens.db", dimensions=4, enable_pgvector=False)
    assert isinstance(idx, InMemoryVectorIndex)
    idx.upsert("c1", [0.5, 0.5, 0.5, 0.5])
    assert idx.count() == 1
    res = idx.query([0.5, 0.5, 0.5, 0.5], top_k=1)
    assert len(res) == 1
    assert res[0][0] == "c1"

    # 2. PgVectorIndex rejects non-Postgres URLs truthfully
    with pytest.raises(ValueError, match="requires a PostgreSQL database URL"):
        PgVectorIndex(db_url="sqlite:///./repolens.db", dimensions=4)

    # 3. create_vector_index with enable_pgvector=True on SQLite raises clear error
    with pytest.raises(ValueError, match="Cannot initialize PgVectorIndex"):
        create_vector_index(db_url="sqlite:///./repolens.db", dimensions=4, enable_pgvector=True)


# =========================================================================
# 2. Reciprocal Rank Fusion (RRF) Tests
# =========================================================================

def test_reciprocal_rank_fusion_deterministic_scoring():
    """Verify RRF calculates scores correctly and handles multi-channel fusion."""
    channel_rankings = {
        RetrievalChannel.EXACT: [("c1", 1.0), ("c2", 0.8)],
        RetrievalChannel.LEXICAL: [("c2", 2.5), ("c3", 1.5), ("c1", 0.5)],
        RetrievalChannel.DENSE: [("c1", 0.95), ("c4", 0.7)],
    }

    fused = reciprocal_rank_fusion(channel_rankings, k=60)

    # c1 appears in:
    # EXACT rank 1 -> 1/61
    # LEXICAL rank 3 -> 1/63
    # DENSE rank 1 -> 1/61
    expected_c1_score = (1.0 / 61.0) + (1.0 / 63.0) + (1.0 / 61.0)

    fused_by_id = {item[0]: item for item in fused}
    assert "c1" in fused_by_id
    assert pytest.approx(fused_by_id["c1"][1], rel=1e-5) == expected_c1_score

    # Verify multi-channel source attribution
    assert set(fused_by_id["c1"][2]) == {RetrievalChannel.EXACT, RetrievalChannel.LEXICAL, RetrievalChannel.DENSE}
    assert fused_by_id["c2"][2] == [RetrievalChannel.EXACT, RetrievalChannel.LEXICAL]

    # c1 should be rank 1 overall
    assert fused[0][0] == "c1"


# =========================================================================
# 3. Qwen Reranker Fallback Tests
# =========================================================================

@pytest.mark.asyncio
async def test_qwen_reranker_clean_fallback_when_unconfigured():
    """When API key is empty, reranker falls back cleanly to RRF ranking without errors."""
    reranker = QwenReranker(api_key="")
    candidates = [
        RerankCandidate(chunk_id="c1", content="def auth(): pass", initial_score=0.05),
        RerankCandidate(chunk_id="c2", content="def login(): pass", initial_score=0.03),
    ]

    results = await reranker.rerank("user authentication", candidates)
    assert len(results) == 2
    # Preserves initial order, score is None indicating fallback
    assert results[0] == ("c1", None)
    assert results[1] == ("c2", None)


@pytest.mark.asyncio
async def test_qwen_reranker_clean_fallback_on_network_error():
    """When network fails or HTTP error occurs, reranker falls back to RRF rather than failing scan."""
    reranker = QwenReranker(api_key="mock-key", base_url="https://api.hf.co/v1")
    candidates = [
        RerankCandidate(chunk_id="c1", content="def test(): pass", initial_score=0.04),
    ]

    with patch("app.retrieval.reranker.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("Connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        results = await reranker.rerank("test query", candidates)
        assert len(results) == 1
        assert results[0] == ("c1", None)


@pytest.mark.asyncio
async def test_qwen_reranker_successful_reranking():
    """When reranker succeeds, results are sorted by neural cross-encoder score."""
    reranker = QwenReranker(api_key="valid-key", base_url="https://api.hf.co/v1")
    candidates = [
        RerankCandidate(chunk_id="c1", content="def foo(): pass", initial_score=0.02),
        RerankCandidate(chunk_id="c2", content="def secure_login(): pass", initial_score=0.01),
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "results": [
            {"index": 0, "relevance_score": 0.15},
            {"index": 1, "relevance_score": 0.92},
        ]
    }

    with patch("app.retrieval.reranker.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        results = await reranker.rerank("login security", candidates)
        assert len(results) == 2
        # c2 had higher neural score (0.92 vs 0.15), should be first
        assert results[0] == ("c2", 0.92)
        assert results[1] == ("c1", 0.15)


# =========================================================================
# 4. End-to-End RetrievalService Tests
# =========================================================================

@pytest.mark.asyncio
async def test_hybrid_retrieval_service_all_channels():
    """Verify multi-channel hybrid search combines exact, lexical, dense, and graph evidence."""
    commit_sha = "1234567890abcdef1234567890abcdef12345678"

    chunks = [
        CodeChunk(
            chunk_id="chunk:auth:login",
            commit_sha=commit_sha,
            file_path="app/auth.py",
            language="python",
            symbol="login_user",
            symbol_kind=ChunkSymbolKind.FUNCTION,
            start_line=10,
            end_line=25,
            content="def login_user(username, password):\n    validate_credentials(username, password)\n    return generate_token(username)",
            content_hash=content_hash("login_user"),
            index_version=INDEX_VERSION,
        ),
        CodeChunk(
            chunk_id="chunk:auth:validate",
            commit_sha=commit_sha,
            file_path="app/auth.py",
            language="python",
            symbol="validate_credentials",
            symbol_kind=ChunkSymbolKind.FUNCTION,
            start_line=27,
            end_line=40,
            content="def validate_credentials(user, pwd):\n    check_hash(pwd)",
            content_hash=content_hash("validate_credentials"),
            index_version=INDEX_VERSION,
        ),
        CodeChunk(
            chunk_id="chunk:routes:users",
            commit_sha=commit_sha,
            file_path="app/routes.py",
            language="python",
            symbol="get_users",
            symbol_kind=ChunkSymbolKind.ROUTE,
            start_line=1,
            end_line=10,
            content="@app.get('/api/users')\ndef get_users(): return []",
            content_hash=content_hash("get_users"),
            index_version=INDEX_VERSION,
        ),
    ]

    # Setup VectorIndex
    vector_index = InMemoryVectorIndex(dimensions=2)
    vector_index.upsert("chunk:auth:login", [1.0, 0.0])
    vector_index.upsert("chunk:auth:validate", [0.8, 0.2])
    vector_index.upsert("chunk:routes:users", [0.0, 1.0])

    # Setup Mock Embedding Provider
    mock_embedder = MagicMock()
    mock_embedder.default_model = "nvidia/nv-embedcode-7b-v1"
    mock_embed_resp = MagicMock()
    mock_embed_resp.embeddings = [MagicMock(vector=[1.0, 0.0])]
    mock_embedder.embed = AsyncMock(return_value=mock_embed_resp)

    # Setup Relationship Graph
    graph = RepositoryGraph()
    graph.add_node("file:app/auth.py", NodeKind.FILE, "app/auth.py", "app/auth.py", 1, 50)
    graph.add_node("file:app/routes.py", NodeKind.FILE, "app/routes.py", "app/routes.py", 1, 20)
    graph.add_edge("file:app/routes.py", "file:app/auth.py", EdgeKind.IMPORTS)

    # Instantiate RetrievalService (with unconfigured reranker to test fallback)
    service = RetrievalService(
        chunks=chunks,
        vector_index=vector_index,
        embedding_provider=mock_embedder,
        repository_graph=graph,
        reranker=QwenReranker(api_key=""),
    )

    # Query for "login_user"
    query = RetrievalQuery(query="login_user", top_k=3, use_reranker=True)
    results = await service.retrieve(query)

    assert len(results) >= 2
    top_result = results[0]

    # Top result should be chunk:auth:login with multiple channels
    assert top_result.chunk_id == "chunk:auth:login"
    assert RetrievalChannel.EXACT in top_result.source_channels
    assert RetrievalChannel.LEXICAL in top_result.source_channels
    assert RetrievalChannel.DENSE in top_result.source_channels

    # Provenance fields must be fully populated
    assert top_result.provenance["file_path"] == "app/auth.py"
    assert top_result.provenance["symbol"] == "login_user"
    assert top_result.provenance["start_line"] == 10
    assert top_result.provenance["end_line"] == 25
    assert top_result.provenance["language"] == "python"


@pytest.mark.asyncio
async def test_reranker_can_promote_candidate_below_requested_top_k():
    """Reranking sees a bounded expansion pool before the final top-k cut."""
    chunks = [
        CodeChunk(
            chunk_id=f"chunk:{index}",
            commit_sha="a" * 40,
            file_path=f"src/file_{index}.py",
            language="python",
            symbol=f"fn_{index}",
            symbol_kind=ChunkSymbolKind.FUNCTION,
            start_line=1,
            end_line=1,
            content=f"def fn_{index}(): pass",
            content_hash=content_hash(f"fn_{index}"),
            index_version=INDEX_VERSION,
        )
        for index in range(1, 6)
    ]
    reranker = MagicMock()
    reranker.rerank = AsyncMock(
        return_value=[
            ("chunk:4", 0.99),
            ("chunk:1", 0.20),
            ("chunk:2", 0.10),
            ("chunk:3", 0.05),
        ]
    )
    service = RetrievalService(chunks=chunks, reranker=reranker)
    service._search_exact = MagicMock(
        return_value=[(f"chunk:{index}", 1.0 / index) for index in range(1, 6)]
    )
    service._search_lexical = MagicMock(return_value=[])
    service._search_dense = AsyncMock(return_value=[])

    results = await service.retrieve(RetrievalQuery(query="target", top_k=1))

    assert [result.chunk_id for result in results] == ["chunk:4"]
    rerank_candidates = reranker.rerank.await_args.args[1]
    assert [candidate.chunk_id for candidate in rerank_candidates] == [
        "chunk:1",
        "chunk:2",
        "chunk:3",
        "chunk:4",
    ]
    assert results[0].provenance["reranked_from_position"] == 4
    assert results[0].provenance["final_position"] == 1


@pytest.mark.asyncio
async def test_graph_expansion_uses_lexical_seed_and_intent_weight():
    """A lexical-only seed can retrieve a bounded architecture neighbor."""
    chunks = [
        CodeChunk(
            chunk_id="chunk:seed",
            commit_sha="b" * 40,
            file_path="src/seed.py",
            language="python",
            symbol="entrypoint",
            symbol_kind=ChunkSymbolKind.FUNCTION,
            start_line=1,
            end_line=2,
            content="def entrypoint():\n    needle = True",
            content_hash=content_hash("seed"),
            index_version=INDEX_VERSION,
        ),
        CodeChunk(
            chunk_id="chunk:dependency",
            commit_sha="b" * 40,
            file_path="src/dependency.py",
            language="python",
            symbol="dependency",
            symbol_kind=ChunkSymbolKind.FUNCTION,
            start_line=1,
            end_line=1,
            content="def dependency(): pass",
            content_hash=content_hash("dependency"),
            index_version=INDEX_VERSION,
        ),
    ]
    graph = RepositoryGraph()
    graph.add_node("file:src/seed.py", NodeKind.FILE, "src/seed.py", "src/seed.py")
    graph.add_node(
        "file:src/dependency.py",
        NodeKind.FILE,
        "src/dependency.py",
        "src/dependency.py",
    )
    graph.add_edge("file:src/seed.py", "file:src/dependency.py", EdgeKind.IMPORTS)
    service = RetrievalService(chunks=chunks, repository_graph=graph)

    results = await service.retrieve(
        RetrievalQuery(
            query="needle",
            top_k=2,
            use_reranker=False,
            analysis_intent="architecture",
        )
    )

    by_id = {result.chunk_id: result for result in results}
    expanded = by_id["chunk:dependency"]
    assert expanded.source_channels == [RetrievalChannel.GRAPH]
    assert expanded.provenance["seed_chunk_id"] == "chunk:seed"
    assert expanded.provenance["seed_reason"] == "lexical"
    assert expanded.provenance["graph_distance"] == 1
    assert expanded.provenance["graph_edge_type"] == "IMPORTS"
    assert expanded.provenance["effective_graph_weight"] == 0.95
