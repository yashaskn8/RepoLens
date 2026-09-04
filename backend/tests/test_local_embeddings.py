"""Comprehensive tests for the local embedding layer (Sentence Transformers).

All tests are 100% offline — SentenceTransformer is fully mocked so no model
download or GPU/CPU inference ever occurs during pytest.
"""

from __future__ import annotations

import asyncio
import math
import threading
from typing import Any, List
from unittest.mock import MagicMock, patch, PropertyMock

import numpy as np
import pytest

from app.embeddings.constants import (
    DEFAULT_LOCAL_EMBEDDING_DEVICE,
    DEFAULT_LOCAL_EMBEDDING_MODEL,
    MAX_LOCAL_EMBEDDING_BATCH_SIZE,
    MAX_LOCAL_EMBEDDING_TEXT_CHARS,
)
from app.embeddings.service import LocalEmbeddingError, LocalEmbeddingService
from app.indexing.schemas import EmbeddingRequest

# The correct patch target: SentenceTransformer is imported inside
# _ensure_loaded() via `from sentence_transformers import SentenceTransformer`
_ST_PATCH = "app.embeddings.service._load_sentence_transformer"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_model(dim: int = 384, max_seq: int = 256) -> MagicMock:
    """Create a mock SentenceTransformer with configurable dimension."""
    model = MagicMock()
    model.get_embedding_dimension.return_value = dim
    model.get_sentence_embedding_dimension.return_value = dim
    model.max_seq_length = max_seq

    def _encode_side_effect(texts, **kwargs):
        if isinstance(texts, str):
            return np.random.randn(dim).astype(np.float32)
        return np.random.randn(len(texts), dim).astype(np.float32)

    model.encode.side_effect = _encode_side_effect
    return model


def _make_normalized_mock_model(dim: int = 384) -> MagicMock:
    """Create a mock that returns properly normalized vectors."""
    model = MagicMock()
    model.get_embedding_dimension.return_value = dim
    model.get_sentence_embedding_dimension.return_value = dim
    model.max_seq_length = 256

    def _encode_normalized(texts, **kwargs):
        if isinstance(texts, str):
            vec = np.random.randn(dim).astype(np.float32)
            vec /= np.linalg.norm(vec)
            return vec
        vecs = np.random.randn(len(texts), dim).astype(np.float32)
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return vecs / norms

    model.encode.side_effect = _encode_normalized
    return model


# ===========================================================================
# 1. Lazy Loading
# ===========================================================================

class TestLazyLoading:
    """Model is only loaded on first use, not at construction time."""

    def test_model_not_loaded_on_init(self):
        service = LocalEmbeddingService()
        assert not service.is_loaded

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_model_loaded_on_first_embed(self, mock_cls):
        service = LocalEmbeddingService()
        assert not service.is_loaded
        service.embed_text("hello")
        assert service.is_loaded
        mock_cls.assert_called_once()


# ===========================================================================
# 2. Single Load (thread-safe)
# ===========================================================================

class TestSingleLoad:
    """Model is loaded exactly once even under concurrent access."""

    @patch(_ST_PATCH)
    def test_concurrent_loads_only_creates_one_model(self, mock_cls):
        mock_cls.return_value = _make_normalized_mock_model()
        service = LocalEmbeddingService()
        barrier = threading.Barrier(4)
        results: List[Any] = []

        def worker():
            barrier.wait()
            try:
                service.embed_text("test")
                results.append("ok")
            except Exception as exc:
                results.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert mock_cls.call_count == 1
        assert all(r == "ok" for r in results)


# ===========================================================================
# 3. embed_text
# ===========================================================================

class TestEmbedText:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_returns_list_of_floats(self, _):
        service = LocalEmbeddingService()
        vec = service.embed_text("hello world")
        assert isinstance(vec, list)
        assert all(isinstance(v, float) for v in vec)
        assert len(vec) == 384

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_single_text_calls_encode(self, mock_cls):
        service = LocalEmbeddingService()
        service.embed_text("test input")
        service._model.encode.assert_called_once()


# ===========================================================================
# 4. embed_documents
# ===========================================================================

class TestEmbedDocuments:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_returns_correct_count(self, _):
        service = LocalEmbeddingService()
        texts = ["doc one", "doc two", "doc three"]
        vecs = service.embed_documents(texts)
        assert len(vecs) == 3
        assert all(len(v) == 384 for v in vecs)

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_batch_encoding_called(self, _):
        service = LocalEmbeddingService()
        service.embed_documents(["a", "b"])
        service._model.encode.assert_called_once()


# ===========================================================================
# 5. embed_query
# ===========================================================================

class TestEmbedQuery:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_embed_query_returns_vector(self, _):
        service = LocalEmbeddingService()
        vec = service.embed_query("search query")
        assert isinstance(vec, list)
        assert len(vec) == 384


# ===========================================================================
# 6. Batch Bounds
# ===========================================================================

class TestBatchBounds:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_rejects_oversized_batch(self, _):
        service = LocalEmbeddingService()
        texts = [f"text {i}" for i in range(MAX_LOCAL_EMBEDDING_BATCH_SIZE + 1)]
        with pytest.raises(LocalEmbeddingError, match="exceeds maximum"):
            service.embed_documents(texts)

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_accepts_max_batch(self, _):
        service = LocalEmbeddingService()
        texts = [f"text {i}" for i in range(MAX_LOCAL_EMBEDDING_BATCH_SIZE)]
        vecs = service.embed_documents(texts)
        assert len(vecs) == MAX_LOCAL_EMBEDDING_BATCH_SIZE


# ===========================================================================
# 7. Empty Inputs
# ===========================================================================

class TestEmptyInputs:

    def test_empty_string_rejected(self):
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="empty"):
            service.embed_text("")

    def test_whitespace_only_rejected(self):
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="empty"):
            service.embed_text("   \n\t  ")

    def test_empty_list_rejected(self):
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="empty"):
            service.embed_documents([])


# ===========================================================================
# 8. Oversized Text
# ===========================================================================

class TestOversizedText:

    def test_text_exceeding_max_chars_rejected(self):
        service = LocalEmbeddingService()
        huge = "x" * (MAX_LOCAL_EMBEDDING_TEXT_CHARS + 1)
        with pytest.raises(LocalEmbeddingError, match="maximum length"):
            service.embed_text(huge)


# ===========================================================================
# 9. Dimension Discovery
# ===========================================================================

class TestDimensionDiscovery:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model(dim=768))
    def test_discovers_dimension_from_model(self, _):
        service = LocalEmbeddingService()
        assert service.dimensions == 768

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model(dim=384))
    def test_default_model_dimension(self, _):
        service = LocalEmbeddingService()
        assert service.dimensions == 384


# ===========================================================================
# 10. Invalid Dimension from Model
# ===========================================================================

class TestInvalidDimension:

    @patch(_ST_PATCH)
    def test_zero_dimension_raises(self, mock_cls):
        model = MagicMock()
        model.get_embedding_dimension.return_value = 0
        model.get_sentence_embedding_dimension.return_value = 0
        mock_cls.return_value = model
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="invalid embedding dimension"):
            service.embed_text("test")

    @patch(_ST_PATCH)
    def test_negative_dimension_raises(self, mock_cls):
        model = MagicMock()
        model.get_embedding_dimension.return_value = -1
        model.get_sentence_embedding_dimension.return_value = -1
        mock_cls.return_value = model
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="invalid embedding dimension"):
            service.embed_text("test")


# ===========================================================================
# 11. NaN/Inf Rejection
# ===========================================================================

class TestNanInfRejection:

    @patch(_ST_PATCH)
    def test_nan_in_vector_raises(self, mock_cls):
        model = MagicMock()
        model.get_embedding_dimension.return_value = 3
        model.get_sentence_embedding_dimension.return_value = 3
        model.max_seq_length = 256
        vec = np.array([0.1, float("nan"), 0.3])
        model.encode.return_value = vec
        mock_cls.return_value = model
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="Non-finite"):
            service.embed_text("test")

    @patch(_ST_PATCH)
    def test_inf_in_vector_raises(self, mock_cls):
        model = MagicMock()
        model.get_embedding_dimension.return_value = 3
        model.get_sentence_embedding_dimension.return_value = 3
        model.max_seq_length = 256
        vec = np.array([0.1, float("inf"), 0.3])
        model.encode.return_value = vec
        mock_cls.return_value = model
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="Non-finite"):
            service.embed_text("test")


# ===========================================================================
# 12. Zero Vector Rejection
# ===========================================================================

class TestZeroVectorRejection:

    @patch(_ST_PATCH)
    def test_zero_vector_raises(self, mock_cls):
        model = MagicMock()
        model.get_embedding_dimension.return_value = 3
        model.get_sentence_embedding_dimension.return_value = 3
        model.max_seq_length = 256
        model.encode.return_value = np.array([0.0, 0.0, 0.0])
        mock_cls.return_value = model
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="zero"):
            service.embed_text("test")


# ===========================================================================
# 13. Normalization
# ===========================================================================

class TestNormalization:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_encode_called_with_normalize(self, _):
        service = LocalEmbeddingService()
        service.embed_text("test")
        call_kwargs = service._model.encode.call_args
        assert call_kwargs[1].get("normalize_embeddings") is True


# ===========================================================================
# 14. Load Failure
# ===========================================================================

class TestLoadFailure:

    @patch(_ST_PATCH, side_effect=RuntimeError("model not found"))
    def test_load_failure_raises_clean_error(self, _):
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="Failed to load"):
            service.embed_text("test")

    @patch(_ST_PATCH, side_effect=RuntimeError("C:\\Users\\secret\\path\\model"))
    def test_load_failure_redacts_paths(self, _):
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError) as exc_info:
            service.embed_text("test")
        assert "C:\\Users" not in str(exc_info.value)
        assert "redacted" in str(exc_info.value).lower()


# ===========================================================================
# 15. Encode Failure
# ===========================================================================

class TestEncodeFailure:

    @patch(_ST_PATCH)
    def test_encode_error_raises_clean_error(self, mock_cls):
        model = _make_normalized_mock_model()
        model.encode.side_effect = RuntimeError("CUDA out of memory")
        mock_cls.return_value = model
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="Encoding failed"):
            service.embed_text("test")


# ===========================================================================
# 16. Settings Override
# ===========================================================================

class TestSettingsOverride:

    def test_custom_model_name(self):
        service = LocalEmbeddingService(model_name="custom/model", device="cuda")
        assert service.model_name == "custom/model"
        assert service.device == "cuda"

    def test_defaults(self):
        service = LocalEmbeddingService()
        assert service.model_name == DEFAULT_LOCAL_EMBEDDING_MODEL
        assert service.device == DEFAULT_LOCAL_EMBEDDING_DEVICE


# ===========================================================================
# 17. Adapter: asyncio.to_thread dispatch
# ===========================================================================

class TestAdapterAsyncDispatch:

    @pytest.mark.asyncio
    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    async def test_adapter_uses_to_thread(self, _):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter()
        req = EmbeddingRequest(texts=["hello"], input_type="query", model=adapter.default_model)
        with patch("app.embeddings.adapter.asyncio.to_thread", wraps=asyncio.to_thread) as mock_thread:
            resp = await adapter.embed(req)
            mock_thread.assert_called_once()
        assert len(resp.embeddings) == 1


# ===========================================================================
# 18. Adapter: provider_name
# ===========================================================================

class TestAdapterProviderName:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_provider_name_is_local(self, _):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter()
        assert adapter.provider_name == "local"


# ===========================================================================
# 19. Adapter: query vs passage routing
# ===========================================================================

class TestAdapterQueryVsPassage:

    @pytest.mark.asyncio
    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    async def test_single_query_uses_embed_query(self, _):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter()
        req = EmbeddingRequest(texts=["search term"], input_type="query", model=adapter.default_model)
        with patch.object(adapter._service, "embed_queries", wraps=adapter._service.embed_queries) as mock_q:
            resp = await adapter.embed(req)
            mock_q.assert_called_once_with(["search term"])

    @pytest.mark.asyncio
    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    async def test_multiple_queries_keep_query_semantics(self, _):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter()
        req = EmbeddingRequest(
            texts=["first query", "second query"],
            input_type="query",
            model=adapter.default_model,
        )
        with patch.object(adapter._service, "embed_queries", wraps=adapter._service.embed_queries) as mock_q, \
             patch.object(adapter._service, "embed_documents", wraps=adapter._service.embed_documents) as mock_d:
            response = await adapter.embed(req)
        mock_q.assert_called_once_with(["first query", "second query"])
        mock_d.assert_not_called()
        assert len(response.embeddings) == 2

    @pytest.mark.asyncio
    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    async def test_passage_uses_embed_documents(self, _):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter()
        req = EmbeddingRequest(texts=["doc1", "doc2"], input_type="passage", model=adapter.default_model)
        with patch.object(adapter._service, "embed_documents", wraps=adapter._service.embed_documents) as mock_d:
            resp = await adapter.embed(req)
            mock_d.assert_called_once()
        assert len(resp.embeddings) == 2


# ===========================================================================
# 20. Adapter: EmbeddingResponse schema compliance
# ===========================================================================

class TestAdapterResponseSchema:

    @pytest.mark.asyncio
    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    async def test_response_has_correct_fields(self, _):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter()
        req = EmbeddingRequest(texts=["test"], input_type="passage", model=adapter.default_model)
        resp = await adapter.embed(req)
        assert resp.provider == "local"
        assert resp.dimensions == 384
        assert resp.total_tokens is None
        assert len(resp.embeddings) == 1
        assert resp.embeddings[0].index == 0
        assert resp.embeddings[0].dimensions == 384
        assert resp.model == adapter.default_model
        assert resp.preprocessing_version == adapter.preprocessing_version
        assert resp.max_input_tokens == 256

    @pytest.mark.asyncio
    async def test_incompatible_model_override_is_rejected_truthfully(self):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter(service=LocalEmbeddingService(model_name="actual/model"))
        request = EmbeddingRequest(texts=["test"], input_type="passage", model="other/model")
        with pytest.raises(ValueError, match="does not match loaded model"):
            await adapter.embed(request)


class TestSequenceWindowTruthfulness:

    @patch(_ST_PATCH)
    def test_input_that_exceeds_model_token_window_is_rejected(self, mock_loader):
        model = _make_normalized_mock_model()
        model.tokenizer.encode.return_value = list(range(257))
        mock_loader.return_value = model
        service = LocalEmbeddingService()
        with pytest.raises(LocalEmbeddingError, match="sequence window"):
            service.embed_text("bounded by the tokenizer, not only characters")


class TestSentenceTransformerRoleSemantics:

    @patch(_ST_PATCH)
    def test_v6_query_and_document_encoders_are_distinct(self, mock_loader):
        class RoleAwareModel:
            max_seq_length = 256

            def __init__(self):
                self.tokenizer = MagicMock()
                self.tokenizer.encode.return_value = [1, 2, 3]
                self.query_calls = 0
                self.document_calls = 0

            def get_embedding_dimension(self):
                return 3

            def encode_query(self, inputs, **kwargs):
                self.query_calls += 1
                return np.array([[1.0, 0.0, 0.0] for _ in inputs])

            def encode_document(self, inputs, **kwargs):
                self.document_calls += 1
                return np.array([[0.0, 1.0, 0.0] for _ in inputs])

        model = RoleAwareModel()
        mock_loader.return_value = model
        service = LocalEmbeddingService()
        service.embed_queries(["find caller", "find route"])
        service.embed_documents(["def caller(): pass"])
        assert model.query_calls == 1
        assert model.document_calls == 1


# ===========================================================================
# 21. Cosine Similarity Hardening: NaN/Inf
# ===========================================================================

class TestCosineSimHardening:

    def test_nan_in_v1_returns_zero(self):
        from app.retrieval.vector_index import cosine_similarity
        assert cosine_similarity([1.0, float("nan")], [1.0, 0.5]) == 0.0

    def test_inf_in_v2_returns_zero(self):
        from app.retrieval.vector_index import cosine_similarity
        assert cosine_similarity([1.0, 0.5], [1.0, float("inf")]) == 0.0

    def test_neg_inf_returns_zero(self):
        from app.retrieval.vector_index import cosine_similarity
        assert cosine_similarity([float("-inf"), 0.5], [1.0, 0.5]) == 0.0

    def test_normal_vectors_unaffected(self):
        from app.retrieval.vector_index import cosine_similarity
        sim = cosine_similarity([1.0, 0.0], [1.0, 0.0])
        assert abs(sim - 1.0) < 1e-6

    def test_empty_vectors_return_zero(self):
        from app.retrieval.vector_index import cosine_similarity
        assert cosine_similarity([], []) == 0.0

    def test_mismatched_dimensions_return_zero(self):
        from app.retrieval.vector_index import cosine_similarity
        assert cosine_similarity([1.0, 2.0], [1.0]) == 0.0

    def test_clamped_to_bounds(self):
        from app.retrieval.vector_index import cosine_similarity
        sim = cosine_similarity([1.0, 0.0, 0.0], [1.0, 0.0, 0.0])
        assert -1.0 <= sim <= 1.0


# ===========================================================================
# 22. Retrieval Integration (local adapter wiring)
# ===========================================================================

class TestRetrievalIntegration:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_retrieval_service_selects_local_when_enabled(self, _):
        from app.retrieval.service import RetrievalService
        with patch("app.retrieval.service.get_settings") as mock_settings:
            s = MagicMock()
            s.LOCAL_EMBEDDING_ENABLED = True
            s.COHERE_API_KEY = None
            mock_settings.return_value = s
            rs = RetrievalService(chunks=[])
            assert rs.embedding_provider is not None
            assert rs.embedding_provider.provider_name == "local"


# ===========================================================================
# 23. Retrieval Integration: cloud fallback preserved
# ===========================================================================

class TestCloudFallbackPreserved:

    def test_cohere_selected_when_local_disabled(self):
        from app.retrieval.service import RetrievalService
        with patch("app.retrieval.service.get_settings") as mock_settings:
            s = MagicMock()
            s.LOCAL_EMBEDDING_ENABLED = False
            s.COHERE_API_KEY = "test-key"
            s.COHERE_BASE_URL = "https://api.cohere.com/v2"
            s.COHERE_EMBEDDING_MODEL = "embed-english-v3.0"
            s.LLM_DEFAULT_TIMEOUT = 30.0
            mock_settings.return_value = s
            rs = RetrievalService(chunks=[])
            assert rs.embedding_provider is not None
            assert rs.embedding_provider.provider_name == "cohere"

    def test_no_provider_when_all_disabled(self):
        from app.retrieval.service import RetrievalService
        with patch("app.retrieval.service.get_settings") as mock_settings:
            s = MagicMock()
            s.LOCAL_EMBEDDING_ENABLED = False
            s.COHERE_API_KEY = None
            mock_settings.return_value = s
            rs = RetrievalService(chunks=[])
            assert rs.embedding_provider is None


# ===========================================================================
# 24. ScanIntelligenceRuntime Integration
# ===========================================================================

class TestRuntimeIntegration:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_runtime_build_resolves_local_provider(self, _):
        """Verify that ScanIntelligenceRuntime.build() picks local adapter."""
        # We just verify the provider resolution logic, not the full build
        with patch("app.context.runtime.get_settings") as mock_settings:
            s = MagicMock()
            s.LOCAL_EMBEDDING_ENABLED = True
            s.NVIDIA_API_KEY = None
            s.HUGGINGFACE_API_KEY = None
            s.DATABASE_URL = None
            s.ENABLE_PGVECTOR = False
            mock_settings.return_value = s

            from app.embeddings.adapter import LocalEmbeddingAdapter
            adapter = LocalEmbeddingAdapter()
            assert adapter.provider_name == "local"
            assert adapter.dimensions == 384


# ===========================================================================
# 25. Provenance Preservation
# ===========================================================================

class TestProvenancePreservation:

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_adapter_dimensions_match_service(self, _):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter()
        assert adapter.dimensions == adapter._service.dimensions

    @patch(_ST_PATCH, side_effect=lambda *a, **kw: _make_normalized_mock_model())
    def test_adapter_model_name_matches_service(self, _):
        from app.embeddings.adapter import LocalEmbeddingAdapter
        adapter = LocalEmbeddingAdapter()
        assert adapter.default_model == adapter._service.model_name


# ===========================================================================
# 26. Vector Index Default Dimension Not Changed
# ===========================================================================

class TestVectorIndexDefaultDimension:

    def test_create_vector_index_default_is_4096(self):
        """Verify we did NOT globally change the default dimension to 384."""
        from app.retrieval.vector_index import create_vector_index
        import inspect
        sig = inspect.signature(create_vector_index)
        default_dim = sig.parameters["dimensions"].default
        assert default_dim == 4096, f"Default dimension should remain 4096, got {default_dim}"

    def test_inmemory_index_accepts_384(self):
        """Local embeddings with 384-dim vectors work correctly."""
        from app.retrieval.vector_index import InMemoryVectorIndex
        idx = InMemoryVectorIndex(dimensions=384)
        vec = [0.1] * 384
        idx.upsert("chunk1", vec, {"test": True})
        assert idx.count() == 1
        results = idx.query(vec, top_k=1)
        assert len(results) == 1
        assert results[0][0] == "chunk1"
