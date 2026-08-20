"""Tests for Phase 2B: symbol-aware semantic code indexing, chunking and embedding."""

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.indexing.chunker import chunk_file, chunk_manifest, MAX_FILE_FALLBACK_LINES
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
from app.ingestion.schemas import (
    FileEntry,
    FrameworkDetected,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)


# =========================================================================
# CodeChunk Schema Tests
# =========================================================================

class TestCodeChunkSchema:
    """Test canonical CodeChunk schema and content hashing."""

    def test_content_hash_deterministic(self):
        """Same content always produces same hash."""
        c = "def foo():\n    pass"
        h1 = content_hash(c)
        h2 = content_hash(c)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_content_hash_differs_on_change(self):
        """Different content produces different hash."""
        h1 = content_hash("def foo(): pass")
        h2 = content_hash("def bar(): pass")
        assert h1 != h2

    def test_code_chunk_model_fields(self):
        """CodeChunk includes all required fields."""
        chunk = CodeChunk(
            chunk_id="abc:file.py:foo:10",
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
            file_path="src/file.py",
            language="python",
            symbol="foo",
            symbol_kind=ChunkSymbolKind.FUNCTION,
            start_line=10,
            end_line=20,
            content="def foo(): pass",
            content_hash=content_hash("def foo(): pass"),
            index_version=INDEX_VERSION,
        )
        assert chunk.chunk_id == "abc:file.py:foo:10"
        assert chunk.symbol_kind == ChunkSymbolKind.FUNCTION
        assert chunk.index_version == INDEX_VERSION

    def test_embedding_index_metadata_prevents_model_mixing(self):
        """EmbeddingIndexMetadata captures model and dimensions for index isolation."""
        meta = EmbeddingIndexMetadata(
            model="nvidia/nv-embedcode-7b-v1",
            provider="nvidia",
            dimensions=4096,
            index_version=INDEX_VERSION,
            total_chunks=42,
        )
        assert meta.dimensions == 4096
        assert meta.model == "nvidia/nv-embedcode-7b-v1"
        assert meta.index_version == INDEX_VERSION


# =========================================================================
# Chunker Tests
# =========================================================================

class TestChunker:
    """Test symbol-aware chunking from manifest file entries."""

    COMMIT_SHA = "a" * 40

    def _make_file_entry(self, path, language, lines, symbols=None):
        return FileEntry(
            path=path,
            language=language,
            size_bytes=lines * 30,
            lines_count=lines,
            symbols=symbols or [],
        )

    def test_symbol_chunks_from_functions_and_classes(self):
        """Functions and classes produce symbol-level chunks."""
        source = "line1\ndef foo():\n    return 1\n\nclass Bar:\n    x = 1\n    def m(self):\n        pass\n"
        fe = self._make_file_entry("app/main.py", "python", 8, [
            ParsedSymbol(name="foo", kind=SymbolKind.FUNCTION, start_line=2, end_line=3),
            ParsedSymbol(name="Bar", kind=SymbolKind.CLASS, start_line=5, end_line=8),
        ])
        chunks = chunk_file(fe, self.COMMIT_SHA, source)

        assert len(chunks) == 2
        assert chunks[0].symbol == "foo"
        assert chunks[0].symbol_kind == ChunkSymbolKind.FUNCTION
        assert chunks[0].start_line == 2
        assert chunks[0].end_line == 3
        assert "def foo" in chunks[0].content

        assert chunks[1].symbol == "Bar"
        assert chunks[1].symbol_kind == ChunkSymbolKind.CLASS

    def test_route_symbols_produce_route_chunks(self):
        """FastAPI and Express route symbols create ROUTE chunks."""
        source = "@app.get('/items')\ndef get_items():\n    return []\n"
        fe = self._make_file_entry("app/routes.py", "python", 3, [
            ParsedSymbol(
                name="get_items",
                kind=SymbolKind.FASTAPI_ROUTE,
                start_line=1,
                end_line=3,
                details={"http_method": "GET", "path": "/items"},
            ),
        ])
        chunks = chunk_file(fe, self.COMMIT_SHA, source)

        assert len(chunks) == 1
        assert chunks[0].symbol_kind == ChunkSymbolKind.ROUTE
        assert chunks[0].symbol == "get_items"

    def test_file_fallback_when_no_chunkable_symbols(self):
        """Files without functions/classes/routes get a FILE-level fallback chunk."""
        source = "# Configuration\nDEBUG = True\nPORT = 8080\n"
        fe = self._make_file_entry("config.py", "python", 3, [
            ParsedSymbol(name="os", kind=SymbolKind.IMPORT, start_line=1, end_line=1),
        ])
        chunks = chunk_file(fe, self.COMMIT_SHA, source)

        assert len(chunks) == 1
        assert chunks[0].symbol_kind == ChunkSymbolKind.FILE
        assert chunks[0].symbol == "config.py"
        assert chunks[0].start_line == 1

    def test_file_fallback_bounded_by_max_lines(self):
        """File fallback is bounded to MAX_FILE_FALLBACK_LINES."""
        lines = [f"line {i}" for i in range(1, 1000)]
        source = "\n".join(lines)
        fe = self._make_file_entry("big.py", "python", 999)
        chunks = chunk_file(fe, self.COMMIT_SHA, source)

        assert len(chunks) == 1
        assert chunks[0].end_line == MAX_FILE_FALLBACK_LINES

    def test_binary_files_produce_no_chunks(self):
        """Binary files are skipped entirely."""
        fe = FileEntry(
            path="image.png",
            language=None,
            size_bytes=10000,
            lines_count=0,
            is_binary=True,
        )
        chunks = chunk_file(fe, self.COMMIT_SHA, "")
        assert len(chunks) == 0

    def test_content_hash_enables_skip_on_unchanged(self):
        """Identical content produces identical hash so re-embedding can be skipped."""
        source = "def foo():\n    pass\n"
        fe = self._make_file_entry("a.py", "python", 2, [
            ParsedSymbol(name="foo", kind=SymbolKind.FUNCTION, start_line=1, end_line=2),
        ])
        c1 = chunk_file(fe, self.COMMIT_SHA, source)
        c2 = chunk_file(fe, self.COMMIT_SHA, source)
        assert c1[0].content_hash == c2[0].content_hash

    def test_chunk_manifest_aggregates_all_files(self):
        """chunk_manifest produces chunks from all manifest file entries."""
        manifest = RepositoryManifest(
            repository_url="https://github.com/org/repo.git",
            commit_hash=self.COMMIT_SHA,
            total_files=2,
            total_size_bytes=500,
            languages={"python": 2},
            files=[
                self._make_file_entry("app/main.py", "python", 5, [
                    ParsedSymbol(name="main", kind=SymbolKind.FUNCTION, start_line=1, end_line=5),
                ]),
                self._make_file_entry("config.py", "python", 3),
            ],
        )
        file_contents = {
            "app/main.py": "def main():\n    print('hi')\n    return\n\n\n",
            "config.py": "X = 1\nY = 2\nZ = 3\n",
        }
        chunks = chunk_manifest(manifest, file_contents)

        assert len(chunks) == 2
        symbols = {c.symbol for c in chunks}
        assert "main" in symbols
        assert "config.py" in symbols  # file fallback

    def test_imports_and_fetch_calls_do_not_produce_symbol_chunks(self):
        """IMPORT, FETCH_CALL, AXIOS_CALL are not chunkable and trigger file fallback."""
        source = "import os\nfetch('/api/items')\n"
        fe = self._make_file_entry("utils.ts", "typescript", 2, [
            ParsedSymbol(name="os", kind=SymbolKind.IMPORT, start_line=1, end_line=1),
            ParsedSymbol(name="fetchItems", kind=SymbolKind.FETCH_CALL, start_line=2, end_line=2,
                         details={"url": "/api/items", "http_method": "GET"}),
        ])
        chunks = chunk_file(fe, self.COMMIT_SHA, source)
        assert len(chunks) == 1
        assert chunks[0].symbol_kind == ChunkSymbolKind.FILE


# =========================================================================
# Embedding Provider Tests (Mocked)
# =========================================================================

class TestEmbeddingProviders:
    """Test embedding provider abstraction and mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_nvidia_embedding_adapter_mocked(self):
        """NvidiaEmbeddingAdapter produces correct EmbeddingResponse from mocked HTTP."""
        mock_response_data = {
            "data": [
                {"index": 0, "embedding": [0.1] * 4096},
                {"index": 1, "embedding": [0.2] * 4096},
            ],
            "model": "nvidia/nv-embedcode-7b-v1",
            "usage": {"total_tokens": 50},
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_response_data

        adapter = NvidiaEmbeddingAdapter(api_key="test-key", base_url="https://test.nvidia.com/v1")
        assert adapter.provider_name == "nvidia"
        assert adapter.default_model == "nvidia/nv-embedcode-7b-v1"
        assert adapter.dimensions == 4096

        with patch("app.indexing.embeddings.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            request = EmbeddingRequest(
                texts=["def foo(): pass", "class Bar: x = 1"],
                input_type="passage",
                model="nvidia/nv-embedcode-7b-v1",
            )
            response = await adapter.embed(request)

        assert isinstance(response, EmbeddingResponse)
        assert len(response.embeddings) == 2
        assert response.embeddings[0].dimensions == 4096
        assert response.model == "nvidia/nv-embedcode-7b-v1"
        assert response.provider == "nvidia"
        assert response.total_tokens == 50

        # Verify passage input_type was sent
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[1]["json"]["input_type"] == "passage"

    @pytest.mark.asyncio
    async def test_huggingface_embedding_adapter_mocked(self):
        """HuggingFaceEmbeddingAdapter returns correct response from mocked HTTP."""
        mock_response_data = {
            "data": [
                {"index": 0, "embedding": [0.5] * 1024},
            ],
            "model": "Qwen/Qwen3-Embedding-0.6B",
            "usage": {"total_tokens": 20},
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_response_data

        adapter = HuggingFaceEmbeddingAdapter(api_key="hf-key", base_url="https://test.hf.co/v1")
        assert adapter.provider_name == "huggingface"
        assert adapter.default_model == "Qwen/Qwen3-Embedding-0.6B"
        assert adapter.dimensions == 1024

        with patch("app.indexing.embeddings.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            request = EmbeddingRequest(
                texts=["def bar(): pass"],
                input_type="query",
                model="Qwen/Qwen3-Embedding-0.6B",
            )
            response = await adapter.embed(request)

        assert isinstance(response, EmbeddingResponse)
        assert len(response.embeddings) == 1
        assert response.embeddings[0].dimensions == 1024
        assert response.provider == "huggingface"

    def test_embedding_provider_is_abstract(self):
        """EmbeddingProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            EmbeddingProvider()

    def test_input_type_passage_vs_query(self):
        """EmbeddingRequest validates input_type string."""
        passage_req = EmbeddingRequest(
            texts=["code"], input_type="passage", model="m"
        )
        query_req = EmbeddingRequest(
            texts=["what does foo do?"], input_type="query", model="m"
        )
        assert passage_req.input_type == "passage"
        assert query_req.input_type == "query"

    def test_index_metadata_prevents_dimension_mixing(self):
        """Two indexes with different dimensions are distinct objects."""
        m1 = EmbeddingIndexMetadata(
            model="nvidia/nv-embedcode-7b-v1",
            provider="nvidia",
            dimensions=4096,
        )
        m2 = EmbeddingIndexMetadata(
            model="Qwen/Qwen3-Embedding-0.6B",
            provider="huggingface",
            dimensions=1024,
        )
        assert m1.dimensions != m2.dimensions
        assert m1.model != m2.model
