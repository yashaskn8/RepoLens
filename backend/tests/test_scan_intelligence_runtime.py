"""Tests for Phase 3.5B: Wiring Phase 2 repository intelligence into real scans via ScanIntelligenceRuntime."""

from typing import Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.agents.graph import run_analysis_workflow
from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.analysis.store import EvidenceStore
from app.context.engine import ContextEngine
from app.context.runtime import ScanIntelligenceRuntime
from app.graph.repository_graph import RepositoryGraph
from app.indexing.embeddings import EmbeddingProvider
from app.indexing.schemas import EmbeddingRequest, EmbeddingResponse, EmbeddingResult
from app.ingestion.schemas import (
    FileEntry,
    FrameworkDetected,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)
from app.llm.types import LLMResponse, ModelExecutionMetadata
from app.retrieval.service import RetrievalService
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence


class DeterministicMockEmbeddingProvider(EmbeddingProvider):
    """Deterministic token-hash embedding provider for testing vector indexing."""

    def __init__(self) -> None:
        self.requests: List[EmbeddingRequest] = []

    @property
    def provider_name(self) -> str:
        return "mock_test"

    @property
    def default_model(self) -> str:
        return "test-embed-v1"

    @property
    def dimensions(self) -> int:
        return 16

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        self.requests.append(request)
        results = []
        for idx, text in enumerate(request.texts):
            vec = [0.0] * 16
            for char in text.lower():
                pos = ord(char) % 16
                vec[pos] += 1.0
            norm = sum(x * x for x in vec) ** 0.5 or 1.0
            unit_vec = [x / norm for x in vec]
            results.append(EmbeddingResult(index=idx, vector=unit_vec, dimensions=16))

        return EmbeddingResponse(
            embeddings=results,
            model=self.default_model,
            provider=self.provider_name,
            dimensions=16,
        )


def _build_test_evidence_store() -> Tuple[EvidenceStore, Dict[str, str]]:
    """Build a rich synthetic EvidenceStore and file contents for runtime tests."""
    commit_sha = "f1e2d3c4b5a697887766554433221100aabbccdd"

    files_content = {
        "app/routes/items.py": (
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n\n"
            "@router.get('/api/v1/items')\n"
            "def list_items():\n"
            "    return [{'id': 1, 'name': 'Widget'}]\n"
        ),
        "frontend/src/api/items.ts": (
            "export async function fetchItems() {\n"
            "  const res = await fetch('/api/v1/items');\n"
            "  return res.json();\n"
            "}\n"
        ),
        "app/db/connection.py": (
            "import sqlite3\n\n"
            "def get_db_connection():\n"
            "    return sqlite3.connect('app.db')\n"
        ),
    }

    manifest = RepositoryManifest(
        repository_url="https://github.com/repolens-test/runtime-demo.git",
        commit_hash=commit_sha,
        total_files=len(files_content),
        total_size_bytes=sum(len(c) for c in files_content.values()),
        languages={"python": 2, "typescript": 1},
        frameworks=[
            FrameworkDetected(name="FastAPI", version="0.115.0", evidence="from fastapi import APIRouter"),
        ],
        files=[
            FileEntry(
                path="app/routes/items.py",
                language="python",
                size_bytes=len(files_content["app/routes/items.py"]),
                lines_count=6,
                symbols=[
                    ParsedSymbol(
                        name="list_items",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=4,
                        end_line=6,
                        details={"http_method": "GET", "path": "/api/v1/items"},
                    )
                ],
            ),
            FileEntry(
                path="frontend/src/api/items.ts",
                language="typescript",
                size_bytes=len(files_content["frontend/src/api/items.ts"]),
                lines_count=4,
                symbols=[
                    ParsedSymbol(
                        name="fetchItems",
                        kind=SymbolKind.FETCH_CALL,
                        start_line=1,
                        end_line=4,
                        details={"http_method": "GET", "url": "/api/v1/items"},
                    )
                ],
            ),
            FileEntry(
                path="app/db/connection.py",
                language="python",
                size_bytes=len(files_content["app/db/connection.py"]),
                lines_count=4,
                symbols=[
                    ParsedSymbol(
                        name="get_db_connection",
                        kind=SymbolKind.FUNCTION,
                        start_line=3,
                        end_line=4,
                    )
                ],
            ),
        ],
    )

    evidence_store = EvidenceStore(manifest=manifest)
    evidence_store.add_scanner_result(
        ScannerResult(
            tool="semgrep",
            status=ToolStatus.COMPLETED,
            findings=[
                StaticFinding(
                    tool="semgrep",
                    rule_id="python.lang.security.db",
                    title="Database Connection Pattern",
                    description="Standard connection helper",
                    severity=Severity.INFO,
                    category="security",
                    evidence=Evidence(
                        file_path="app/db/connection.py",
                        start_line=3,
                        end_line=4,
                        code_snippet="def get_db_connection():",
                    ),
                )
            ],
        )
    )

    return evidence_store, files_content


# =========================================================================
# 1. ScanIntelligenceRuntime Assembly Tests
# =========================================================================


@pytest.mark.asyncio
async def test_scan_intelligence_runtime_assembly_end_to_end():
    """Verify ScanIntelligenceRuntime constructs graph, chunks, vector index, and ContextEngine."""
    evidence_store, files_content = _build_test_evidence_store()
    mock_embedder = DeterministicMockEmbeddingProvider()

    runtime = await ScanIntelligenceRuntime.build(
        evidence_store=evidence_store,
        file_contents=files_content,
        embedding_provider=mock_embedder,
    )

    assert isinstance(runtime, ScanIntelligenceRuntime)
    assert isinstance(runtime.repository_graph, RepositoryGraph)
    assert isinstance(runtime.retrieval_service, RetrievalService)
    assert isinstance(runtime.context_engine, ContextEngine)

    # 1. Chunks generated with exact commit SHA
    assert len(runtime.chunks) >= 3
    for chunk in runtime.chunks:
        assert chunk.commit_sha == evidence_store.manifest.commit_hash
        assert chunk.chunk_id.startswith(evidence_store.manifest.commit_hash[:12])

    # 2. Vector index populated
    assert runtime.vector_index.count() == len(runtime.chunks)

    # 3. ContextEngine query produces targeted bundle
    bundle = await runtime.context_engine.build_context_bundle(
        scan_id="test-scan-123",
        query="items endpoint route contract",
        analysis_intent="integration",
        context_budget=2000,
        max_chunks=3,
    )

    assert len(bundle.relevant_chunks) >= 1
    assert any("items" in c.chunk.file_path for c in bundle.relevant_chunks)
    assert bundle.provenance["total_chunks"] >= 1


@pytest.mark.asyncio
async def test_scan_intelligence_runtime_embedding_failure_graceful_degradation():
    """Verify that if embedding fails, runtime still functions with exact+lexical+graph channels."""
    evidence_store, files_content = _build_test_evidence_store()

    class FailingEmbeddingProvider(EmbeddingProvider):
        @property
        def provider_name(self) -> str:
            return "failing_provider"

        @property
        def default_model(self) -> str:
            return "failing-model"

        @property
        def dimensions(self) -> int:
            return 16

        async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
            raise RuntimeError("NVIDIA NIM embedding quota exceeded (503 Service Unavailable)")

    runtime = await ScanIntelligenceRuntime.build(
        evidence_store=evidence_store,
        file_contents=files_content,
        embedding_provider=FailingEmbeddingProvider(),
    )

    # Runtime should build successfully without raising
    assert runtime is not None
    assert runtime.vector_index.count() == 0

    # ContextEngine retrieval still works via exact and lexical channels
    bundle = await runtime.context_engine.build_context_bundle(
        scan_id="test-scan-fallback",
        query="list_items",
        analysis_intent="architecture",
    )

    assert len(bundle.relevant_chunks) >= 1
    assert any(c.chunk.symbol == "list_items" for c in bundle.relevant_chunks)


@pytest.mark.asyncio
async def test_scan_runtime_survives_embedding_model_load_failure():
    """Provider metadata discovery must remain inside the degradation boundary."""
    evidence_store, files_content = _build_test_evidence_store()

    class LoadFailingProvider(EmbeddingProvider):
        @property
        def provider_name(self) -> str:
            return "unavailable_local"

        @property
        def default_model(self) -> str:
            return "missing-model"

        @property
        def dimensions(self) -> int:
            raise RuntimeError("local model unavailable")

        async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
            raise AssertionError("embed must not run after metadata discovery fails")

    runtime = await ScanIntelligenceRuntime.build(
        evidence_store=evidence_store,
        file_contents=files_content,
        embedding_provider=LoadFailingProvider(),
    )

    assert runtime.embedding_provider is None
    assert runtime.vector_index.count() == 0
    bundle = await runtime.context_engine.build_context_bundle(
        scan_id="test-load-failure",
        query="list_items",
        analysis_intent="architecture",
    )
    assert any(item.chunk.symbol == "list_items" for item in bundle.relevant_chunks)


@pytest.mark.asyncio
async def test_scan_intelligence_runtime_reuses_unchanged_embeddings():
    """A prepopulated index skips unchanged chunks and embeds only stale content."""
    evidence_store, files_content = _build_test_evidence_store()
    mock_embedder = DeterministicMockEmbeddingProvider()

    initial_runtime = await ScanIntelligenceRuntime.build(
        evidence_store=evidence_store,
        file_contents=files_content,
        embedding_provider=mock_embedder,
    )
    assert mock_embedder.requests

    mock_embedder.requests.clear()
    reused_runtime = await ScanIntelligenceRuntime.build(
        evidence_store=evidence_store,
        file_contents=files_content,
        embedding_provider=mock_embedder,
        vector_index=initial_runtime.vector_index,
    )

    assert mock_embedder.requests == []
    assert reused_runtime.vector_index.count() == len(reused_runtime.chunks)
    for chunk in reused_runtime.chunks:
        stored = reused_runtime.vector_index.get(chunk.chunk_id)
        assert stored is not None
        assert stored["metadata"]["content_hash"] == chunk.content_hash
        assert stored["metadata"]["model"] == mock_embedder.default_model
        assert stored["metadata"]["index_version"] == chunk.index_version

    changed_contents = dict(files_content)
    changed_contents["app/db/connection.py"] = (
        "import sqlite3\n\n"
        "def get_db_connection():\n"
        "    return sqlite3.connect('cache.db')\n"
    )
    stale_runtime = await ScanIntelligenceRuntime.build(
        evidence_store=evidence_store,
        file_contents=changed_contents,
        embedding_provider=mock_embedder,
        vector_index=reused_runtime.vector_index,
    )

    assert len(mock_embedder.requests) == 1
    assert mock_embedder.requests[0].texts == [
        "def get_db_connection():\n    return sqlite3.connect('cache.db')"
    ]
    assert stale_runtime.vector_index.count() == len(stale_runtime.chunks)


# =========================================================================
# 2. Real Runtime Wiring into LangGraph Workflow Tests
# =========================================================================


@pytest.mark.asyncio
async def test_langgraph_workflow_with_real_runtime_avoids_unnecessary_specialist_context():
    """A fully deterministic case must not send broad repository chunks to a specialist model."""
    evidence_store, files_content = _build_test_evidence_store()
    mock_embedder = DeterministicMockEmbeddingProvider()

    # 1. Assemble real ScanIntelligenceRuntime
    runtime = await ScanIntelligenceRuntime.build(
        evidence_store=evidence_store,
        file_contents=files_content,
        embedding_provider=mock_embedder,
    )

    received_prompts = []

    async def mock_llm_generate(request):
        # Capture user prompts passed to each specialist agent
        user_msg = next((m.content for m in request.messages if m.role == "user"), "")
        received_prompts.append(user_msg)

        # Return mock JSON finding
        json_resp = (
            '{"findings": [{"title": "Sample Finding", "description": "Test issue", '
            '"severity": "MEDIUM", "category": "architecture", "file_path": "app/routes/items.py", '
            '"start_line": 4, "end_line": 6, "code_snippet": "def list_items():"}]}'
        )
        metadata = ModelExecutionMetadata(
            model_name="mock-model",
            provider="mock",
            latency_ms=10.0,
        )
        return LLMResponse(content=json_resp, metadata=metadata)

    # 2. Execute full LangGraph analysis workflow with real ContextEngine
    with patch("app.llm.router.LLMRouter.generate", side_effect=mock_llm_generate):
        final_state = await run_analysis_workflow(
            evidence_store=evidence_store,
            scan_id=str(uuid4()),
            repo_dir=".",
            context_engine=runtime.context_engine,
            repository_graph=runtime.repository_graph,
        )

        assert final_state["status"] == "COMPLETED"
        assert "architecture" in final_state["completed_nodes"]
        assert "integration" in final_state["completed_nodes"]
        assert "security" in final_state["completed_nodes"]
        assert "bug" in final_state["completed_nodes"]
        assert "verifier" in final_state["completed_nodes"]

        # 3. Deterministic coverage avoids broad model discovery/context payloads.
        prompts_with_chunks = [
            p for p in received_prompts
            if '"file":"app/routes/items.py"' in p
            or '"file":"frontend/src/api/items.ts"' in p
            or '"file":"app/db/connection.py"' in p
        ]
        assert prompts_with_chunks == []


@pytest.mark.asyncio
async def test_scan_intelligence_runtime_build_from_directory(tmp_path):
    """Verify ScanIntelligenceRuntime reads files directly from repository directory workspace."""
    evidence_store, files_content = _build_test_evidence_store()

    # Write files into temporary directory
    for rel_path, content in files_content.items():
        file_p = tmp_path / rel_path
        file_p.parent.mkdir(parents=True, exist_ok=True)
        file_p.write_text(content, encoding="utf-8")

    runtime = await ScanIntelligenceRuntime.build(
        evidence_store=evidence_store,
        repo_dir=str(tmp_path),
        embedding_provider=DeterministicMockEmbeddingProvider(),
    )

    assert len(runtime.chunks) >= 3
    assert runtime.vector_index.count() >= 3

    # Query for connection
    bundle = await runtime.context_engine.build_context_bundle(
        scan_id="dir-test",
        query="get_db_connection sqlite",
        analysis_intent="security",
    )
    assert len(bundle.relevant_chunks) >= 1
    assert any("connection.py" in c.chunk.file_path for c in bundle.relevant_chunks)
