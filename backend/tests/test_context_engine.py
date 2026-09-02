"""Deterministic tests for Phase 2D Context Engine and targeted ContextBundle assembly."""

from unittest.mock import AsyncMock, MagicMock
import pytest

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.analysis.store import EvidenceStore
from app.context.engine import ContextEngine
from app.context.prompt import pack_repository_context
from app.graph.builder import build_repository_graph
from app.indexing.schemas import ChunkSymbolKind, CodeChunk, INDEX_VERSION, content_hash
from app.ingestion.schemas import (
    FileEntry,
    FrameworkDetected,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)
from app.retrieval.schemas import RetrievalChannel, RetrievalResult
from app.retrieval.service import RetrievalService
from app.retrieval.vector_index import InMemoryVectorIndex
from app.schemas.enums import Severity
from app.schemas.finding import Evidence


@pytest.mark.asyncio
async def test_context_engine_builds_bounded_bundle():
    """Verify ContextEngine integrates chunks, graph edges, routes, and static findings into a bounded bundle."""
    commit_sha = "abcdef1234567890abcdef1234567890abcdef12"

    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash=commit_sha,
        total_files=2,
        total_size_bytes=1000,
        languages={"python": 1, "typescript": 1},
        frameworks=[FrameworkDetected(name="FastAPI", version="0.115.0", evidence="import fastapi")],
        files=[
            FileEntry(
                path="app/server.py",
                language="python",
                size_bytes=500,
                lines_count=30,
                symbols=[
                    ParsedSymbol(
                        name="get_users",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=10,
                        end_line=20,
                        details={"http_method": "GET", "path": "/api/v1/users/{id}"},
                    ),
                ],
            ),
            FileEntry(
                path="frontend/src/api.ts",
                language="typescript",
                size_bytes=500,
                lines_count=25,
                symbols=[
                    ParsedSymbol(
                        name="fetchUsers",
                        kind=SymbolKind.FETCH_CALL,
                        start_line=5,
                        end_line=10,
                        details={"http_method": "GET", "url": "/api/v1/users/:id"},
                    ),
                ],
            ),
        ],
    )

    # Setup EvidenceStore with static findings
    evidence_store = EvidenceStore(manifest=manifest)
    static_finding = StaticFinding(
        tool="semgrep",
        rule_id="py.sql-injection",
        title="Potential SQL injection",
        description="Unsanitized query in get_users",
        severity=Severity.HIGH,
        category="security",
        evidence=Evidence(file_path="app/server.py", start_line=15, end_line=18, code_snippet="query = f'SELECT *'"),
    )
    scanner_result = ScannerResult(
        tool="semgrep",
        status=ToolStatus.COMPLETED,
        findings=[static_finding],
        execution_time_ms=50.0,
    )
    evidence_store.add_scanner_result(scanner_result)

    # Setup RepositoryGraph
    graph = build_repository_graph(manifest, evidence_store)

    # Setup RetrievalService with chunks
    chunks = [
        CodeChunk(
            chunk_id="chunk:server:get_users",
            commit_sha=commit_sha,
            file_path="app/server.py",
            language="python",
            symbol="get_users",
            symbol_kind=ChunkSymbolKind.ROUTE,
            start_line=10,
            end_line=20,
            content="@app.get('/api/v1/users/{id}')\ndef get_users(id: str):\n    return db.query(id)",
            content_hash=content_hash("get_users"),
            index_version=INDEX_VERSION,
        ),
    ]
    vector_index = InMemoryVectorIndex(dimensions=2)
    vector_index.upsert("chunk:server:get_users", [1.0, 0.0])

    retrieval_service = RetrievalService(
        chunks=chunks,
        vector_index=vector_index,
        repository_graph=graph,
    )

    # Initialize ContextEngine
    context_engine = ContextEngine(
        evidence_store=evidence_store,
        repository_graph=graph,
        retrieval_service=retrieval_service,
    )

    bundle = await context_engine.build_context_bundle(
        scan_id="scan-123",
        query="get_users SQL injection",
        analysis_intent="security",
        context_budget=2000,
        max_chunks=3,
    )

    assert bundle.scan_id == "scan-123"
    assert bundle.analysis_intent == "security"
    assert len(bundle.relevant_chunks) >= 1
    assert bundle.relevant_chunks[0].chunk.file_path == "app/server.py"

    # Verify static finding for app/server.py is included
    assert len(bundle.static_findings) == 1
    assert bundle.static_findings[0].title == "Potential SQL injection"

    # Verify provenance
    assert bundle.provenance["total_chunks"] >= 1
    assert bundle.provenance["total_static_findings"] == 1
    assert bundle.estimated_tokens > 0


@pytest.mark.asyncio
async def test_context_engine_budget_enforcement():
    """Verify ContextEngine strictly respects token/char budget constraints."""
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash="a" * 40,
        files=[],
    )
    evidence_store = EvidenceStore(manifest=manifest)

    # Create large chunks
    chunks = [
        CodeChunk(
            chunk_id=f"chunk:{i}",
            commit_sha="a" * 40,
            file_path=f"file_{i}.py",
            symbol=f"fn_{i}",
            symbol_kind=ChunkSymbolKind.FUNCTION,
            start_line=1,
            end_line=100,
            content="x = " + "1" * 1000 + f" # chunk {i}",
            content_hash=content_hash(f"content_{i}"),
            index_version=INDEX_VERSION,
        )
        for i in range(10)
    ]
    retrieval_service = RetrievalService(chunks=chunks)

    context_engine = ContextEngine(
        evidence_store=evidence_store,
        retrieval_service=retrieval_service,
    )

    # Budget of 300 tokens ~= 1200 chars -> at most 1-2 chunks
    bundle = await context_engine.build_context_bundle(
        scan_id="scan-test",
        query="fn",
        context_budget=300,
        max_chunks=10,
    )

    assert len(bundle.relevant_chunks) <= 2
    assert bundle.provenance["context_budget"] == 300
    packed = pack_repository_context(bundle, token_budget=300)
    assert len(packed.text.encode("utf-8")) <= 900
    assert packed.estimated_tokens <= 300
    assert packed.digest
