"""Tests for the 3 new read-only MCP tools: repo_get_related_symbols, repo_trace_contract, and repo_retrieve_context."""

import os
import tempfile
import pytest

from app.analysis.store import EvidenceStore
from app.context.engine import ContextEngine
from app.graph.builder import build_repository_graph
from app.indexing.schemas import ChunkSymbolKind, CodeChunk, INDEX_VERSION, content_hash
from app.ingestion.schemas import (
    FileEntry,
    FrameworkDetected,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)
from app.mcp.server import MCPRepositoryServer
from app.retrieval.service import RetrievalService


@pytest.fixture
def sample_mcp_setup():
    """Setup an isolated workspace with manifest, graph, and context engine for MCP testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create real files
        app_dir = os.path.join(tmpdir, "app")
        os.makedirs(app_dir, exist_ok=True)
        main_py = os.path.join(app_dir, "main.py")
        with open(main_py, "w", encoding="utf-8") as f:
            f.write("@app.get('/api/v1/items')\ndef get_items():\n    return []\n")

        manifest = RepositoryManifest(
            repository_url="https://github.com/org/test-repo.git",
            commit_hash="abcdef1234567890abcdef1234567890abcdef12",
            total_files=1,
            total_size_bytes=50,
            languages={"python": 1},
            frameworks=[FrameworkDetected(name="FastAPI", version="0.115.0", evidence="from fastapi import FastAPI")],
            files=[
                FileEntry(
                    path="app/main.py",
                    language="python",
                    size_bytes=50,
                    lines_count=3,
                    symbols=[
                        ParsedSymbol(
                            name="get_items",
                            kind=SymbolKind.FASTAPI_ROUTE,
                            start_line=1,
                            end_line=3,
                            details={"http_method": "GET", "path": "/api/v1/items"},
                        ),
                    ],
                ),
            ],
        )

        evidence_store = EvidenceStore(manifest=manifest)
        graph = build_repository_graph(manifest, evidence_store)

        chunks = [
            CodeChunk(
                chunk_id="chunk:main:get_items",
                commit_sha=manifest.commit_hash,
                file_path="app/main.py",
                symbol="get_items",
                symbol_kind=ChunkSymbolKind.ROUTE,
                start_line=1,
                end_line=3,
                content="@app.get('/api/v1/items')\ndef get_items():\n    return []",
                content_hash=content_hash("get_items"),
                index_version=INDEX_VERSION,
            ),
        ]
        retrieval_service = RetrievalService(chunks=chunks, repository_graph=graph)
        context_engine = ContextEngine(
            evidence_store=evidence_store,
            repository_graph=graph,
            retrieval_service=retrieval_service,
        )

        server = MCPRepositoryServer(
            evidence_store=evidence_store,
            repo_dir=tmpdir,
            repository_graph=graph,
            context_engine=context_engine,
        )

        yield server


def test_mcp_list_tools_includes_all_10_tools(sample_mcp_setup):
    """Verify list_tools() exposes 10 typed read-only tools without exposing vector DB or raw graph."""
    tools = sample_mcp_setup.list_tools()
    assert len(tools) == 10
    tool_names = {t.name for t in tools}

    # Verify all 10 canonical tool names
    expected_tools = {
        "repo_get_manifest",
        "repo_search_code",
        "repo_read_file",
        "repo_get_symbols",
        "repo_get_routes",
        "repo_get_frontend_requests",
        "repo_get_static_findings",
        "repo_get_related_symbols",
        "repo_trace_contract",
        "repo_retrieve_context",
    }
    assert tool_names == expected_tools


@pytest.mark.asyncio
async def test_mcp_tool_repo_get_related_symbols(sample_mcp_setup):
    """Verify repo_get_related_symbols traces graph connections for a symbol."""
    res = await sample_mcp_setup.call_tool("repo_get_related_symbols", {"symbol_name": "get_items"})
    assert not res.is_error
    assert res.content["symbol_name"] == "get_items"
    assert "related_symbols" in res.content
    assert res.content["count"] >= 1


@pytest.mark.asyncio
async def test_mcp_tool_repo_trace_contract(sample_mcp_setup):
    """Verify repo_trace_contract evaluates parameter normalization and match status."""
    res = await sample_mcp_setup.call_tool("repo_trace_contract", {"route_or_url": "/api/v1/items"})
    assert not res.is_error
    assert res.content["normalized_path"] == "/api/v1/items"
    assert len(res.content["backend_routes"]) == 1


@pytest.mark.asyncio
async def test_mcp_tool_repo_retrieve_context(sample_mcp_setup):
    """Verify repo_retrieve_context returns a targeted ContextBundle."""
    res = await sample_mcp_setup.call_tool("repo_retrieve_context", {"query": "get_items", "max_chunks": 2})
    assert not res.is_error
    bundle_data = res.content
    assert "relevant_chunks" in bundle_data
    assert "graph_relationships" in bundle_data
    assert "provenance" in bundle_data
    assert len(bundle_data["relevant_chunks"]) >= 1
