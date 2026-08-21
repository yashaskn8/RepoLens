"""Contract and protocol tests for the Model Context Protocol (MCP) server integration."""

import json
import os
import tempfile
import pytest

from mcp.shared.memory import create_connected_server_and_client_session

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import FileEntry, ParsedSymbol, RepositoryManifest, SymbolKind
from app.mcp.adapter import MCPProtocolAdapter, create_mcp_protocol_server
from app.mcp.server import MCPRepositoryServer
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence


@pytest.fixture
def mcp_protocol_fixture():
    """Create a sample repository, evidence store, and configured MCP protocol server."""
    with tempfile.TemporaryDirectory(prefix="mcp_proto_test_") as tmp_dir:
        # Create sample files
        main_py = os.path.join(tmp_dir, "main.py")
        with open(main_py, "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "from fastapi import FastAPI\n\n"
                "app = FastAPI()\n\n"
                "@app.get('/api/v1/health')\n"
                "def health():\n"
                "    return {'status': 'healthy'}\n"
            )

        client_ts = os.path.join(tmp_dir, "client.ts")
        with open(client_ts, "w", encoding="utf-8") as f:
            f.write(
                "export async function checkHealth() {\n"
                "    return fetch('/api/v1/health');\n"
                "}\n"
            )

        manifest = RepositoryManifest(
            repository_url="https://github.com/org/mcp-proto-test.git",
            commit_hash="c0ffee1234567890",
            total_files=2,
            total_size_bytes=260,
            languages={"python": 1, "typescript": 1},
            files=[
                FileEntry(
                    path="main.py",
                    language="python",
                    size_bytes=130,
                    lines_count=8,
                    symbols=[
                        ParsedSymbol(
                            name="import os",
                            kind=SymbolKind.IMPORT,
                            start_line=1,
                            end_line=1,
                        ),
                        ParsedSymbol(
                            name="GET /api/v1/health",
                            kind=SymbolKind.FASTAPI_ROUTE,
                            start_line=6,
                            end_line=8,
                            details={"http_method": "GET", "path": "/api/v1/health"},
                        ),
                    ],
                ),
                FileEntry(
                    path="client.ts",
                    language="typescript",
                    size_bytes=130,
                    lines_count=3,
                    symbols=[
                        ParsedSymbol(
                            name="fetch(/api/v1/health)",
                            kind=SymbolKind.FETCH_CALL,
                            start_line=2,
                            end_line=2,
                            details={"url": "/api/v1/health", "target": "/api/v1/health"},
                        ),
                    ],
                ),
            ],
        )

        finding = StaticFinding(
            tool="semgrep",
            rule_id="python.lang.security.test",
            title="Protocol Test Finding",
            description="Test vulnerability finding",
            severity=Severity.HIGH,
            category="security",
            evidence=Evidence(file_path="main.py", start_line=6, end_line=8),
        )

        store = EvidenceStore(
            manifest=manifest,
            scanner_results={"semgrep": ScannerResult(tool="semgrep", status=ToolStatus.COMPLETED, findings=[finding])},
        )
        repo_server = MCPRepositoryServer(evidence_store=store, repo_dir=tmp_dir)
        protocol_server = create_mcp_protocol_server(repo_server)

        yield repo_server, protocol_server, tmp_dir


# =============================================================================
# 1. MCP Protocol Contract: Initialize & List Tools
# =============================================================================

@pytest.mark.asyncio
async def test_protocol_initialize_and_list_tools(mcp_protocol_fixture):
    """Verify MCP protocol handshake and tool listing via official client session."""
    _, protocol_server, _ = mcp_protocol_fixture

    async with create_connected_server_and_client_session(protocol_server) as session:
        init_result = await session.initialize()
        assert init_result.serverInfo.name == "repolens-repository-server"
        assert init_result.protocolVersion is not None

        tools_result = await session.list_tools()
        tool_names = [t.name for t in tools_result.tools]

        expected_tools = [
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
        ]

        for expected in expected_tools:
            assert expected in tool_names

        # Prohibited tools must NOT be present
        forbidden_tools = ["shell", "exec", "eval", "write_file", "env", "secrets"]
        for forbidden in forbidden_tools:
            assert forbidden not in tool_names


# =============================================================================
# 2. MCP Protocol Contract: Valid Tool Calls
# =============================================================================

@pytest.mark.asyncio
async def test_protocol_valid_tool_calls(mcp_protocol_fixture):
    """Verify executing valid tool calls across the official MCP protocol."""
    _, protocol_server, _ = mcp_protocol_fixture

    async with create_connected_server_and_client_session(protocol_server) as session:
        await session.initialize()

        # 1. Manifest
        manifest_res = await session.call_tool("repo_get_manifest", {})
        assert manifest_res.isError is False
        assert len(manifest_res.content) > 0
        manifest_data = json.loads(manifest_res.content[0].text)
        assert manifest_data["repository_url"] == "https://github.com/org/mcp-proto-test.git"

        # 2. Search code
        search_res = await session.call_tool("repo_search_code", {"query": "FastAPI"})
        assert search_res.isError is False
        search_data = json.loads(search_res.content[0].text)
        assert search_data["count"] >= 1
        assert search_data["matches"][0]["file_path"] == "main.py"

        # 3. Read file
        read_res = await session.call_tool("repo_read_file", {"file_path": "main.py", "start_line": 1, "end_line": 2})
        assert read_res.isError is False
        read_data = json.loads(read_res.content[0].text)
        assert "import os" in read_data["content"]
        assert read_data["start_line"] == 1
        assert read_data["end_line"] == 2

        # 4. Get routes
        routes_res = await session.call_tool("repo_get_routes", {})
        assert routes_res.isError is False
        routes_data = json.loads(routes_res.content[0].text)
        assert routes_data["count"] == 1
        assert routes_data["routes"][0]["name"] == "GET /api/v1/health"

        # 5. Contract tracing
        trace_res = await session.call_tool("repo_trace_contract", {"route_or_url": "/api/v1/health"})
        assert trace_res.isError is False
        trace_data = json.loads(trace_res.content[0].text)
        assert trace_data["is_matched"] is True


# =============================================================================
# 3. MCP Protocol Contract: Malformed Arguments Rejection
# =============================================================================

@pytest.mark.asyncio
async def test_protocol_malformed_arguments_rejected(mcp_protocol_fixture):
    """Verify malformed arguments return structured isError=True tool results."""
    _, protocol_server, _ = mcp_protocol_fixture

    async with create_connected_server_and_client_session(protocol_server) as session:
        await session.initialize()

        # Missing query in search_code
        res1 = await session.call_tool("repo_search_code", {})
        assert res1.isError is True
        assert "query" in res1.content[0].text.lower()

        # Empty string query in search_code
        res2 = await session.call_tool("repo_search_code", {"query": ""})
        assert res2.isError is True

        # Missing file_path in read_file
        res3 = await session.call_tool("repo_read_file", {})
        assert res3.isError is True

        # Invalid symbol kind enum
        res4 = await session.call_tool("repo_get_symbols", {"kind": "INVALID_KIND"})
        assert res4.isError is True


# =============================================================================
# 4. MCP Protocol Security: Path Traversal Rejection
# =============================================================================

@pytest.mark.asyncio
async def test_protocol_path_traversal_rejection(mcp_protocol_fixture):
    """Verify path traversal attacks over MCP protocol are rejected without leaking data."""
    _, protocol_server, _ = mcp_protocol_fixture

    async with create_connected_server_and_client_session(protocol_server) as session:
        await session.initialize()

        malicious_paths = [
            "../../etc/passwd",
            "../secret.txt",
            "..\\..\\Windows\\System32\\calc.exe",
            "/etc/shadow",
            "C:\\Windows\\win.ini",
        ]

        for bad_path in malicious_paths:
            res = await session.call_tool("repo_read_file", {"file_path": bad_path})
            assert res.isError is True
            assert "Access denied" in res.content[0].text or "escapes repository boundary" in res.content[0].text


# =============================================================================
# 5. MCP Protocol Security: Unsupported Tool Rejection
# =============================================================================

@pytest.mark.asyncio
async def test_protocol_unsupported_tool_rejected(mcp_protocol_fixture):
    """Verify calling dangerous or unsupported tools is rejected."""
    _, protocol_server, _ = mcp_protocol_fixture

    async with create_connected_server_and_client_session(protocol_server) as session:
        await session.initialize()

        unsupported = ["shell", "bash", "execute_command", "write_file", "eval"]
        for tool_name in unsupported:
            res = await session.call_tool(tool_name, {"command": "whoami"})
            assert res.isError is True
            assert "Unknown MCP tool" in res.content[0].text or "Unknown tool" in res.content[0].text


# =============================================================================
# 6. Independence: Internal Tool Service Works Without Transport
# =============================================================================

@pytest.mark.asyncio
async def test_internal_tool_service_works_without_mcp_transport(mcp_protocol_fixture):
    """Verify canonical MCPRepositoryServer functions directly when no MCP transport is active."""
    repo_server, _, _ = mcp_protocol_fixture

    manifest_resp = await repo_server.call_tool("repo_get_manifest", {})
    assert manifest_resp.is_error is False
    assert manifest_resp.content["total_files"] == 2

    read_resp = await repo_server.call_tool("repo_read_file", {"file_path": "main.py"})
    assert read_resp.is_error is False
    assert "FastAPI" in read_resp.content["content"]
