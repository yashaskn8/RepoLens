"""Contract and security tests for the read-only MCP repository intelligence server."""

import os
import tempfile
import pytest

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import FileEntry, ParsedSymbol, RepositoryManifest, SymbolKind
from app.mcp.server import MCPRepositoryServer
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence


@pytest.fixture
def mcp_server_fixture():
    """Create a temporary repository directory with files, evidence store, and MCP server instance."""
    with tempfile.TemporaryDirectory(prefix="mcp_repo_test_") as tmp_dir:
        # Create a sample python file
        main_py_path = os.path.join(tmp_dir, "main.py")
        with open(main_py_path, "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "from fastapi import FastAPI\n\n"
                "app = FastAPI()\n\n"
                "@app.get('/health')\n"
                "def health():\n"
                "    return {'status': 'healthy'}\n"
            )

        # Create a sample typescript file
        api_ts_path = os.path.join(tmp_dir, "api.ts")
        with open(api_ts_path, "w", encoding="utf-8") as f:
            f.write(
                "export async function fetchHealth() {\n"
                "    return fetch('/health');\n"
                "}\n"
            )

        manifest = RepositoryManifest(
            repository_url="https://github.com/org/mcp-test.git",
            commit_hash="deadbeef12345678",
            total_files=2,
            total_size_bytes=250,
            languages={"python": 1, "typescript": 1},
            files=[
                FileEntry(
                    path="main.py",
                    language="python",
                    size_bytes=120,
                    lines_count=8,
                    symbols=[
                        ParsedSymbol(
                            name="import os",
                            kind=SymbolKind.IMPORT,
                            start_line=1,
                            end_line=1,
                        ),
                        ParsedSymbol(
                            name="GET /health",
                            kind=SymbolKind.FASTAPI_ROUTE,
                            start_line=6,
                            end_line=8,
                            details={"http_method": "GET", "path": "/health"},
                        ),
                    ],
                ),
                FileEntry(
                    path="api.ts",
                    language="typescript",
                    size_bytes=130,
                    lines_count=3,
                    symbols=[
                        ParsedSymbol(
                            name="fetch(/health)",
                            kind=SymbolKind.FETCH_CALL,
                            start_line=2,
                            end_line=2,
                            details={"target": "/health"},
                        ),
                    ],
                ),
            ],
        )

        finding = StaticFinding(
            tool="semgrep",
            rule_id="python.security.test",
            title="Test Finding",
            description="Sample security finding",
            severity=Severity.HIGH,
            category="security",
            evidence=Evidence(file_path="main.py", start_line=6, end_line=8),
        )

        scanner_results = {
            "semgrep": ScannerResult(tool="semgrep", status=ToolStatus.COMPLETED, findings=[finding])
        }

        store = EvidenceStore(manifest=manifest, scanner_results=scanner_results)
        server = MCPRepositoryServer(evidence_store=store, repo_dir=tmp_dir)

        yield server, tmp_dir


def test_mcp_list_tools_contract(mcp_server_fixture):
    """Verify that MCP server exposes the required tools with schema definitions."""
    server, _ = mcp_server_fixture
    tools = server.list_tools()
    tool_names = [t.name for t in tools]

    expected_tools = [
        "repo_get_manifest",
        "repo_search_code",
        "repo_read_file",
        "repo_get_symbols",
        "repo_get_routes",
        "repo_get_frontend_requests",
        "repo_get_static_findings",
    ]

    for expected in expected_tools:
        assert expected in tool_names


@pytest.mark.asyncio
async def test_mcp_tool_repo_get_manifest(mcp_server_fixture):
    """Verify repo_get_manifest execution."""
    server, _ = mcp_server_fixture
    res = await server.call_tool("repo_get_manifest", {})
    assert res.is_error is False
    assert res.content["repository_url"] == "https://github.com/org/mcp-test.git"
    assert res.content["total_files"] == 2


@pytest.mark.asyncio
async def test_mcp_tool_repo_search_code(mcp_server_fixture):
    """Verify repo_search_code matches substrings across files safely."""
    server, _ = mcp_server_fixture
    res = await server.call_tool("repo_search_code", {"query": "FastAPI"})
    assert res.is_error is False
    assert res.content["count"] >= 1
    assert res.content["matches"][0]["file_path"] == "main.py"
    assert "FastAPI" in res.content["matches"][0]["line_content"]


@pytest.mark.asyncio
async def test_mcp_tool_repo_read_file_safe_range(mcp_server_fixture):
    """Verify repo_read_file reads specific line spans."""
    server, _ = mcp_server_fixture
    res = await server.call_tool("repo_read_file", {"file_path": "main.py", "start_line": 1, "end_line": 2})
    assert res.is_error is False
    assert res.content["file_path"] == "main.py"
    assert res.content["start_line"] == 1
    assert res.content["end_line"] == 2
    assert "import os" in res.content["content"]


@pytest.mark.asyncio
async def test_mcp_tool_repo_get_symbols_and_routes(mcp_server_fixture):
    """Verify repo_get_symbols and repo_get_routes."""
    server, _ = mcp_server_fixture
    routes_res = await server.call_tool("repo_get_routes", {})
    assert routes_res.is_error is False
    assert routes_res.content["count"] == 1
    assert routes_res.content["routes"][0]["name"] == "GET /health"

    symbols_res = await server.call_tool("repo_get_symbols", {"kind": "IMPORT"})
    assert symbols_res.is_error is False
    assert symbols_res.content["count"] == 1
    assert symbols_res.content["symbols"][0]["name"] == "import os"


@pytest.mark.asyncio
async def test_mcp_tool_repo_get_frontend_requests_and_findings(mcp_server_fixture):
    """Verify repo_get_frontend_requests and repo_get_static_findings."""
    server, _ = mcp_server_fixture
    req_res = await server.call_tool("repo_get_frontend_requests", {})
    assert req_res.is_error is False
    assert req_res.content["count"] == 1
    assert "fetch" in req_res.content["http_calls"][0]["name"]

    find_res = await server.call_tool("repo_get_static_findings", {"tool": "semgrep"})
    assert find_res.is_error is False
    assert find_res.content["count"] == 1
    assert find_res.content["findings"][0]["rule_id"] == "python.security.test"


@pytest.mark.asyncio
async def test_mcp_security_path_traversal_rejection(mcp_server_fixture):
    """Security Test: Path traversal attempts must be denied without leaking host files."""
    server, _ = mcp_server_fixture

    traversal_paths = [
        "../../etc/passwd",
        "../secret.txt",
        "..\\..\\Windows\\System32",
        "/etc/shadow",
    ]

    for p in traversal_paths:
        res = await server.call_tool("repo_read_file", {"file_path": p})
        assert res.is_error is True
        assert "Access denied" in res.error_message or "escapes repository boundary" in res.error_message


@pytest.mark.asyncio
async def test_mcp_security_unknown_tool_rejection(mcp_server_fixture):
    """Security Test: Invoking non-existent or dangerous tool names returns safe error."""
    server, _ = mcp_server_fixture
    res = await server.call_tool("system_exec", {"cmd": "whoami"})
    assert res.is_error is True
    assert "Unknown MCP tool" in res.error_message
