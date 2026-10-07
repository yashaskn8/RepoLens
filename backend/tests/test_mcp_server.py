"""Contract and security tests for the read-only MCP repository intelligence server."""

import os
import hashlib
import tempfile
from types import SimpleNamespace
import pytest

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import FileEntry, ParsedSymbol, RepositoryManifest, SymbolKind
from app.mcp.server import MCPRepositoryServer
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence


@pytest.fixture
def mcp_server_fixture(monkeypatch):
    """Create a temporary repository directory with files, evidence store, and MCP server instance."""
    monkeypatch.setattr("app.mcp.server.get_settings", lambda: SimpleNamespace(MAX_FILE_SIZE_BYTES=1_048_576))
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
            total_size_bytes=os.path.getsize(main_py_path) + os.path.getsize(api_ts_path),
            languages={"python": 1, "typescript": 1},
            files=[
                FileEntry(
                    path="main.py",
                    language="python",
                    size_bytes=os.path.getsize(main_py_path),
                    content_sha256=hashlib.sha256(open(main_py_path, "rb").read()).hexdigest(),
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
                    size_bytes=os.path.getsize(api_ts_path),
                    content_sha256=hashlib.sha256(open(api_ts_path, "rb").read()).hexdigest(),
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
async def test_mcp_search_rejects_same_size_source_drift(mcp_server_fixture):
    server, repo_dir = mcp_server_fixture
    path = os.path.join(repo_dir, "main.py")
    original = open(path, "rb").read()
    with open(path, "wb") as source_file:
        source_file.write(bytes([original[0] ^ 1]) + original[1:])

    result = await server.call_tool("repo_search_code", {"query": "FastAPI"})

    assert result.is_error is True
    assert result.error_message == (
        "MCP_SOURCE_SNAPSHOT_DRIFT: Source no longer matches the authorized repository snapshot."
    )


@pytest.mark.asyncio
async def test_mcp_search_bounds_long_matching_lines(mcp_server_fixture):
    import json
    from app.mcp.constants import MAX_MCP_RESULT_BYTES, MAX_MCP_SNIPPET_CHARS

    server, repo_dir = mcp_server_fixture
    payload = b"needle " + b"x" * 400_000
    path = os.path.join(repo_dir, "long-line.py")
    with open(path, "wb") as source_file:
        source_file.write(payload)
    entry = FileEntry(
        path="long-line.py",
        language="python",
        size_bytes=len(payload),
        content_sha256=hashlib.sha256(payload).hexdigest(),
        lines_count=1,
    )
    server.evidence_store.manifest.files.append(entry)
    server.evidence_store._files_by_path[entry.path] = entry

    result = await server.call_tool("repo_search_code", {"query": "needle"})

    assert result.is_error is False
    assert len(result.content["matches"][0]["line_content"]) <= MAX_MCP_SNIPPET_CHARS
    assert result.content["truncated"] is True
    assert len(json.dumps(result.content, ensure_ascii=False).encode("utf-8")) <= MAX_MCP_RESULT_BYTES


@pytest.mark.asyncio
async def test_mcp_symbol_collection_is_cardinality_bounded(mcp_server_fixture, monkeypatch):
    from types import SimpleNamespace
    from app.mcp.constants import MAX_MCP_SERVER_COLLECTION_ITEMS

    server, _ = mcp_server_fixture
    monkeypatch.setattr(
        server.evidence_store,
        "get_symbols",
        lambda **_kwargs: [
            SimpleNamespace(model_dump=lambda: {"name": f"symbol_{index}"})
            for index in range(MAX_MCP_SERVER_COLLECTION_ITEMS + 1)
        ],
    )

    result = await server.call_tool("repo_get_symbols", {})

    assert result.is_error is False
    assert result.content["count"] == MAX_MCP_SERVER_COLLECTION_ITEMS + 1
    assert result.content["returned_count"] == MAX_MCP_SERVER_COLLECTION_ITEMS
    assert result.content["truncated"] is True


@pytest.mark.asyncio
async def test_mcp_result_byte_cap_rejects_oversized_structured_record(mcp_server_fixture, monkeypatch):
    from types import SimpleNamespace

    server, _ = mcp_server_fixture
    monkeypatch.setattr(
        server.evidence_store,
        "get_symbols",
        lambda **_kwargs: [SimpleNamespace(model_dump=lambda: {"name": "x" * 60_000})],
    )

    result = await server.call_tool("repo_get_symbols", {})

    assert result.is_error is True
    assert result.error_message == (
        "MCP_RESULT_RESOURCE_LIMIT: Tool result exceeded the configured response size limit."
    )
    assert result.content is None


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
async def test_mcp_read_rejects_unmanifested_git_pack_file(mcp_server_fixture):
    server, repo_dir = mcp_server_fixture
    pack_dir = os.path.join(repo_dir, ".git", "objects", "pack")
    os.makedirs(pack_dir)
    with open(os.path.join(pack_dir, "pack-hostile"), "wb") as pack:
        pack.write(b"x" * 100_000)

    result = await server.call_tool(
        "repo_read_file",
        {"file_path": ".git/objects/pack/pack-hostile", "start_line": 1, "end_line": 200},
    )

    assert result.is_error is True
    assert result.error_message == "MCP_FILE_NOT_AUTHORIZED: File is not present in the repository manifest."


@pytest.mark.asyncio
async def test_mcp_read_bounds_a_single_oversized_source_line(mcp_server_fixture):
    from app.mcp.constants import MAX_MCP_SERVER_SOURCE_READ_BYTES

    server, repo_dir = mcp_server_fixture
    payload = b"x" * (MAX_MCP_SERVER_SOURCE_READ_BYTES + 5_000)
    source_path = os.path.join(repo_dir, "long-line.py")
    with open(source_path, "wb") as source_file:
        source_file.write(payload)
    entry = FileEntry(
        path="long-line.py",
        language="python",
        size_bytes=len(payload),
        content_sha256=hashlib.sha256(payload).hexdigest(),
        lines_count=1,
    )
    server.evidence_store.manifest.files.append(entry)
    server.evidence_store._files_by_path[entry.path] = entry

    result = await server.call_tool(
        "repo_read_file",
        {"file_path": "long-line.py", "start_line": 1, "end_line": 1},
    )

    assert result.is_error is False
    assert len(result.content["content"].encode("utf-8")) <= MAX_MCP_SERVER_SOURCE_READ_BYTES
    assert result.content["truncated"] is True


@pytest.mark.asyncio
async def test_mcp_read_rejects_same_size_snapshot_drift(mcp_server_fixture):
    server, repo_dir = mcp_server_fixture
    path = os.path.join(repo_dir, "main.py")
    original = open(path, "rb").read()
    with open(path, "wb") as source_file:
        source_file.write(bytes([original[0] ^ 1]) + original[1:])
    assert os.path.getsize(path) == len(original)

    result = await server.call_tool("repo_read_file", {"file_path": "main.py"})

    assert result.is_error is True
    assert result.error_message == (
        "MCP_SOURCE_SNAPSHOT_DRIFT: Source no longer matches the authorized repository snapshot."
    )


@pytest.mark.asyncio
async def test_mcp_read_reports_actual_range_and_explicit_truncation(mcp_server_fixture):
    server, _ = mcp_server_fixture

    short = await server.call_tool("repo_read_file", {"file_path": "main.py"})
    assert short.is_error is False
    assert short.content["end_line"] == short.content["total_lines"]
    assert short.content["truncated"] is False

    long = await server.call_tool(
        "repo_read_file",
        {"file_path": "main.py", "start_line": 1, "end_line": 1_000},
    )
    assert long.is_error is False
    assert long.content["end_line"] == long.content["total_lines"]
    assert long.content["truncated"] is False


@pytest.mark.asyncio
async def test_mcp_read_out_of_range_start_fails_before_opening_file(mcp_server_fixture, monkeypatch):
    import builtins

    server, _ = mcp_server_fixture
    original_open = builtins.open

    def fail_source_open(path, *args, **kwargs):
        if os.fspath(path).endswith("main.py"):
            raise AssertionError("out-of-range request opened source")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fail_source_open)

    result = await server.call_tool(
        "repo_read_file",
        {"file_path": "main.py", "start_line": 1_000_000},
    )

    assert result.is_error is True
    assert result.error_message.startswith("MCP_LINE_NOT_FOUND:")


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
