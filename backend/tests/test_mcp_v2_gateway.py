import pytest

from mcp import Client

from app.agent_tools.schemas import (
    AGENT_TOOL_VERSION,
    ToolInvocationResult,
    ToolMetadata,
    ToolResultStatus,
)
from app.mcp.adapter import create_agent_mcp_protocol_server, create_agent_mcp_streamable_http_app
from app.mcp.agent_bridge import MCPAgentToolBridge
from app.mcp.runtime_client import MCPRuntimeClient
from app.mcp.runtime_factory import MCPScanRuntimeFactory


class _FakeRegistry:
    default_snapshot_id = "a" * 40

    def __init__(self):
        self.calls = []

    def list_tools(self):
        return [
            ToolMetadata(
                tool_name="search_symbol",
                tool_version=AGENT_TOOL_VERSION,
                description="Search symbols",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": False,
                },
                output_schema={"type": "object"},
                capability="SYMBOLS",
                timeout_class="FAST",
                evidence_required=True,
            )
        ]

    def invoke(self, name, arguments):
        self.calls.append((name, arguments))
        return ToolInvocationResult(
            tool=name,
            tool_version=AGENT_TOOL_VERSION,
            status=ToolResultStatus.SUCCESS,
            result={"query": arguments["query"]},
        )


def test_bridge_exposes_only_registry_metadata_and_structured_envelope():
    registry = _FakeRegistry()
    bridge = MCPAgentToolBridge(registry)  # type: ignore[arg-type]
    tools = bridge.list_tool_definitions()
    assert [tool.name for tool in tools] == ["search_symbol"]
    assert tools[0].annotations.read_only_hint is True
    assert tools[0].annotations.open_world_hint is False
    assert tools[0].output_schema == ToolInvocationResult.model_json_schema(mode="serialization")

    result = bridge.call_tool_result("search_symbol", {"query": "parse_token"})
    assert result.is_error is False
    assert result.structured_content["contract_version"] == "2.0.0"
    assert registry.calls == [("search_symbol", {"query": "parse_token", "snapshot_id": "a" * 40})]


def test_bridge_rejects_unknown_and_snapshot_switch():
    bridge = MCPAgentToolBridge(_FakeRegistry())  # type: ignore[arg-type]
    unknown = bridge.invoke("run_shell", {})
    assert unknown.status is ToolResultStatus.UNSUPPORTED
    switched = bridge.invoke("search_symbol", {"query": "x", "snapshot_id": "b" * 40})
    assert switched.status is ToolResultStatus.INVALID_INPUT


@pytest.mark.asyncio
async def test_v2_client_negotiates_modern_protocol_and_calls_bridge():
    server = create_agent_mcp_protocol_server(MCPAgentToolBridge(_FakeRegistry()))  # type: ignore[arg-type]
    async with Client(server) as client:
        assert client.protocol_version == "2026-07-28"
        tools = await client.list_tools()
        assert [item.name for item in tools.tools] == ["search_symbol"]
        result = await client.call_tool("search_symbol", {"query": "parse_token"})
        assert result.is_error is False
        assert result.structured_content["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_runtime_client_accepts_first_class_v2_protocol_server():
    server = create_agent_mcp_protocol_server(MCPAgentToolBridge(_FakeRegistry()))  # type: ignore[arg-type]
    client = MCPRuntimeClient(protocol_server=server)
    result = await client.call_tool("search_symbol", {"query": "parse_token"})
    assert result.is_error is False
    assert client.protocol_version == "2026-07-28"
    await client.aclose()


def test_streamable_http_helper_is_loopback_only():
    bridge = MCPAgentToolBridge(_FakeRegistry())  # type: ignore[arg-type]
    app = create_agent_mcp_streamable_http_app(bridge)
    assert any(getattr(route, "path", None) == "/mcp" for route in app.routes)
    with pytest.raises(ValueError):
        create_agent_mcp_streamable_http_app(bridge, host="0.0.0.0")


def test_scan_runtime_factory_binds_registry_snapshot():
    registry = _FakeRegistry()
    runtime = MCPScanRuntimeFactory.create(scan_id="scan-1", tenant_id="tenant-1", registry=registry)  # type: ignore[arg-type]
    assert runtime.snapshot_id == registry.default_snapshot_id
    with pytest.raises(ValueError):
        MCPScanRuntimeFactory.create(
            scan_id="scan-1",
            tenant_id="tenant-1",
            registry=registry,  # type: ignore[arg-type]
            snapshot_id="b" * 40,
        )
