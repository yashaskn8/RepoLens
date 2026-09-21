"""Thin Model Context Protocol (MCP) adapter connecting MCPRepositoryServer to the official MCP SDK."""

import json
from typing import Any, List, Optional

from mcp.server.lowlevel import Server
import mcp.types as mcp_types

from app.mcp.server import MCPRepositoryServer
from app.mcp.types import MCPToolCallResponse
from app.mcp.agent_bridge import MCPAgentToolBridge


class MCPProtocolAdapter:
    """Adapts a canonical MCPRepositoryServer to the official Python MCP protocol Server.

    Guarantees:
    - Exposes only the approved read-only repository intelligence tools.
    - Zero shell execution, arbitrary filesystem access, environment variable exposure, or repository mutations.
    - Protocol requests are strictly delegated to MCPRepositoryServer without duplicating repository logic.
    - Gracefully formats responses and errors as standardized MCP CallToolResults.
    """

    def __init__(
        self,
        repo_server: MCPRepositoryServer,
        server_name: str = "repolens-repository-server",
        version: str = "1.0.1",
    ):
        self.repo_server = repo_server
        self.server_name = server_name
        self.version = version
        self._mcp_server: Optional[Server] = None

    def get_protocol_server(self) -> Server:
        """Create and configure the official MCP lowlevel Server instance."""
        if self._mcp_server is not None:
            return self._mcp_server

        async def handle_list_tools(_ctx: Any, _params: Any) -> mcp_types.ListToolsResult:
            definitions = self.repo_server.list_tools()
            tools: List[mcp_types.Tool] = []
            for tool_def in definitions:
                tools.append(
                    mcp_types.Tool(
                        name=tool_def.name,
                        description=tool_def.description,
                        inputSchema=tool_def.parameters,
                        annotations=mcp_types.ToolAnnotations(
                            readOnlyHint=True,
                            destructiveHint=False,
                            idempotentHint=True,
                            openWorldHint=False,
                        ),
                    )
                )
            return mcp_types.ListToolsResult(tools=tools)

        async def handle_call_tool(_ctx: Any, params: mcp_types.CallToolRequestParams) -> mcp_types.CallToolResult:
            name = params.name
            args = params.arguments if isinstance(params.arguments, dict) else {}

            # Strict delegation to canonical MCPRepositoryServer
            tool_resp: MCPToolCallResponse = await self.repo_server.call_tool(name, args)

            if tool_resp.is_error:
                error_msg = tool_resp.error_message or f"Tool '{name}' execution failed."
                return mcp_types.CallToolResult(
                    isError=True,
                    content=[mcp_types.TextContent(type="text", text=error_msg)],
                )

            # Serialize output content deterministically
            if isinstance(tool_resp.content, (dict, list)):
                serialized_content = json.dumps(tool_resp.content, indent=2, default=str)
            else:
                serialized_content = str(tool_resp.content) if tool_resp.content is not None else ""

            return mcp_types.CallToolResult(
                isError=False,
                content=[mcp_types.TextContent(type="text", text=serialized_content)],
            )

        self._mcp_server = Server(
            self.server_name,
            version=self.version,
            on_list_tools=handle_list_tools,
            on_call_tool=handle_call_tool,
        )
        return self._mcp_server

    async def run_stdio(self) -> None:
        """Run the MCP protocol server over local stdio transport."""
        from mcp.server.stdio import stdio_server

        server = self.get_protocol_server()
        async with stdio_server() as (read_stream, write_stream):
            init_options = server.create_initialization_options()
            await server.run(read_stream, write_stream, init_options)


def create_mcp_protocol_server(
    repo_server: MCPRepositoryServer,
    server_name: str = "repolens-repository-server",
    version: str = "1.0.1",
) -> Server:
    """Convenience factory returning the configured official MCP Server instance."""
    adapter = MCPProtocolAdapter(repo_server=repo_server, server_name=server_name, version=version)
    return adapter.get_protocol_server()


async def serve_stdio(repo_server: MCPRepositoryServer) -> None:
    """Convenience runner to start stdio MCP transport for a repository server."""
    adapter = MCPProtocolAdapter(repo_server=repo_server)
    await adapter.run_stdio()


class MCPAgentProtocolAdapter:
    """MCP v2 protocol adapter over the canonical AgentToolRegistry bridge."""

    def __init__(
        self,
        bridge: MCPAgentToolBridge,
        server_name: str = "repolens-agent-gateway",
        version: str = "2.0.0",
    ) -> None:
        self.bridge = bridge
        self.server_name = server_name
        self.version = version
        self._mcp_server: Optional[Server] = None

    def get_protocol_server(self) -> Server:
        if self._mcp_server is not None:
            return self._mcp_server

        async def handle_list_tools(_ctx: Any, _params: Any) -> mcp_types.ListToolsResult:
            return mcp_types.ListToolsResult(tools=self.bridge.list_tool_definitions())

        async def handle_call_tool(_ctx: Any, params: mcp_types.CallToolRequestParams) -> mcp_types.CallToolResult:
            args = params.arguments if isinstance(params.arguments, dict) else {}
            return self.bridge.call_tool_result(params.name, args)

        self._mcp_server = Server(
            self.server_name,
            version=self.version,
            on_list_tools=handle_list_tools,
            on_call_tool=handle_call_tool,
        )
        return self._mcp_server

    async def run_stdio(self) -> None:
        from mcp.server.stdio import stdio_server

        server = self.get_protocol_server()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())


def create_agent_mcp_protocol_server(
    bridge: MCPAgentToolBridge,
    server_name: str = "repolens-agent-gateway",
    version: str = "2.0.0",
) -> Server:
    """Create an MCP v2 server exposing only the scan-bound agent gateway."""
    return MCPAgentProtocolAdapter(bridge=bridge, server_name=server_name, version=version).get_protocol_server()


def create_agent_mcp_streamable_http_app(
    bridge: MCPAgentToolBridge,
    *,
    host: str = "127.0.0.1",
    streamable_http_path: str = "/mcp",
) -> Any:
    """Create the SDK-owned Streamable HTTP app for loopback-only use.

    Remote deployment must supply an authentication verifier at the hosting
    boundary; this helper intentionally refuses non-loopback unauthenticated
    exposure and never adds a public route to the main FastAPI app.
    """
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("unauthenticated MCP HTTP is restricted to loopback hosts")
    server = create_agent_mcp_protocol_server(bridge)
    return server.streamable_http_app(host=host, streamable_http_path=streamable_http_path)
