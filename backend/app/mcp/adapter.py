"""Thin Model Context Protocol (MCP) adapter connecting MCPRepositoryServer to the official MCP SDK."""

import json
from typing import Any, Dict, List, Optional

from mcp.server.lowlevel import Server
import mcp.types as mcp_types

from app.mcp.server import MCPRepositoryServer
from app.mcp.types import MCPToolCallResponse, MCPToolDefinition


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
        version: str = "1.0.0",
    ):
        self.repo_server = repo_server
        self.server_name = server_name
        self.version = version
        self._mcp_server: Optional[Server] = None

    def get_protocol_server(self) -> Server:
        """Create and configure the official MCP lowlevel Server instance."""
        if self._mcp_server is not None:
            return self._mcp_server

        app = Server(self.server_name, version=self.version)

        @app.list_tools()
        async def handle_list_tools() -> List[mcp_types.Tool]:
            definitions = self.repo_server.list_tools()
            tools: List[mcp_types.Tool] = []
            for tool_def in definitions:
                tools.append(
                    mcp_types.Tool(
                        name=tool_def.name,
                        description=tool_def.description,
                        inputSchema=tool_def.parameters,
                    )
                )
            return tools

        @app.call_tool()
        async def handle_call_tool(
            name: str,
            arguments: Optional[Dict[str, Any]] = None,
        ) -> mcp_types.CallToolResult:
            args = arguments if isinstance(arguments, dict) else {}

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

        self._mcp_server = app
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
    version: str = "1.0.0",
) -> Server:
    """Convenience factory returning the configured official MCP Server instance."""
    adapter = MCPProtocolAdapter(repo_server=repo_server, server_name=server_name, version=version)
    return adapter.get_protocol_server()


async def serve_stdio(repo_server: MCPRepositoryServer) -> None:
    """Convenience runner to start stdio MCP transport for a repository server."""
    adapter = MCPProtocolAdapter(repo_server=repo_server)
    await adapter.run_stdio()
