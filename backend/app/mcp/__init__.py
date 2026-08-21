"""Read-only Model Context Protocol (MCP) server package for RepoLens."""

from app.mcp.adapter import (
    MCPProtocolAdapter,
    create_mcp_protocol_server,
    serve_stdio,
)
from app.mcp.server import MCPRepositoryServer
from app.mcp.types import (
    MCPToolCallRequest,
    MCPToolCallResponse,
    MCPToolDefinition,
)

__all__ = [
    "MCPRepositoryServer",
    "MCPProtocolAdapter",
    "create_mcp_protocol_server",
    "serve_stdio",
    "MCPToolDefinition",
    "MCPToolCallRequest",
    "MCPToolCallResponse",
]
