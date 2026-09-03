"""Read-only Model Context Protocol (MCP) server package for RepoLens."""

from app.mcp.adapter import (
    MCPProtocolAdapter,
    create_mcp_protocol_server,
    serve_stdio,
)
from app.mcp.executor import (
    MAX_MCP_CALLS_PER_TARGET,
    MAX_MCP_CALLS_PER_WORKFLOW,
    MAX_MCP_TARGETS_PER_REVISION,
    RUNTIME_MCP_ALLOWLIST,
    MCPToolEvidence,
    MCPToolExecutionRecord,
    MCPToolExecutor,
)
from app.mcp.runtime_client import MCPNormalizedResult, MCPRuntimeClient
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
    "MCPRuntimeClient",
    "MCPNormalizedResult",
    "MCPToolExecutor",
    "MCPToolEvidence",
    "MCPToolExecutionRecord",
    "RUNTIME_MCP_ALLOWLIST",
    "MAX_MCP_CALLS_PER_WORKFLOW",
    "MAX_MCP_CALLS_PER_TARGET",
    "MAX_MCP_TARGETS_PER_REVISION",
]
