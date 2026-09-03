"""Read-only Model Context Protocol (MCP) server package for RepoLens."""

from app.mcp.adapter import (
    MCPProtocolAdapter,
    create_mcp_protocol_server,
    serve_stdio,
)
from app.mcp.constants import (
    DEFAULT_MCP_INITIALIZATION_TIMEOUT_SECONDS,
    DEFAULT_MCP_TOOL_TIMEOUT_SECONDS,
    MAX_LINE_SPAN_READ,
    MAX_MCP_CALLS_PER_TARGET,
    MAX_MCP_CALLS_PER_WORKFLOW,
    MAX_MCP_CLIENT_RESULT_BYTES,
    MAX_MCP_LIST_ITEMS,
    MAX_MCP_RESULT_BYTES,
    MAX_MCP_SERVER_COLLECTION_ITEMS,
    MAX_MCP_SNIPPET_CHARS,
    MAX_MCP_TARGETS_PER_REVISION,
    MAX_MCP_TEXT_CHARS,
    RUNTIME_MCP_ALLOWLIST,
)
from app.mcp.executor import (
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
    "MAX_MCP_RESULT_BYTES",
    "MAX_MCP_CLIENT_RESULT_BYTES",
    "MAX_MCP_SERVER_COLLECTION_ITEMS",
    "MAX_MCP_TEXT_CHARS",
    "MAX_MCP_LIST_ITEMS",
    "MAX_MCP_SNIPPET_CHARS",
    "MAX_LINE_SPAN_READ",
    "DEFAULT_MCP_INITIALIZATION_TIMEOUT_SECONDS",
    "DEFAULT_MCP_TOOL_TIMEOUT_SECONDS",
]
