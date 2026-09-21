"""Optional, content-free distributed tracing for RepoLens."""

from .tracing import (
    configure_tracing,
    current_trace_headers,
    extract_trace_context,
    inject_trace_context,
    shutdown_tracing,
    span,
    span_event,
    mcp_server_tool_span_active,
    is_mcp_server_tool_span_active,
)

__all__ = [
    "configure_tracing",
    "current_trace_headers",
    "extract_trace_context",
    "inject_trace_context",
    "shutdown_tracing",
    "span",
    "span_event",
    "mcp_server_tool_span_active",
    "is_mcp_server_tool_span_active",
]
