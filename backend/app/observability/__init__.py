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
from .metrics import (
    METRIC_CATALOG,
    METRIC_CATALOG_VERSION,
    configure_metrics,
    metrics_enabled,
    record_metric,
    replace_metric_gauges,
    shutdown_metrics,
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
    "METRIC_CATALOG",
    "METRIC_CATALOG_VERSION",
    "configure_metrics",
    "metrics_enabled",
    "record_metric",
    "replace_metric_gauges",
    "shutdown_metrics",
]
