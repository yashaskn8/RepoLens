"""Shared constants and threshold limits for RepoLens Model Context Protocol (MCP) subsystem."""

# Timeout limits (seconds)
DEFAULT_MCP_INITIALIZATION_TIMEOUT_SECONDS: float = 10.0
DEFAULT_MCP_TOOL_TIMEOUT_SECONDS: float = 10.0

# Payload and memory bounds
MAX_MCP_RESULT_BYTES: int = 50_000
MAX_MCP_CLIENT_RESULT_BYTES: int = MAX_MCP_RESULT_BYTES

# Server collection cardinality bounds
MAX_MCP_SERVER_COLLECTION_ITEMS: int = 50

# Executor and prompt limits
MAX_MCP_TEXT_CHARS: int = 20_000
MAX_MCP_LIST_ITEMS: int = 20
MAX_MCP_SNIPPET_CHARS: int = 5_000
MAX_LINE_SPAN_READ: int = 200

# Quotas and budgets
MAX_MCP_TARGETS_PER_REVISION: int = 4
MAX_MCP_CALLS_PER_TARGET: int = 2
MAX_MCP_CALLS_PER_WORKFLOW: int = 8

# Runtime tool allowlist
RUNTIME_MCP_ALLOWLIST: frozenset[str] = frozenset({
    "repo_read_file",
    "repo_get_related_symbols",
    "repo_trace_contract",
    "repo_retrieve_context",
    "repo_get_static_findings",
})

# Protocol-facing agent gateway allowlist.  This is deliberately separate
# from the legacy repo_* enrichment allowlist above; both remain authoritative
# for their respective consumers.
MCP_AGENT_TOOL_ALLOWLIST: frozenset[str] = frozenset({
    "inspect_file",
    "search_symbol",
    "read_source_slice",
    "inspect_symbol",
    "find_callers",
    "find_callees",
    "trace_dataflow",
    "scan_security",
    "verify_finding",
})
