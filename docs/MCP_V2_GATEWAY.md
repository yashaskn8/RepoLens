# RepoLens MCP v2 gateway

RepoLens keeps its legacy `repo_*` MCP server and `MCPToolExecutor` for the
deterministic enrichment workflow.  The Phase-D gateway is a separate,
scan-bound adapter over `AgentToolRegistry` and uses the official MCP SDK
2.x `Client(server)`/low-level `Server` APIs.

The external gateway exposes only these read-only capabilities:

`inspect_file`, `search_symbol`, `read_source_slice`, `inspect_symbol`,
`find_callers`, `find_callees`, `trace_dataflow`, `scan_security`, and
`verify_finding`.

Tool schemas and the structured `ToolInvocationResult` envelope are derived
from the canonical registry.  Every call is bound to the registry's immutable
repository snapshot; model-supplied snapshot identities are rejected or must
match the binding for nested verification claims.  Registry validation,
redaction, deterministic evidence provenance, and resource limits remain the
execution authority.  MCP annotations are descriptive and never grant
authorization.

Protocol sessions negotiate MCP `2026-07-28` by default, with the SDK's
legacy fallback available for compatibility.  Streamable HTTP is exposed only
through the SDK app and the helper defaults to loopback (`127.0.0.1`); the
main FastAPI application does not publish an unauthenticated public `/mcp`
route.  Remote OAuth/authentication is a hosting concern and is not enabled by
this gateway.

The existing deterministic enrichment path is unchanged.  No scanner, LLM,
shell, network, repository write, GitHub write, database, or tenant-selection
capability is exposed through the gateway.
