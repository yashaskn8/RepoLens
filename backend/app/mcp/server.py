"""Read-only Model Context Protocol (MCP) server exposing repository intelligence."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.analysis.store import EvidenceStore
from app.context.engine import ContextEngine
from app.graph.matcher import match_route_contract, normalize_route_path
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import GraphNode, NodeKind
from app.ingestion.schemas import SymbolKind
from app.mcp.types import (
    MCPToolCallRequest,
    MCPToolCallResponse,
    MCPToolDefinition,
)
from app.schemas.enums import Severity


class MCPRepositoryServer:
    """Read-only MCP Server providing typed, secure access to repository intelligence.
    
    Guarantees:
    - No arbitrary filesystem access or path traversal outside the repository root.
    - No shell command execution.
    - No direct vector database access or ungrounded graph mutations.
    - Zero write operations.
    - Repository content is treated strictly as data.
    """

    def __init__(
        self,
        evidence_store: EvidenceStore,
        repo_dir: str,
        repository_graph: Optional[RepositoryGraph] = None,
        context_engine: Optional[ContextEngine] = None,
    ):
        self.evidence_store = evidence_store
        self.repo_dir = os.path.abspath(repo_dir)
        self.repository_graph = repository_graph
        self.context_engine = context_engine

    def _resolve_safe_path(self, relative_path: str) -> str:
        """Ensure file path is strictly localized within repo_dir, preventing path traversal."""
        if not relative_path or not isinstance(relative_path, str):
            raise ValueError("File path must be a non-empty string.")

        # Disallow control characters, null bytes
        if "\x00" in relative_path:
            raise ValueError("Invalid characters in file path.")

        # Disallow absolute paths (POSIX leading slash, Windows drive letter or backslash)
        if (
            os.path.isabs(relative_path)
            or relative_path.startswith(("/", "\\"))
            or (len(relative_path) >= 2 and relative_path[1] == ":")
        ):
            raise PermissionError(f"Access denied: absolute path '{relative_path}' is prohibited.")

        # Normalize and resolve relative to repository workspace
        clean_path = relative_path.replace("\\", "/")
        full_path = os.path.abspath(os.path.join(self.repo_dir, clean_path))

        # Strict containment check
        if not full_path.startswith(self.repo_dir + os.sep) and full_path != self.repo_dir:
            raise PermissionError(f"Access denied: path '{relative_path}' escapes repository boundary.")

        return full_path

    def list_tools(self) -> List[MCPToolDefinition]:
        """Return the definitions of all available MCP tools."""
        return [
            MCPToolDefinition(
                name="repo_get_manifest",
                description="Get repository manifest summary including detected languages, frameworks, file counts, and commit hash.",
                parameters={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_search_code",
                description="Search for exact substring occurrences across text files in the repository.",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Text substring to search for"},
                        "max_results": {"type": "integer", "description": "Maximum matching lines to return (default: 20)", "default": 20},
                        "language": {"type": "string", "description": "Optional language filter (e.g. python, typescript)"},
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_read_file",
                description="Safely read the text content and line range of a specific file in the repository.",
                parameters={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Relative file path from repository root"},
                        "start_line": {"type": "integer", "description": "Optional starting line (1-indexed)"},
                        "end_line": {"type": "integer", "description": "Optional ending line (1-indexed)"},
                    },
                    "required": ["file_path"],
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_get_symbols",
                description="Retrieve AST parsed symbols (functions, classes, methods, imports) filtered by file or kind.",
                parameters={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Optional relative file path filter"},
                        "kind": {
                            "type": "string",
                            "enum": ["FUNCTION", "CLASS", "METHOD", "IMPORT", "FASTAPI_ROUTE", "EXPRESS_ROUTE", "FETCH_CALL", "AXIOS_CALL"],
                            "description": "Optional symbol kind filter",
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_get_routes",
                description="Retrieve all detected backend API routes (FastAPI and Express) with HTTP methods, paths, and source locations.",
                parameters={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_get_frontend_requests",
                description="Retrieve all detected frontend client HTTP calls (fetch and axios) with target URLs and locations.",
                parameters={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_get_static_findings",
                description="Retrieve deterministic static analysis findings from Semgrep, Trivy, and OSV-Scanner.",
                parameters={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Optional relative file path filter"},
                        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], "description": "Optional severity filter"},
                        "category": {"type": "string", "description": "Optional category filter (e.g. sast, vulnerability, secret, misconfiguration, dependency)"},
                        "tool": {"type": "string", "description": "Optional scanner tool filter (semgrep, trivy, osv-scanner)"},
                    },
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_get_related_symbols",
                description="Retrieve related symbols and module dependencies connected via structural relationship graph edges.",
                parameters={
                    "type": "object",
                    "properties": {
                        "symbol_name": {"type": "string", "description": "Symbol name or function to trace"},
                        "file_path": {"type": "string", "description": "Optional file path containing the symbol"},
                    },
                    "required": ["symbol_name"],
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_trace_contract",
                description="Trace cross-layer frontend/backend API contract alignment for a specific route or endpoint.",
                parameters={
                    "type": "object",
                    "properties": {
                        "route_or_url": {"type": "string", "description": "Route path or client URL pattern (e.g. /api/users/:id or /api/users/{id})"},
                        "http_method": {"type": "string", "description": "Optional HTTP method (GET, POST, PUT, DELETE)"},
                    },
                    "required": ["route_or_url"],
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                name="repo_retrieve_context",
                description="Retrieve an evidence-grounded, bounded ContextBundle with relevant code chunks, graph edges, and static findings.",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Targeted search query describing needed context"},
                        "analysis_intent": {"type": "string", "description": "Specialist intent (architecture, integration, security, bug, verification)"},
                        "max_chunks": {"type": "integer", "description": "Maximum number of code chunks to include (default: 5)", "default": 5},
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            ),
        ]

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> MCPToolCallResponse:
        """Dispatch tool invocation with error containment."""
        try:
            if tool_name == "repo_get_manifest":
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content=self.evidence_store.get_summary(),
                )

            elif tool_name == "repo_search_code":
                query = arguments.get("query", "")
                if not query or not isinstance(query, str):
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Parameter 'query' must be a non-empty string.")

                max_results = min(int(arguments.get("max_results", 20)), 100)
                lang_filter = arguments.get("language")
                matches = []

                for file_entry in self.evidence_store.manifest.files:
                    if file_entry.is_binary or file_entry.skipped_reason:
                        continue
                    if lang_filter and file_entry.language != lang_filter.lower():
                        continue

                    abs_path = self._resolve_safe_path(file_entry.path)
                    if not os.path.exists(abs_path):
                        continue

                    try:
                        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                            for idx, line in enumerate(f, start=1):
                                if query.lower() in line.lower():
                                    matches.append({
                                        "file_path": file_entry.path,
                                        "line_number": idx,
                                        "line_content": line.rstrip("\r\n"),
                                    })
                                    if len(matches) >= max_results:
                                        break
                    except Exception:
                        continue
                    if len(matches) >= max_results:
                        break

                return MCPToolCallResponse(tool_name=tool_name, content={"matches": matches, "count": len(matches)})

            elif tool_name == "repo_read_file":
                file_path = arguments.get("file_path", "")
                abs_path = self._resolve_safe_path(file_path)

                if not os.path.exists(abs_path) or os.path.isdir(abs_path):
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message=f"File not found: '{file_path}'")

                try:
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception as exc:
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message=f"Could not read file: {str(exc)}")

                total_lines = len(lines)
                start_line = max(int(arguments.get("start_line", 1)), 1) if arguments.get("start_line") else 1
                end_line = min(int(arguments.get("end_line", total_lines)), total_lines) if arguments.get("end_line") else total_lines

                if start_line > total_lines:
                    slice_content = ""
                else:
                    slice_content = "".join(lines[start_line - 1:end_line])

                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "file_path": file_path,
                        "total_lines": total_lines,
                        "start_line": start_line,
                        "end_line": end_line,
                        "content": slice_content,
                    },
                )

            elif tool_name == "repo_get_symbols":
                file_path = arguments.get("file_path")
                kind_str = arguments.get("kind")
                kind = SymbolKind(kind_str) if kind_str else None

                symbols = self.evidence_store.get_symbols(file_path=file_path, kind=kind)
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={"symbols": [s.model_dump() for s in symbols], "count": len(symbols)},
                )

            elif tool_name == "repo_get_routes":
                routes = self.evidence_store.get_routes()
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={"routes": [r.model_dump() for r in routes], "count": len(routes)},
                )

            elif tool_name == "repo_get_frontend_requests":
                calls = self.evidence_store.get_http_calls()
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={"http_calls": [c.model_dump() for c in calls], "count": len(calls)},
                )

            elif tool_name == "repo_get_static_findings":
                file_path = arguments.get("file_path")
                sev_str = arguments.get("severity")
                severity = Severity(sev_str) if sev_str else None
                category = arguments.get("category")
                tool = arguments.get("tool")

                findings = self.evidence_store.get_findings(
                    file_path=file_path,
                    severity=severity,
                    category=category,
                    tool=tool,
                )
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={"findings": [f.model_dump() for f in findings], "count": len(findings)},
                )

            elif tool_name == "repo_get_related_symbols":
                sym_name = arguments.get("symbol_name", "")
                f_path = arguments.get("file_path")
                if not sym_name:
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Parameter 'symbol_name' is required.")

                related = []
                if self.repository_graph:
                    for node in self.repository_graph.get_nodes_by_kind(NodeKind.SYMBOL):
                        if node.label == sym_name or sym_name in node.label:
                            if not f_path or (node.file_path and f_path in node.file_path):
                                # Gather connected neighbors
                                for edge in self.repository_graph.get_outgoing_edges(node.id):
                                    tgt = self.repository_graph.get_node(edge.target)
                                    if tgt:
                                        related.append({"relationship": edge.kind.value, "target": tgt.model_dump()})
                                for edge in self.repository_graph.get_incoming_edges(node.id):
                                    src = self.repository_graph.get_node(edge.source)
                                    if src:
                                        related.append({"relationship": f"INCOMING_{edge.kind.value}", "source": src.model_dump()})

                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={"symbol_name": sym_name, "related_symbols": related, "count": len(related)},
                )

            elif tool_name == "repo_trace_contract":
                raw_route = arguments.get("route_or_url", "")
                method = arguments.get("http_method", "GET").upper()
                if not raw_route:
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Parameter 'route_or_url' is required.")

                norm_path = normalize_route_path(raw_route)
                routes = self.evidence_store.get_routes()
                calls = self.evidence_store.get_http_calls()

                # Filter matching routes and calls
                matched_routes = [
                    r.model_dump() for r in routes
                    if normalize_route_path(r.details.get("path", "")) == norm_path
                ]
                matched_calls = [
                    c.model_dump() for c in calls
                    if normalize_route_path(c.details.get("url", "")) == norm_path
                ]

                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "input_pattern": raw_route,
                        "normalized_path": norm_path,
                        "http_method": method,
                        "backend_routes": matched_routes,
                        "frontend_calls": matched_calls,
                        "is_matched": len(matched_routes) > 0 and len(matched_calls) > 0,
                    },
                )

            elif tool_name == "repo_retrieve_context":
                query = arguments.get("query", "")
                intent = arguments.get("analysis_intent", "general")
                max_chunks = min(int(arguments.get("max_chunks", 5)), 20)

                if not query:
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Parameter 'query' is required.")

                if self.context_engine:
                    bundle = await self.context_engine.build_context_bundle(
                        scan_id=str(self.evidence_store.manifest.commit_hash[:12]),
                        query=query,
                        analysis_intent=intent,
                        max_chunks=max_chunks,
                    )
                    return MCPToolCallResponse(tool_name=tool_name, content=bundle.model_dump())
                else:
                    # Fallback summary
                    return MCPToolCallResponse(
                        tool_name=tool_name,
                        content={"query": query, "message": "Context engine not initialized for this session."},
                    )

            else:
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    is_error=True,
                    error_message=f"Unknown MCP tool: '{tool_name}'",
                )

        except PermissionError as exc:
            return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message=str(exc))
        except ValueError as exc:
            return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message=str(exc))
        except Exception as exc:
            return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message=f"Execution error: {str(exc)}")
