import logging
import hashlib
import hmac
import json
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
from app.mcp.constants import (
    MAX_LINE_SPAN_READ,
    MAX_MCP_SERVER_COLLECTION_ITEMS,
    MAX_MCP_SERVER_SEARCH_BYTES,
    MAX_MCP_SERVER_SOURCE_READ_BYTES,
    MAX_MCP_RESULT_BYTES,
    MAX_MCP_SNIPPET_CHARS,
)
from app.core.config import get_settings
from app.schemas.enums import Severity
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)
_MAX_MCP_ERROR_CHARS = 512


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
        from app.core.path_confinement import PathTraversalError, resolve_safe_path

        try:
            full_path_obj = resolve_safe_path(self.repo_dir, relative_path)
            return str(full_path_obj)
        except (PathTraversalError, ValueError) as err:
            logger.warning("Access denied in path resolution: %s", redact_secrets(str(err))[:256])
            raise PermissionError("Access denied: repository path is not permitted.")

    def _read_manifest_source(self, file_entry) -> tuple[bytes | None, str | None]:
        """Read bounded source only when bytes still match the immutable manifest."""
        if file_entry.is_binary or file_entry.skipped_reason:
            return None, "MCP_FILE_UNSUPPORTED: File is binary or was skipped during repository ingestion."
        if not file_entry.content_sha256:
            return None, "MCP_SOURCE_DIGEST_UNAVAILABLE: The authorized snapshot has no immutable source digest."

        max_file_bytes = int(get_settings().MAX_FILE_SIZE_BYTES)
        try:
            abs_path = self._resolve_safe_path(file_entry.path)
            if (
                not os.path.isfile(abs_path)
                or file_entry.size_bytes > max_file_bytes
                or os.path.getsize(abs_path) != file_entry.size_bytes
                or os.path.getsize(abs_path) > max_file_bytes
            ):
                return None, "MCP_SOURCE_RESOURCE_LIMIT: File is unavailable, changed, or exceeds the manifest byte limit."
            with open(abs_path, "rb") as source_file:
                source_bytes = source_file.read(max_file_bytes + 1)
        except Exception:
            # Repository-controlled paths and filesystem failures are both
            # reported as a bounded read error. Do not expose OS-specific
            # details, host paths, or token-like text from exception messages.
            return None, "MCP_FILE_READ_FAILED: Could not read repository file."

        if len(source_bytes) > max_file_bytes or len(source_bytes) != file_entry.size_bytes:
            return None, "MCP_SOURCE_RESOURCE_LIMIT: File is unavailable, changed, or exceeds the manifest byte limit."
        if not hmac.compare_digest(hashlib.sha256(source_bytes).hexdigest(), file_entry.content_sha256):
            return None, "MCP_SOURCE_SNAPSHOT_DRIFT: Source no longer matches the authorized repository snapshot."
        return source_bytes, None

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
        """Dispatch one tool and enforce a final serialized response bound."""
        response = await self._call_tool_unbounded(tool_name, arguments)
        if response.is_error:
            message = response.error_message or "MCP tool execution failed."
            if len(message) > _MAX_MCP_ERROR_CHARS:
                message = message[:_MAX_MCP_ERROR_CHARS] + "... [truncated]"
            return MCPToolCallResponse(
                tool_name=tool_name,
                is_error=True,
                error_message=message,
            )
        try:
            content = response.content
            if hasattr(content, "model_dump"):
                content = content.model_dump(mode="json")
            def encode_content(value: object) -> bytes:
                return json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")

            encoded = encode_content(content)
        except (TypeError, ValueError, OverflowError):
            return MCPToolCallResponse(
                tool_name=tool_name,
                is_error=True,
                error_message="MCP_RESULT_INVALID: Tool result could not be safely serialized.",
            )
        if len(encoded) > MAX_MCP_RESULT_BYTES:
            if isinstance(content, dict) and isinstance(content.get("content"), str):
                source_text = content["content"]
                low, high = 0, len(source_text)
                best: dict[str, Any] | None = None
                while low <= high:
                    middle = (low + high) // 2
                    candidate = {**content, "content": source_text[:middle], "truncated": True}
                    try:
                        candidate_size = len(encode_content(candidate))
                    except (TypeError, ValueError, OverflowError):
                        candidate_size = MAX_MCP_RESULT_BYTES + 1
                    if candidate_size <= MAX_MCP_RESULT_BYTES:
                        best = candidate
                        low = middle + 1
                    else:
                        high = middle - 1
                if best is not None:
                    return response.model_copy(update={"content": best})
            return MCPToolCallResponse(
                tool_name=tool_name,
                is_error=True,
                error_message="MCP_RESULT_RESOURCE_LIMIT: Tool result exceeded the configured response size limit.",
            )
        return response

    async def _call_tool_unbounded(self, tool_name: str, arguments: Dict[str, Any]) -> MCPToolCallResponse:
        """Dispatch tool invocation with error containment; public wrapper bounds output."""
        try:
            if tool_name == "repo_get_manifest":
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content=self.evidence_store.get_summary(),
                )

            elif tool_name == "repo_search_code":
                query = arguments.get("query", "")
                if not query or not isinstance(query, str) or len(query) > 512:
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Parameter 'query' must be a non-empty string.")

                requested_max_results = arguments.get("max_results", 20)
                if isinstance(requested_max_results, bool) or not isinstance(requested_max_results, int):
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Parameter 'max_results' must be an integer.")
                max_results = min(max(requested_max_results, 1), MAX_MCP_SERVER_COLLECTION_ITEMS)
                lang_filter = arguments.get("language")
                matches = []
                scanned_bytes = 0
                truncated = False

                for file_entry in self.evidence_store.manifest.files:
                    if file_entry.is_binary or file_entry.skipped_reason:
                        continue
                    if lang_filter and file_entry.language != lang_filter.lower():
                        continue

                    source_bytes, source_error = self._read_manifest_source(file_entry)
                    if source_error is not None:
                        return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message=source_error)
                    assert source_bytes is not None
                    if scanned_bytes + len(source_bytes) > MAX_MCP_SERVER_SEARCH_BYTES:
                        truncated = True
                        break
                    scanned_bytes += len(source_bytes)
                    for idx, line_bytes in enumerate(source_bytes.splitlines(), start=1):
                        line = line_bytes.decode("utf-8", errors="replace")
                        if query.casefold() not in line.casefold():
                            continue
                        redacted_line = redact_secrets(line)
                        line_content = redacted_line[:MAX_MCP_SNIPPET_CHARS]
                        if len(redacted_line) > MAX_MCP_SNIPPET_CHARS:
                            truncated = True
                        candidate = {
                            "file_path": file_entry.path,
                            "line_number": idx,
                            "line_content": line_content,
                        }
                        proposed = matches + [candidate]
                        proposed_content = {
                            "matches": proposed,
                            "count": len(proposed),
                            "truncated": False,
                        }
                        if len(json.dumps(proposed_content, ensure_ascii=False).encode("utf-8")) > MAX_MCP_RESULT_BYTES:
                            truncated = True
                            break
                        matches.append(candidate)
                        if len(matches) >= max_results:
                            truncated = True
                            break
                    if truncated or len(matches) >= max_results:
                        break

                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={"matches": matches, "count": len(matches), "truncated": truncated},
                )

            elif tool_name == "repo_read_file":
                file_path = str(arguments.get("file_path", "")).strip()
                if not file_path:
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Parameter 'file_path' must be a non-empty string.")

                normalized_path = file_path.replace("\\", "/")
                # Preserve the established path-confinement error for traversal
                # attempts before checking whether a path is manifest-authorized.
                abs_path = self._resolve_safe_path(normalized_path)
                file_entry = self.evidence_store.get_file_entry(normalized_path)
                if file_entry is None:
                    return MCPToolCallResponse(
                        tool_name=tool_name,
                        is_error=True,
                        error_message="MCP_FILE_NOT_AUTHORIZED: File is not present in the repository manifest.",
                    )
                if file_entry.is_binary or file_entry.skipped_reason:
                    return MCPToolCallResponse(
                        tool_name=tool_name,
                        is_error=True,
                        error_message="MCP_FILE_UNSUPPORTED: File is binary or was skipped during repository ingestion.",
                    )
                try:
                    start_raw = arguments.get("start_line", 1)
                    end_raw = arguments.get("end_line")
                    if isinstance(start_raw, bool) or not isinstance(start_raw, int):
                        raise ValueError("start_line must be an integer")
                    if end_raw is not None and (isinstance(end_raw, bool) or not isinstance(end_raw, int)):
                        raise ValueError("end_line must be an integer")
                    start_line = max(start_raw, 1)
                    requested_end = end_raw if end_raw is not None else start_line + MAX_LINE_SPAN_READ - 1
                    if requested_end < start_line:
                        requested_end = start_line
                except (TypeError, ValueError):
                    return MCPToolCallResponse(
                        tool_name=tool_name,
                        is_error=True,
                        error_message="MCP_ARGUMENT_INVALID: Line bounds must be integers.",
                    )
                total_lines = int(file_entry.lines_count)
                if start_line > total_lines:
                    return MCPToolCallResponse(
                        tool_name=tool_name,
                        is_error=True,
                        error_message="MCP_LINE_NOT_FOUND: The requested start line is outside the manifest-authorized file.",
                    )

                try:
                    source_bytes, source_error = self._read_manifest_source(file_entry)
                except PermissionError:
                    return MCPToolCallResponse(
                        tool_name=tool_name,
                        is_error=True,
                        error_message="Access denied: repository path is not permitted.",
                    )
                if source_error is not None:
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message=source_error)
                assert source_bytes is not None
                line_limit_end = start_line + MAX_LINE_SPAN_READ - 1
                selected_end = min(requested_end, line_limit_end, total_lines)
                collected = bytearray()
                truncated = total_lines > line_limit_end and (
                    end_raw is None or requested_end >= line_limit_end
                )
                actual_end_line = start_line - 1
                source_lines = source_bytes.splitlines(keepends=True)
                for line_number in range(start_line, selected_end + 1):
                    line = source_lines[line_number - 1]
                    remaining_output = MAX_MCP_SERVER_SOURCE_READ_BYTES - len(collected)
                    if len(line) > remaining_output:
                        collected.extend(line[:remaining_output])
                        actual_end_line = line_number
                        truncated = True
                        break
                    collected.extend(line)
                    actual_end_line = line_number
                slice_content = bytes(collected).decode("utf-8", errors="replace")

                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "file_path": normalized_path,
                        "total_lines": total_lines,
                        "start_line": start_line,
                        "end_line": actual_end_line,
                        "content": slice_content,
                        "truncated": truncated,
                    },
                )

            elif tool_name == "repo_get_symbols":
                file_path = arguments.get("file_path")
                kind_str = arguments.get("kind")
                kind = SymbolKind(kind_str) if kind_str else None

                symbols = self.evidence_store.get_symbols(file_path=file_path, kind=kind)
                bounded_symbols = symbols[:MAX_MCP_SERVER_COLLECTION_ITEMS]
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "symbols": [s.model_dump() for s in bounded_symbols],
                        "count": len(symbols),
                        "returned_count": len(bounded_symbols),
                        "truncated": len(symbols) > len(bounded_symbols),
                    },
                )

            elif tool_name == "repo_get_routes":
                routes = self.evidence_store.get_routes()
                bounded_routes = routes[:MAX_MCP_SERVER_COLLECTION_ITEMS]
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "routes": [r.model_dump() for r in bounded_routes],
                        "count": len(routes),
                        "returned_count": len(bounded_routes),
                        "truncated": len(routes) > len(bounded_routes),
                    },
                )

            elif tool_name == "repo_get_frontend_requests":
                calls = self.evidence_store.get_http_calls()
                bounded_calls = calls[:MAX_MCP_SERVER_COLLECTION_ITEMS]
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "http_calls": [c.model_dump() for c in bounded_calls],
                        "count": len(calls),
                        "returned_count": len(bounded_calls),
                        "truncated": len(calls) > len(bounded_calls),
                    },
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
                total_count = len(findings)
                bounded_findings = findings[:MAX_MCP_SERVER_COLLECTION_ITEMS]
                is_truncated = total_count > MAX_MCP_SERVER_COLLECTION_ITEMS
                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "findings": [f.model_dump() for f in bounded_findings],
                        "total_count": total_count,
                        "returned_count": len(bounded_findings),
                        "count": len(bounded_findings),
                        "truncated": is_truncated,
                    },
                )

            elif tool_name == "repo_get_related_symbols":
                sym_name = arguments.get("symbol_name", "")
                f_path = arguments.get("file_path")
                if not sym_name:
                    return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Parameter 'symbol_name' is required.")

                related = []
                is_truncated = False
                if self.repository_graph:
                    for node in self.repository_graph.get_nodes_by_kind(NodeKind.SYMBOL):
                        if node.label == sym_name or sym_name in node.label:
                            if not f_path or (node.file_path and f_path in node.file_path):
                                # Gather connected neighbors
                                for edge in self.repository_graph.get_outgoing_edges(node.id):
                                    tgt = self.repository_graph.get_node(edge.target)
                                    if tgt:
                                        related.append({"relationship": edge.kind.value, "target": tgt.model_dump()})
                                        if len(related) > MAX_MCP_SERVER_COLLECTION_ITEMS:
                                            is_truncated = True
                                            related = related[:MAX_MCP_SERVER_COLLECTION_ITEMS]
                                            break
                                if is_truncated:
                                    break
                                for edge in self.repository_graph.get_incoming_edges(node.id):
                                    src = self.repository_graph.get_node(edge.source)
                                    if src:
                                        related.append({"relationship": f"INCOMING_{edge.kind.value}", "source": src.model_dump()})
                                        if len(related) > MAX_MCP_SERVER_COLLECTION_ITEMS:
                                            is_truncated = True
                                            related = related[:MAX_MCP_SERVER_COLLECTION_ITEMS]
                                            break
                                if is_truncated:
                                    break
                        if is_truncated:
                            break

                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "symbol_name": sym_name,
                        "related_symbols": related,
                        "returned_count": len(related),
                        "count": len(related),
                        "truncated": is_truncated,
                    },
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
                    if normalize_route_path(c.details.get("url") or c.details.get("target", "")) == norm_path
                ]

                backend_total = len(matched_routes)
                frontend_total = len(matched_calls)
                bounded_routes = matched_routes[:MAX_MCP_SERVER_COLLECTION_ITEMS]
                bounded_calls = matched_calls[:MAX_MCP_SERVER_COLLECTION_ITEMS]
                is_truncated = backend_total > MAX_MCP_SERVER_COLLECTION_ITEMS or frontend_total > MAX_MCP_SERVER_COLLECTION_ITEMS

                return MCPToolCallResponse(
                    tool_name=tool_name,
                    content={
                        "input_pattern": raw_route,
                        "normalized_path": norm_path,
                        "http_method": method,
                        "backend_routes": bounded_routes,
                        "backend_total_count": backend_total,
                        "backend_returned_count": len(bounded_routes),
                        "frontend_calls": bounded_calls,
                        "frontend_total_count": frontend_total,
                        "frontend_returned_count": len(bounded_calls),
                        "is_matched": len(bounded_routes) > 0 and len(bounded_calls) > 0,
                        "truncated": is_truncated,
                    },
                )

            elif tool_name == "repo_retrieve_context":
                query = arguments.get("query", "")
                intent = arguments.get("analysis_intent", "general")
                max_chunks = min(max(1, int(arguments.get("max_chunks", 5))), 10)

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
            logger.warning("Access denied in MCP tool %s: %s", tool_name, redact_secrets(str(exc))[:2048])
            return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="Access denied: repository path is not permitted.")
        except ValueError as exc:
            safe_msg = redact_secrets(str(exc))[:256]
            return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message=f"Invalid arguments for tool '{tool_name}': {safe_msg}")
        except Exception as exc:
            logger.error("Unexpected MCP execution error in %s: %s", tool_name, redact_secrets(str(exc))[:2048])
            return MCPToolCallResponse(tool_name=tool_name, is_error=True, error_message="MCP tool execution failed.")
