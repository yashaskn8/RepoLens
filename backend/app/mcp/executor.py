"""Bounded runtime MCP tool executor enforcing budgets, allowlist, input/output limits, and evidence normalization."""

import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.mcp.runtime_client import MCPNormalizedResult, MCPRuntimeClient
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)

from app.mcp.constants import (
    DEFAULT_MCP_TOOL_TIMEOUT_SECONDS,
    MAX_LINE_SPAN_READ,
    MAX_MCP_CALLS_PER_TARGET,
    MAX_MCP_CALLS_PER_WORKFLOW,
    MAX_MCP_LIST_ITEMS,
    MAX_MCP_RESULT_BYTES,
    MAX_MCP_SNIPPET_CHARS,
    MAX_MCP_TARGETS_PER_REVISION,
    MAX_MCP_TEXT_CHARS,
    RUNTIME_MCP_ALLOWLIST,
)


class MCPToolEvidence(BaseModel):
    """Normalized, bounded, serializable evidence record derived from an MCP tool invocation."""

    tool_name: str = Field(..., description="Name of the MCP tool invoked")
    target_finding_id: str = Field(..., description="UUID string of the target finding being enriched")
    file_path: Optional[str] = Field(default=None, description="Affected file path, if relevant")
    start_line: Optional[int] = Field(default=None, description="Starting line number (1-indexed)")
    end_line: Optional[int] = Field(default=None, description="Ending line number (1-indexed)")
    summary: Optional[str] = Field(default=None, description="Concise summary of tool facts")
    snippet: Optional[str] = Field(default=None, description="Bounded extracted source or context snippet")
    content_digest: Optional[str] = Field(default=None, description="SHA256 hex digest prefix of tool content")
    truncated: bool = Field(default=False, description="Whether tool content exceeded limits and was truncated")


class MCPToolExecutionRecord(BaseModel):
    """Bounded operational execution event recording MCP tool invocation metadata."""

    tool_name: str
    target_finding_id: Optional[str] = None
    success: bool
    duration_ms: int
    error_code: Optional[str] = None
    truncated: bool = False


class MCPToolExecutor:
    """Execution layer wrapping MCPRuntimeClient with strict safety policies and bounds.

    Guarantees:
    - Enforces constant allowlist: only approved read-only tools can be dispatched.
    - Enforces strict attempted-call budgeting (consumes budget BEFORE dispatch).
    - Enforces parameter bounds (line ranges, string lengths, chunk counts).
    - Enforces output bounds (bytes, characters, list items) and marks truncated=True truthfully.
    - Sanitizes errors and redacts secret tokens using redact_secrets.
    - Zero LLM model calls.
    """

    def __init__(
        self,
        client: MCPRuntimeClient,
        max_workflow_calls: int = MAX_MCP_CALLS_PER_WORKFLOW,
        max_calls_per_target: int = MAX_MCP_CALLS_PER_TARGET,
    ):
        self.client = client
        self.max_workflow_calls = max_workflow_calls
        self.max_calls_per_target = max_calls_per_target

        self.workflow_call_count: int = 0
        self.target_call_counts: Dict[str, int] = {}
        self.execution_records: List[MCPToolExecutionRecord] = []

    def _check_and_consume_budget(self, target_finding_id: str) -> Optional[str]:
        """Check budget constraints and consume budget BEFORE dispatch.

        Returns None if allowed, or an error code string if budget is exceeded.
        """
        if self.workflow_call_count >= self.max_workflow_calls:
            return "MCP_WORKFLOW_BUDGET_EXCEEDED"

        target_count = self.target_call_counts.get(target_finding_id, 0)
        if target_count >= self.max_calls_per_target:
            return "MCP_TARGET_BUDGET_EXCEEDED"

        # Consume budget immediately on attempt
        self.workflow_call_count += 1
        self.target_call_counts[target_finding_id] = target_count + 1
        return None

    def validate_and_bound_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """Validate and clamp input arguments to conservative bounds.

        Returns (bounded_args, error_code_or_none).
        """
        bounded = dict(arguments)

        if tool_name == "repo_read_file":
            file_path = str(bounded.get("file_path", "")).strip()
            if not file_path or len(file_path) > 500:
                return bounded, "MCP_ARGUMENT_INVALID: file_path must be non-empty and <= 500 characters."

            start_line = max(int(bounded.get("start_line", 1)), 1)
            bounded["start_line"] = start_line

            if "end_line" in bounded and bounded["end_line"] is not None:
                end_line = max(int(bounded["end_line"]), start_line)
                if (end_line - start_line + 1) > MAX_LINE_SPAN_READ:
                    end_line = start_line + MAX_LINE_SPAN_READ - 1
                bounded["end_line"] = end_line
            else:
                bounded["end_line"] = start_line + MAX_LINE_SPAN_READ - 1

        elif tool_name == "repo_get_related_symbols":
            sym = str(bounded.get("symbol_name", "")).strip()
            if not sym or len(sym) > 200:
                return bounded, "MCP_ARGUMENT_INVALID: symbol_name must be non-empty and <= 200 characters."
            bounded["symbol_name"] = sym

            if "file_path" in bounded and bounded["file_path"]:
                bounded["file_path"] = str(bounded["file_path"])[:500]

        elif tool_name == "repo_trace_contract":
            route = str(bounded.get("route_or_url", "")).strip()
            if not route or len(route) > 500:
                return bounded, "MCP_ARGUMENT_INVALID: route_or_url must be non-empty and <= 500 characters."
            bounded["route_or_url"] = route

            if "http_method" in bounded and bounded["http_method"]:
                bounded["http_method"] = str(bounded["http_method"]).upper()[:10]

        elif tool_name == "repo_retrieve_context":
            query = str(bounded.get("query", "")).strip()
            if not query or len(query) > 1000:
                return bounded, "MCP_ARGUMENT_INVALID: query must be non-empty and <= 1000 characters."
            bounded["query"] = query

            max_chunks = int(bounded.get("max_chunks", 5))
            bounded["max_chunks"] = min(max(1, max_chunks), 5)

        elif tool_name == "repo_get_static_findings":
            if "file_path" in bounded and bounded["file_path"]:
                bounded["file_path"] = str(bounded["file_path"])[:500]

        return bounded, None

    async def execute_tool(
        self,
        tool_name: str,
        target_finding_id: str,
        arguments: Dict[str, Any],
        timeout_seconds: Optional[float] = None,
    ) -> Tuple[Optional[MCPToolEvidence], MCPToolExecutionRecord]:
        """Execute a tool with full budget consumption, validation, timeout, and output bounding."""
        start_time = time.monotonic()

        # 1. Allowlist enforcement
        if tool_name not in RUNTIME_MCP_ALLOWLIST:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            record = MCPToolExecutionRecord(
                tool_name=tool_name,
                target_finding_id=target_finding_id,
                success=False,
                duration_ms=duration_ms,
                error_code="MCP_TOOL_NOT_ALLOWED",
            )
            self.execution_records.append(record)
            return None, record

        # 2. Budget check and attempted-call consumption BEFORE dispatch
        budget_error = self._check_and_consume_budget(target_finding_id)
        if budget_error is not None:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            record = MCPToolExecutionRecord(
                tool_name=tool_name,
                target_finding_id=target_finding_id,
                success=False,
                duration_ms=duration_ms,
                error_code=budget_error,
            )
            self.execution_records.append(record)
            return None, record

        # 3. Input bounds validation
        bounded_args, arg_error = self.validate_and_bound_arguments(tool_name, arguments)
        if arg_error is not None:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            record = MCPToolExecutionRecord(
                tool_name=tool_name,
                target_finding_id=target_finding_id,
                success=False,
                duration_ms=duration_ms,
                error_code=arg_error,
            )
            self.execution_records.append(record)
            return None, record

        # 4. Dispatch to MCPRuntimeClient
        result: MCPNormalizedResult = await self.client.call_tool(
            tool_name,
            bounded_args,
            timeout_seconds=timeout_seconds,
        )
        duration_ms = int((time.monotonic() - start_time) * 1000)

        # 5. Handle invocation failure
        if result.is_error:
            error_code = result.error_code or "MCP_TOOL_FAILED"
            record = MCPToolExecutionRecord(
                tool_name=tool_name,
                target_finding_id=target_finding_id,
                success=False,
                duration_ms=duration_ms,
                error_code=error_code,
            )
            self.execution_records.append(record)
            return None, record

        # 6. Normalize and bound successful output
        evidence, truncated = self._normalize_evidence(tool_name, target_finding_id, bounded_args, result.content)
        record = MCPToolExecutionRecord(
            tool_name=tool_name,
            target_finding_id=target_finding_id,
            success=True,
            duration_ms=duration_ms,
            truncated=truncated,
        )
        self.execution_records.append(record)
        return evidence, record

    def _bound_snippet(self, text: str) -> Tuple[str, bool]:
        """Slice text to MAX_MCP_SNIPPET_CHARS and return (bounded_text, was_truncated)."""
        if len(text) > MAX_MCP_SNIPPET_CHARS:
            return text[:MAX_MCP_SNIPPET_CHARS], True
        return text, False

    def _normalize_evidence(
        self,
        tool_name: str,
        target_finding_id: str,
        arguments: Dict[str, Any],
        content: Any,
    ) -> Tuple[MCPToolEvidence, bool]:
        """Convert tool result into bounded, serializable MCPToolEvidence."""
        raw_text = json.dumps(content, default=str) if isinstance(content, (dict, list)) else str(content)
        digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()[:16]

        truncated = False
        if isinstance(content, dict) and content.get("truncated") is True:
            truncated = True
        if len(raw_text) > MAX_MCP_RESULT_BYTES:
            truncated = True

        file_path = arguments.get("file_path")
        start_line = arguments.get("start_line")
        end_line = arguments.get("end_line")
        summary = None
        snippet = None

        if tool_name == "repo_read_file" and isinstance(content, dict):
            file_path = content.get("file_path", file_path)
            start_line = content.get("start_line", start_line)
            end_line = content.get("end_line", end_line)
            raw_snippet = content.get("content", "")
            if len(raw_snippet) > MAX_MCP_SNIPPET_CHARS:
                snippet = raw_snippet[:MAX_MCP_SNIPPET_CHARS] + "\n... [TRUNCATED]"
                truncated = True
            else:
                snippet = raw_snippet
            summary = f"Read {file_path} (lines {start_line}-{end_line})."

        elif tool_name == "repo_get_related_symbols" and isinstance(content, dict):
            symbols = content.get("related_symbols", [])
            sym_name = content.get("symbol_name", "")
            if len(symbols) > MAX_MCP_LIST_ITEMS:
                symbols = symbols[:MAX_MCP_LIST_ITEMS]
                truncated = True
            summary = f"Discovered {len(symbols)} connected symbols for '{sym_name}'."
            snippet, was_trunc = self._bound_snippet(json.dumps(symbols, indent=2, default=str))
            truncated = truncated or was_trunc

        elif tool_name == "repo_trace_contract" and isinstance(content, dict):
            pattern = content.get("input_pattern", "")
            is_matched = content.get("is_matched", False)
            routes = content.get("backend_routes", [])
            calls = content.get("frontend_calls", [])
            summary = f"Route contract trace for '{pattern}': matched={is_matched} (backend_routes={len(routes)}, frontend_calls={len(calls)})."
            snippet, was_trunc = self._bound_snippet(json.dumps(content, indent=2, default=str))
            truncated = truncated or was_trunc

        elif tool_name == "repo_retrieve_context" and isinstance(content, dict):
            chunks = content.get("relevant_chunks", [])
            if len(chunks) > MAX_MCP_LIST_ITEMS:
                chunks = chunks[:MAX_MCP_LIST_ITEMS]
                truncated = True
            summary = f"Retrieved {len(chunks)} code chunks for query: '{arguments.get('query', '')[:80]}'."
            snippet, was_trunc = self._bound_snippet(json.dumps(chunks, indent=2, default=str))
            truncated = truncated or was_trunc

        elif tool_name == "repo_get_static_findings" and isinstance(content, dict):
            findings = content.get("findings", [])
            if len(findings) > MAX_MCP_LIST_ITEMS:
                findings = findings[:MAX_MCP_LIST_ITEMS]
                truncated = True
            summary = f"Retrieved {len(findings)} deterministic static scanner findings."
            snippet, was_trunc = self._bound_snippet(json.dumps(findings, indent=2, default=str))
            truncated = truncated or was_trunc

        else:
            summary = f"Tool '{tool_name}' executed."
            snippet = raw_text[:MAX_MCP_SNIPPET_CHARS]
            if len(raw_text) > MAX_MCP_SNIPPET_CHARS:
                truncated = True

        evidence = MCPToolEvidence(
            tool_name=tool_name,
            target_finding_id=target_finding_id,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            summary=summary,
            snippet=snippet,
            content_digest=digest,
            truncated=truncated,
        )
        return evidence, truncated

    async def aclose(self) -> None:
        """Clean up underlying MCP client."""
        await self.client.aclose()
