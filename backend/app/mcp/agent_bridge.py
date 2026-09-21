"""MCP v2 bridge over RepoLens' canonical deterministic AgentToolRegistry.

The bridge is intentionally thin: the registry remains the only execution
authority and this module only performs protocol shaping, snapshot binding and
the external least-privilege allowlist.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import mcp.types as mcp_types

from app.agent_tools.registry import AgentToolRegistry
from app.agent_tools.schemas import (
    AGENT_TOOL_VERSION,
    ToolError,
    ToolInvocationResult,
    ToolResultStatus,
)
from app.mcp.constants import MCP_AGENT_TOOL_ALLOWLIST, MAX_MCP_RESULT_BYTES
from app.observability import mcp_server_tool_span_active

_BOUNDARY_KEYS = frozenset({"snapshot_id", "base_snapshot_id", "head_snapshot_id"})


def _error_result(
    tool_name: str,
    status: ToolResultStatus,
    code: str,
    message: str,
) -> ToolInvocationResult:
    return ToolInvocationResult(
        tool=tool_name[:128] or "unknown",
        tool_version=AGENT_TOOL_VERSION,
        status=status,
        errors=[ToolError(code=code, message=message)],
    )


def _json_size(value: object) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8"))


class MCPAgentToolBridge:
    """Expose a scan-bound, read-only subset of ``AgentToolRegistry`` over MCP."""

    def __init__(
        self,
        registry: AgentToolRegistry,
        *,
        snapshot_id: str | None = None,
        allowed_tools: frozenset[str] = MCP_AGENT_TOOL_ALLOWLIST,
    ) -> None:
        self.registry = registry
        self.snapshot_id = snapshot_id or registry.default_snapshot_id
        self.allowed_tools = frozenset(allowed_tools) & MCP_AGENT_TOOL_ALLOWLIST
        if not self.snapshot_id:
            raise ValueError("MCP agent bridge requires a bound repository snapshot")

    def list_tool_definitions(self) -> list[mcp_types.Tool]:
        """Build truthful MCP schemas from registry metadata on every server creation."""
        envelope_schema = ToolInvocationResult.model_json_schema(mode="serialization")
        metadata = {item.tool_name: item for item in self.registry.list_tools()}
        tools: list[mcp_types.Tool] = []
        for name in sorted(self.allowed_tools):
            item = metadata.get(name)
            if item is None or not item.read_only or not item.deterministic:
                continue
            tools.append(
                mcp_types.Tool(
                    name=item.tool_name,
                    description=item.description,
                    inputSchema=item.input_schema,
                    outputSchema=envelope_schema,
                    annotations=mcp_types.ToolAnnotations(
                        readOnlyHint=True,
                        destructiveHint=False,
                        idempotentHint=True,
                        openWorldHint=False,
                    ),
                )
            )
        return tools

    def _validate_snapshot_fields(self, value: object, *, nested: bool = False) -> bool:
        """Reject model-controlled snapshot identity; nested claim IDs must match the binding."""
        if isinstance(value, Mapping):
            for key, item in value.items():
                key_text = str(key)
                if key_text in _BOUNDARY_KEYS:
                    if not nested and key_text == "snapshot_id":
                        return False
                    if item is not None and str(item) != self.snapshot_id:
                        return False
                if not self._validate_snapshot_fields(item, nested=True):
                    return False
        elif isinstance(value, list):
            return all(self._validate_snapshot_fields(item, nested=True) for item in value)
        return True

    def _bound_arguments(self, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any] | None:
        if not self._validate_snapshot_fields(arguments):
            return None
        bound = dict(arguments)
        # SnapshotInput fields are optional and resolve to the registry default;
        # explicitly bind them so provenance cannot drift during a session.
        if tool_name != "verify_finding":
            bound["snapshot_id"] = self.snapshot_id
        else:
            claim = bound.get("claim")
            if isinstance(claim, Mapping) and "snapshot_id" not in claim:
                claim_copy = dict(claim)
                claim_copy["snapshot_id"] = self.snapshot_id
                bound["claim"] = claim_copy
        return bound

    def invoke(self, name: str, arguments: Mapping[str, Any] | None) -> ToolInvocationResult:
        if not isinstance(name, str) or name not in self.allowed_tools:
            return _error_result(
                name if isinstance(name, str) else "unknown",
                ToolResultStatus.UNSUPPORTED,
                "TOOL_NOT_PERMITTED",
                "The requested tool is not permitted by the MCP agent gateway.",
            )
        if not isinstance(arguments, Mapping):
            return _error_result(name, ToolResultStatus.INVALID_INPUT, "ARGUMENTS_NOT_OBJECT", "Tool arguments must be a JSON object.")
        bound = self._bound_arguments(name, arguments)
        if bound is None:
            return _error_result(
                name,
                ToolResultStatus.INVALID_INPUT,
                "SNAPSHOT_BOUNDARY_VIOLATION",
                "Tool arguments cannot select a different repository snapshot.",
            )
        # Registry validation, schema validation, bounds and redaction remain
        # authoritative.  The ContextVar only prevents duplicate OTel spans.
        with mcp_server_tool_span_active():
            result = self.registry.invoke(name, bound)
        return result

    def call_tool_result(self, name: str, arguments: Mapping[str, Any] | None) -> mcp_types.CallToolResult:
        result = self.invoke(name, arguments)
        payload = result.model_dump(mode="json")
        if _json_size(payload) > MAX_MCP_RESULT_BYTES:
            result = _error_result(
                name,
                ToolResultStatus.RESOURCE_LIMIT,
                "MCP_RESULT_TOO_LARGE",
                "The tool result exceeded the maximum allowed MCP result size.",
            )
            payload = result.model_dump(mode="json")
        text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=text)],
            structuredContent=payload,
            isError=result.status in {
                ToolResultStatus.INVALID_INPUT,
                ToolResultStatus.UNSUPPORTED,
                ToolResultStatus.RESOURCE_LIMIT,
                ToolResultStatus.INTERNAL_ERROR,
            },
        )
