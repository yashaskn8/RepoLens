"""Deterministic least-privilege policy for investigator tool exposure."""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.agent_runtime.schemas import CompactToolDefinition, InvestigatorDecision
from app.agent_tools.registry import AgentToolRegistry
from app.llm.types import ModelCapability, TaskPolicy


_COMMON_TOOLS = frozenset({
    "inspect_file",
    "search_symbol",
    "inspect_symbol",
    "find_callers",
    "find_callees",
    "read_source_slice",
})
_CATEGORY_TOOLS = {
    "security": _COMMON_TOOLS | {"trace_dataflow", "scan_security"},
    "architecture": _COMMON_TOOLS,
    "integration": _COMMON_TOOLS,
    "bug": _COMMON_TOOLS,
    "general": _COMMON_TOOLS,
    "quality": _COMMON_TOOLS,
}
_CATEGORY_MODELS = {
    "security": (TaskPolicy.SECURITY_REASONING, ModelCapability.SECURITY_REASONING),
    "architecture": (TaskPolicy.ARCHITECTURE, ModelCapability.REPOSITORY_ANALYSIS),
    "integration": (TaskPolicy.INTEGRATION_CODE, ModelCapability.CODE_REASONING),
    "bug": (TaskPolicy.BUG_REASONING, ModelCapability.CODE_REASONING),
}


@dataclass(frozen=True, slots=True)
class InvestigatorPolicyViolation(Exception):
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


def normalized_category(value: str | None) -> str:
    category = str(value or "bug").strip().lower()
    return category if category in _CATEGORY_TOOLS else "bug"


def permitted_tool_names(category: str | None) -> tuple[str, ...]:
    return tuple(sorted(_CATEGORY_TOOLS[normalized_category(category)]))


def category_model_policy(category: str | None) -> tuple[TaskPolicy, ModelCapability]:
    return _CATEGORY_MODELS.get(
        normalized_category(category),
        (TaskPolicy.BUG_REASONING, ModelCapability.CODE_REASONING),
    )


def compact_tool_definitions(
    registry: AgentToolRegistry,
    category: str | None,
) -> list[CompactToolDefinition]:
    definitions: list[CompactToolDefinition] = []
    for name in permitted_tool_names(category):
        metadata = registry.get_tool(name)
        if metadata is None or not metadata.read_only:
            continue
        definitions.append(CompactToolDefinition(
            name=metadata.tool_name,
            purpose=metadata.description[:600],
            capability=metadata.capability.value,
            input_schema=metadata.input_schema,
        ))
    return definitions


def authorize_decision(
    decision: InvestigatorDecision,
    *,
    category: str | None,
    registry: AgentToolRegistry,
) -> None:
    """Fail closed before registry invocation; registry validation remains mandatory."""

    if decision.tool_name is None:
        return
    permitted = set(permitted_tool_names(category))
    if decision.tool_name not in permitted:
        raise InvestigatorPolicyViolation(
            "TOOL_NOT_PERMITTED",
            "The requested tool is not permitted for this investigation category.",
        )
    metadata = registry.get_tool(decision.tool_name)
    if metadata is None:
        raise InvestigatorPolicyViolation("TOOL_UNKNOWN", "The requested tool is not registered.")
    if not metadata.read_only:
        raise InvestigatorPolicyViolation("TOOL_NOT_READ_ONLY", "Write-capable tools are prohibited.")
    try:
        encoded = json.dumps(
            decision.arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvestigatorPolicyViolation("TOOL_ARGUMENT_INVALID", "Tool arguments must be JSON.") from exc
    if len(encoded) > 16_384:
        raise InvestigatorPolicyViolation("TOOL_ARGUMENT_INVALID", "Tool arguments exceed the policy limit.")


__all__ = [
    "InvestigatorPolicyViolation",
    "authorize_decision",
    "category_model_policy",
    "compact_tool_definitions",
    "normalized_category",
    "permitted_tool_names",
]
