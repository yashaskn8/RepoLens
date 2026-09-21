"""Evaluation-only scripted model and bounded tool invocation recording."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import time
from typing import Any

from app.agent_tools.registry import AgentToolRegistry
from app.agent_tools.schemas import ToolError, ToolInvocationResult, ToolMetadata
from app.evaluation.agent.schemas import ScriptedDecision
from app.llm.types import LLMProvider, LLMRequest, LLMResponse
from app.schemas.metadata import ModelExecutionMetadata
from app.security.redaction import redact_secrets, sanitize_metadata


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class ScriptedRouterExhaustedError(RuntimeError):
    """Raised when a trial requests more model decisions than its script owns."""


@dataclass(frozen=True, slots=True)
class ScriptedRequestRecord:
    """Content-free request metadata retained for evaluator diagnostics."""

    sequence: int
    message_count: int
    request_digest: str
    output_schema_digest: str | None
    context_bytes: int
    requested_action: str
    requested_tool_name: str | None


class ScriptedEvaluationRouter:
    """Async router substitute used only by deterministic evaluator trials.

    It emits the exact production ``InvestigatorDecision`` JSON contract.  It
    deliberately uses an existing provider enum while marking every response
    as synthetic in metadata; evaluator reporting must never treat it as live
    provider capability evidence.
    """

    def __init__(self, decisions: list[ScriptedDecision]) -> None:
        self._decisions = tuple(decisions)
        self._index = 0
        self.requests: list[ScriptedRequestRecord] = []

    @property
    def consumed(self) -> int:
        return self._index

    @property
    def remaining(self) -> int:
        return max(0, len(self._decisions) - self._index)

    async def generate(self, request: LLMRequest) -> LLMResponse:
        if self._index >= len(self._decisions):
            raise ScriptedRouterExhaustedError(
                "Scripted evaluator decisions exhausted; refusing to reuse or invent a decision."
            )

        payload = request.model_dump(mode="json")
        messages = payload.get("messages") or []
        decision = self._decisions[self._index]
        self.requests.append(ScriptedRequestRecord(
            sequence=self._index + 1,
            message_count=len(messages),
            request_digest=_digest(payload),
            output_schema_digest=_digest(request.output_schema) if request.output_schema else None,
            context_bytes=sum(len(str(item.get("content", "")).encode("utf-8")) for item in messages),
            requested_action=decision.action.value,
            requested_tool_name=decision.tool_name,
        ))
        self._index += 1
        metadata = ModelExecutionMetadata(
            model_name="scripted-agent-eval",
            provider=LLMProvider.GEMINI.value,
            prompt_tokens=None,
            completion_tokens=None,
            total_tokens=None,
            execution_time_ms=0.0,
            temperature=0.0,
            extra_metadata={
                "scripted": True,
                "synthetic_execution": True,
                "evaluation_only": True,
                "SCRIPTED_NOT_A_REAL_PROVIDER": True,
            },
        )
        return LLMResponse(
            content=decision.model_dump_json(),
            model="scripted-agent-eval",
            provider=LLMProvider.GEMINI,
            metadata=metadata,
            finish_reason="stop",
        )


@dataclass(frozen=True, slots=True)
class RecordedToolEvent:
    """Bounded, content-free record of one registry interaction."""

    sequence: int
    tool_name: str
    argument_digest: str
    validation_code: str | None
    status: str
    result_digest: str
    evidence_refs: tuple[str, ...]
    tool_contract_version: str
    duration_ms: float


class RecordingAgentToolRegistry:
    """Thin evaluation decorator over the canonical AgentToolRegistry."""

    def __init__(self, registry: AgentToolRegistry, *, max_events: int = 64) -> None:
        self._registry = registry
        self._max_events = max(1, min(max_events, 256))
        self._events: list[RecordedToolEvent] = []

    @property
    def events(self) -> tuple[RecordedToolEvent, ...]:
        return tuple(self._events)

    def list_tools(self) -> list[ToolMetadata]:
        return self._registry.list_tools()

    def get_tool(self, name: str) -> ToolMetadata | None:
        return self._registry.get_tool(name)

    def validate_arguments(
        self,
        name: str,
        arguments: Mapping[str, object] | None,
    ) -> ToolError | None:
        return self._registry.validate_arguments(name, arguments)

    def invoke(self, name: str, arguments: Mapping[str, object] | None) -> ToolInvocationResult:
        started = time.perf_counter()
        validation = self._registry.validate_arguments(name, arguments)
        if validation is not None:
            result = ToolInvocationResult(
                tool=str(name)[:128] or "unknown",
                tool_version=(self._registry.get_tool(name).tool_version if self._registry.get_tool(name) else "unknown"),
                status="INVALID_INPUT",
                errors=[validation],
            )
        else:
            result = self._registry.invoke(name, arguments)
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        safe_args = sanitize_metadata(dict(arguments or {}))
        event = RecordedToolEvent(
            sequence=len(self._events) + 1,
            tool_name=str(name)[:128],
            argument_digest=_digest(safe_args),
            validation_code=validation.code if validation else None,
            status=result.status.value,
            result_digest=_digest({
                "tool": result.tool,
                "status": result.status.value,
                "result": sanitize_metadata(result.result or {}),
                "evidence": [item.model_dump(mode="json") for item in result.evidence[:32]],
                "errors": [item.code for item in result.errors[:8]],
            }),
            evidence_refs=tuple(item.evidence_id for item in result.evidence[:32]),
            tool_contract_version=result.contract_version,
            duration_ms=elapsed_ms,
        )
        if len(self._events) < self._max_events:
            self._events.append(event)
        return result


__all__ = [
    "RecordedToolEvent",
    "RecordingAgentToolRegistry",
    "ScriptedEvaluationRouter",
    "ScriptedRequestRecord",
    "ScriptedRouterExhaustedError",
]
