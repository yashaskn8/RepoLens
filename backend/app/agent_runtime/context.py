"""Deterministic selection, normalization, compaction, and packing for investigation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from app.agent_runtime.schemas import (
    CompactToolDefinition,
    EvidenceLedgerEntry,
    InvestigatorBudget,
    InvestigatorContextPack,
    InvestigatorObservation,
    InvestigatorEvidenceArtifact,
    InvestigatorTargetState,
    InvestigatorWorkingMemory,
    MemoryEntry,
    MemoryKind,
)
from app.agent_runtime.prompts import INVESTIGATOR_SYSTEM_PROMPT
from app.agent_tools.schemas import ToolInvocationResult, ToolResultStatus
from app.llm.types import AIContextMetrics, LLMMessage
from app.security.redaction import redact_secrets, sanitize_metadata


@dataclass(frozen=True, slots=True)
class PackedInvestigatorContext:
    messages: tuple[LLMMessage, LLMMessage]
    metrics: AIContextMetrics
    telemetry: dict[str, Any]
    evidence_digest: str


class InvestigatorContextBudgetExceeded(ValueError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _bound_nested(value: Any, *, depth: int = 0, string_bytes: int = 2_000) -> Any:
    if depth >= 4:
        return "[truncated: maximum result depth]"
    if isinstance(value, str):
        return _truncate_utf8(value, string_bytes)
    if isinstance(value, dict):
        return {
            str(key)[:128]: _bound_nested(item, depth=depth + 1, string_bytes=string_bytes)
            for key, item in list(value.items())[:24]
        }
    if isinstance(value, (list, tuple)):
        return [_bound_nested(item, depth=depth + 1, string_bytes=string_bytes) for item in value[:8]]
    return value


def _bounded_result(value: Any, *, max_bytes: int = 16_000) -> dict[str, Any]:
    sanitized = sanitize_metadata(value if isinstance(value, dict) else {"value": value})
    bounded = {
        str(key)[:128]: _bound_nested(
            item,
            string_bytes=10_000 if key == "content" else 2_000,
        )
        for key, item in list(sanitized.items())[:32]
    }
    if len(_canonical(bounded).encode("utf-8")) <= max_bytes:
        return bounded

    priority = (
        "repository_snapshot", "file_path", "start_line", "end_line", "content",
        "content_sha256", "file_sha256", "symbol", "symbols", "matches", "relationships",
        "coverage", "truncated", "query", "match_mode", "total_matches", "returned_matches",
    )
    compact = {key: bounded[key] for key in priority if key in bounded}
    compact["_truncated"] = True
    for key in ("relationships", "matches", "symbols", "coverage", "symbol"):
        if len(_canonical(compact).encode("utf-8")) <= max_bytes:
            break
        compact.pop(key, None)
    if len(_canonical(compact).encode("utf-8")) > max_bytes and isinstance(compact.get("content"), str):
        compact["content"] = _truncate_utf8(compact["content"], 8_000)
    if len(_canonical(compact).encode("utf-8")) > max_bytes:
        compact.pop("content", None)
    return compact


def normalize_tool_result(
    result: ToolInvocationResult,
    *,
    step_number: int,
) -> InvestigatorObservation:
    payload = result.model_dump(mode="json")
    digest = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    useful = _bounded_result(result.result or {})
    warnings = [f"{item.code}: {redact_secrets(item.message)[:400]}" for item in result.warnings[:16]]
    errors = [f"{item.code}: {redact_secrets(item.message)[:400]}" for item in result.errors[:16]]
    evidence_refs = [item.evidence_id for item in result.evidence[:32]]
    repository_snapshot = result.provenance.repository_snapshot if result.provenance else None
    truncated = bool(useful.get("truncated") or useful.get("_truncated"))
    return InvestigatorObservation(
        step_id=f"step-{step_number}",
        tool_name=result.tool,
        status=result.status.value,
        useful_result=useful,
        evidence_refs=evidence_refs,
        warnings=warnings,
        errors=errors,
        result_digest=digest,
        repository_snapshot=repository_snapshot,
        truncated=truncated,
        produced_new_evidence=False,
        ledger_entries=_ledger_entries(result),
    )


def _ledger_entries(result: ToolInvocationResult) -> list[EvidenceLedgerEntry]:
    entries: list[EvidenceLedgerEntry] = []
    snapshot = result.provenance.repository_snapshot if result.provenance else "unknown"
    for evidence in result.evidence[:32]:
        fact = (
            f"{result.tool} returned {evidence.evidence_type.value} evidence"
            f" at {evidence.file_path or 'repository scope'}"
            f"{':' + str(evidence.start_line) if evidence.start_line else ''}."
        )
        if evidence.relationship:
            fact += (
                f" Relationship {evidence.relationship}: "
                f"{str(evidence.source_id or 'unknown')[:300]} -> "
                f"{str(evidence.target_id or 'unknown')[:300]}."
            )
        if result.tool == "read_source_slice" and isinstance(result.result, dict):
            source_excerpt = redact_secrets(str(result.result.get("content") or ""))[:600]
            if source_excerpt:
                fact += f" Redacted source excerpt (untrusted data): {source_excerpt}"
        fact = fact[:1_200]
        entries.append(EvidenceLedgerEntry(
            evidence_id=evidence.evidence_id,
            source=evidence.source_component,
            tool=result.tool,
            status=result.status.value,
            repository_snapshot=snapshot,
            tool_contract_version=result.contract_version,
            file_path=evidence.file_path,
            symbol_id=evidence.symbol if evidence.symbol and evidence.symbol.startswith("symbol:") else None,
            start_line=evidence.start_line,
            end_line=evidence.end_line,
            fact_summary=fact,
            content_digest=(
                evidence.source_id if evidence.source_id and len(evidence.source_id) == 64 else None
            ),
            warnings=[item.code for item in result.warnings[:12]],
        ))
    if not entries and result.status in {
        ToolResultStatus.NOT_FOUND,
        ToolResultStatus.INSUFFICIENT_EVIDENCE,
        ToolResultStatus.RESOURCE_LIMIT,
    }:
        complete = not any(
            marker in item.code
            for item in result.warnings
            for marker in ("COVERAGE", "INCOMPLETE", "LIMIT")
        )
        summary = f"{result.tool} returned {result.status.value}."
        if not complete:
            summary += " Coverage is incomplete; absence is not proven."
        entries.append(EvidenceLedgerEntry(
            source="agent_tool_registry",
            tool=result.tool,
            status=result.status.value,
            repository_snapshot=snapshot,
            tool_contract_version=result.contract_version,
            fact_summary=summary,
            content_digest=hashlib.sha256(_canonical(result.model_dump(mode="json")).encode()).hexdigest(),
            warnings=[item.code for item in [*result.warnings, *result.errors][:12]],
        ))
    return entries


def compact_observation(
    target: InvestigatorTargetState,
    observation: InvestigatorObservation,
    *,
    call_fingerprint: str,
    recent_limit: int = 2,
) -> InvestigatorTargetState:
    """Merge trusted tool facts into bounded durable memory and clear old raw detail."""

    updated = target.model_copy(deep=True)
    existing_keys = {(item.evidence_id, item.content_digest) for item in updated.evidence_ledger}
    existing_by_id = {
        item.evidence_id: item
        for item in updated.evidence_ledger
        if item.evidence_id is not None
    }
    new_entries = [
        item for item in observation.ledger_entries
        if (item.evidence_id, item.content_digest) not in existing_keys
    ]
    new_digest = observation.result_digest not in updated.evidence_digests
    observation = observation.model_copy(update={"produced_new_evidence": bool(new_entries or new_digest)})
    updated.evidence_ledger = [*updated.evidence_ledger, *new_entries][-64:]
    if new_digest:
        updated.evidence_digests = [*updated.evidence_digests, observation.result_digest][-64:]

    memory = updated.working_memory.model_copy(deep=True)
    for entry in new_entries:
        prior = existing_by_id.get(entry.evidence_id) if entry.evidence_id else None
        if (
            prior is not None
            and prior.content_digest is not None
            and entry.content_digest is not None
            and prior.content_digest != entry.content_digest
        ):
            memory.entries.append(MemoryEntry(
                kind=MemoryKind.CONTRADICTION,
                text=f"Trusted tools returned conflicting digests for evidence {entry.evidence_id}.",
                evidence_refs=[entry.evidence_id],
            ))
    for entry in new_entries:
        if entry.file_path and entry.file_path not in memory.important_files:
            memory.important_files.append(entry.file_path)
        if entry.symbol_id and entry.symbol_id not in memory.discovered_symbols:
            memory.discovered_symbols.append(entry.symbol_id)
        kind = MemoryKind.DETERMINISTIC_FACT
        if entry.status == ToolResultStatus.NOT_FOUND.value:
            kind = MemoryKind.NEGATIVE_RESULT
        elif "incomplete" in entry.fact_summary.lower() or entry.status == ToolResultStatus.RESOURCE_LIMIT.value:
            kind = MemoryKind.COVERAGE_LIMITATION
        memory.entries.append(MemoryEntry(
            kind=kind,
            text=entry.fact_summary,
            evidence_refs=[entry.evidence_id] if entry.evidence_id else [],
        ))
    if observation.errors:
        memory.failed_approaches.append(
            f"{observation.tool_name}: {observation.errors[0][:200]}"
        )
    memory.discovered_symbols = list(dict.fromkeys(memory.discovered_symbols))[-32:]
    memory.important_files = list(dict.fromkeys(memory.important_files))[-32:]
    memory.entries = memory.entries[-48:]
    memory.failed_approaches = list(dict.fromkeys(memory.failed_approaches))[-16:]
    updated.working_memory = memory
    updated.recent_observations = [*updated.recent_observations, observation][-recent_limit:]
    summary = (
        new_entries[0].fact_summary
        if new_entries else f"{observation.tool_name} returned {observation.status}."
    )
    artifact = InvestigatorEvidenceArtifact(
        tool_name=observation.tool_name,
        status=observation.status,
        repository_snapshot=observation.repository_snapshot,
        evidence_refs=observation.evidence_refs,
        result_digest=observation.result_digest,
        fact_summary=summary,
        useful_result=observation.useful_result,
    )
    updated.evidence_artifacts = [*updated.evidence_artifacts, artifact][-5:]
    updated.pending_observation = None
    updated.pending_decision = None
    updated.pending_call_fingerprint = None
    updated.call_fingerprints = (
        [call_fingerprint]
        if observation.produced_new_evidence
        else [*updated.call_fingerprints, call_fingerprint][-5:]
    )
    return updated


def _select_memory(memory: InvestigatorWorkingMemory) -> dict[str, Any]:
    priority = {
        MemoryKind.OPEN_QUESTION: 0,
        MemoryKind.CONTRADICTION: 1,
        MemoryKind.DETERMINISTIC_FACT: 2,
        MemoryKind.NEGATIVE_RESULT: 3,
        MemoryKind.COVERAGE_LIMITATION: 4,
        MemoryKind.MODEL_HYPOTHESIS: 5,
    }
    entries = sorted(memory.entries, key=lambda item: priority[item.kind])[:20]
    return {
        "discovered_symbols": memory.discovered_symbols[-20:],
        "important_files": memory.important_files[-20:],
        "entries": [item.model_dump(mode="json") for item in entries],
        "failed_approaches": memory.failed_approaches[-8:],
    }


def _source_bytes(observations: list[dict[str, Any]]) -> int:
    return sum(
        len(str(item.get("useful_result", {}).get("content", "")).encode("utf-8"))
        for item in observations
    )


def pack_decision_context(
    target: InvestigatorTargetState,
    tools: list[CompactToolDefinition],
    *,
    max_context_tokens: int,
) -> PackedInvestigatorContext:
    """Pack prioritized, bounded state; never include the full AnalysisState or transcript."""

    recent = [item.model_dump(mode="json") for item in target.recent_observations[-2:]]
    ledger = [item.model_dump(mode="json") for item in target.evidence_ledger[-20:]]
    payload = {
        "task": {
            "finding": target.finding.model_dump(mode="json"),
            "verifier_gap": target.verifier_gap.model_dump(mode="json"),
        },
        "working_memory": _select_memory(target.working_memory),
        "evidence_ledger": ledger,
        "recent_observations": recent,
        "available_tools": [item.model_dump(mode="json") for item in tools],
        "budget": target.budget.model_dump(mode="json"),
        "output_contract": {
            "action": "TOOL_CALL | FINISH | ABSTAIN",
            "tool_name": "required only for TOOL_CALL",
            "arguments": "one JSON object for one tool",
            "reason": "short operational explanation",
        },
    }
    system = f"<SYSTEM_CONTRACT>\n{INVESTIGATOR_SYSTEM_PROMPT}\n</SYSTEM_CONTRACT>"
    max_bytes = max_context_tokens * 3

    def render() -> str:
        return (
            "<UNTRUSTED_REPOSITORY_DATA>\n"
            + _canonical(payload)
            + "\n</UNTRUSTED_REPOSITORY_DATA>"
        )

    user = render()
    context_truncated = False
    while len(system.encode("utf-8")) + len(user.encode("utf-8")) > max_bytes:
        context_truncated = True
        if len(payload["evidence_ledger"]) > 4:
            payload["evidence_ledger"].pop(0)
        elif len(payload["recent_observations"]) > 1:
            payload["recent_observations"].pop(0)
        elif any("content" in item.get("useful_result", {}) for item in payload["recent_observations"]):
            for item in payload["recent_observations"]:
                item.get("useful_result", {}).pop("content", None)
                item["truncated"] = True
        elif len(payload["working_memory"]["entries"]) > 6:
            payload["working_memory"]["entries"].pop()
        else:
            raise InvestigatorContextBudgetExceeded(
                "Safety policy, active target, permitted tools, and output contract exceed the context budget."
            )
        user = render()

    packed_bytes = len(system.encode("utf-8")) + len(user.encode("utf-8"))
    estimated_tokens = max(1, (packed_bytes + 2) // 3)
    source_bytes = _source_bytes(payload["recent_observations"])
    telemetry = {
        "packed_context_bytes": packed_bytes,
        "estimated_context_tokens": estimated_tokens,
        "token_estimate_exact": False,
        "tool_definition_count": len(tools),
        "permitted_tool_names": [item.name for item in tools],
        "evidence_ledger_count": len(payload["evidence_ledger"]),
        "included_evidence_refs": [
            item["evidence_id"]
            for item in payload["evidence_ledger"]
            if item.get("evidence_id")
        ],
        "recent_observation_count": len(payload["recent_observations"]),
        "compacted_observation_count": max(0, target.budget.tool_calls - len(payload["recent_observations"])),
        "source_context_bytes": source_bytes,
        "step_number": target.budget.step_number,
        "remaining_step_budget": target.budget.max_steps - target.budget.step_number,
        "remaining_tool_budget": target.budget.max_tool_calls - target.budget.tool_calls,
        "context_truncated": context_truncated,
    }
    metrics = AIContextMetrics(
        packed_context_tokens=estimated_tokens,
        packed_context_bytes=packed_bytes,
        deduplicated_items=len(target.evidence_ledger) - len({
            (item.evidence_id, item.content_digest) for item in target.evidence_ledger
        }),
    )
    return PackedInvestigatorContext(
        messages=(LLMMessage(role="system", content=system), LLMMessage(role="user", content=user)),
        metrics=metrics,
        telemetry=telemetry,
        evidence_digest=hashlib.sha256(user.encode("utf-8")).hexdigest(),
    )


__all__ = [
    "INVESTIGATOR_SYSTEM_PROMPT",
    "InvestigatorContextBudgetExceeded",
    "PackedInvestigatorContext",
    "compact_observation",
    "normalize_tool_result",
    "pack_decision_context",
]
