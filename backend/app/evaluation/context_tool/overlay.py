"""Async-local experiment presentation overlay and actual-request recorder."""

from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Callable, Iterator

from app.agent_runtime.prompt_overlay import active_prompt_overlay
from app.evaluation.context_tool.contracts import (
    ContextPresentationManifest,
    ContextToolOverlay,
    build_manifest,
    canonical_digest,
)
from app.llm.context import ContextEstimator
from app.llm.types import LLMRequest


_ACTIVE_OVERLAY: ContextVar[ContextToolOverlay | None] = ContextVar(
    "repolens_context_tool_experiment_overlay", default=None,
)
_ACTIVE_SINK: ContextVar[Callable[[ContextPresentationManifest], None] | None] = ContextVar(
    "repolens_context_tool_manifest_sink", default=None,
)
_TRIAL_IDENTITY: ContextVar[tuple[str, int, str] | None] = ContextVar(
    "repolens_context_tool_trial_identity", default=None,
)


def active_context_tool_overlay() -> ContextToolOverlay | None:
    return _ACTIVE_OVERLAY.get()


@contextmanager
def evaluation_context_tool_overlay(
    overlay: ContextToolOverlay | None,
    *,
    case_id: str = "evaluation",
    trial_number: int = 1,
    evaluation_stage: str = "FULL_DEV",
    manifest_sink: Callable[[ContextPresentationManifest], None] | None = None,
) -> Iterator[None]:
    """Install one evaluation-only overlay and recorder for this async trial."""
    if overlay is not None and active_prompt_overlay() is not None:
        raise ValueError("prompt and context/tool overlays cannot be combined in one experiment")
    if evaluation_stage not in {
        "BASELINE",
        "SCREEN",
        "FULL_DEV",
        "MICRO_EVAL",
        "LIVE_EXECUTION_PROOF_ONLY",
    }:
        raise ValueError("unknown context experiment evaluation stage")
    overlay_token = _ACTIVE_OVERLAY.set(overlay)
    sink_token = _ACTIVE_SINK.set(manifest_sink)
    trial_token = _TRIAL_IDENTITY.set((case_id[:128], trial_number, evaluation_stage))
    try:
        yield
    finally:
        _TRIAL_IDENTITY.reset(trial_token)
        _ACTIVE_SINK.reset(sink_token)
        _ACTIVE_OVERLAY.reset(overlay_token)


def effective_context_budget(component: str, baseline: int) -> int:
    overlay = active_context_tool_overlay()
    if overlay is None or overlay.target_component != component:
        return baseline
    if overlay.context_budget_fraction is not None:
        return max(1, int(baseline * overlay.context_budget_fraction))
    return baseline


def effective_max_chunks(component: str, baseline: int, *, protected_chunk_count: int) -> int:
    overlay = active_context_tool_overlay()
    if (
        overlay is None
        or overlay.target_component != component
        or overlay.max_chunks_reduction is None
    ):
        return baseline
    adjusted = baseline - overlay.max_chunks_reduction
    if adjusted < protected_chunk_count:
        raise ValueError("context ablation would remove deterministic candidate-anchor capacity")
    return adjusted


def record_model_presentation(
    request: LLMRequest,
    *,
    component: str,
    node: str,
    repository_snapshot: str | None = None,
    evidence_ids: list[str] | tuple[str, ...] = (),
    available_fact_count: int | None = None,
    included_fact_count: int | None = None,
    required_fact_count: int | None = None,
    optional_fact_count: int | None = None,
    token_budget: int | None = None,
    deduplicated_fact_count: int | None = None,
    deduplicated_bytes: int | None = None,
    compacted_observation_count: int | None = None,
    truncated: bool | None = None,
    truncated_candidate_ids: list[str] | tuple[str, ...] = (),
    tools: list[object] | tuple[object, ...] = (),
) -> ContextPresentationManifest | None:
    """Record hashes and counts from the actual canonical LLMRequest, never content."""
    sink = _ACTIVE_SINK.get()
    trial = _TRIAL_IDENTITY.get()
    if sink is None or trial is None:
        return None
    request_payload = {
        "messages": [
            {"role": item.role, "content": item.content}
            for item in request.messages
        ],
        "output_schema": request.output_schema,
    }
    context_digest = canonical_digest(request_payload)
    estimate = ContextEstimator().estimate(request)
    serialized_bytes = sum(len(item.content.encode("utf-8")) for item in request.messages)
    if request.output_schema is not None:
        serialized_bytes += len(json.dumps(
            request.output_schema,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8"))
    tool_names: list[str] = []
    tool_definition_digests: dict[str, str] = {}
    tool_schema_digests: dict[str, str] = {}
    for tool in tools:
        name = str(getattr(tool, "name", ""))
        if not name:
            continue
        tool_names.append(name)
        purpose = str(getattr(tool, "purpose", ""))
        schema = getattr(tool, "input_schema", {})
        tool_definition_digests[name] = canonical_digest({"name": name, "purpose": purpose})
        tool_schema_digests[name] = canonical_digest(schema)
    tool_names = sorted(set(tool_names))
    tool_definition_digests = {name: tool_definition_digests[name] for name in tool_names}
    tool_schema_digests = {name: tool_schema_digests[name] for name in tool_names}
    overlay = _ACTIVE_OVERLAY.get()
    kind_counts: dict[str, int] = {}
    for evidence_id in evidence_ids:
        prefix = str(evidence_id).split(":", 1)[0][:32]
        kind_counts[prefix] = kind_counts.get(prefix, 0) + 1
    normalized_truncated_ids = sorted({str(item)[:128] for item in truncated_candidate_ids if item})[:64]
    manifest = build_manifest(
        case_id=trial[0],
        trial_number=trial[1],
        evaluation_stage=trial[2],
        component=component,
        node=node,
        repository_snapshot=repository_snapshot,
        context_policy_digest=overlay.baseline_context_policy_digest if overlay else _baseline_context_policy_digest(),
        overlay_digest=overlay.overlay_digest if overlay else None,
        token_budget=token_budget if token_budget is not None else request.budget.max_input_tokens,
        packed_context_bytes=serialized_bytes,
        estimated_input_tokens=estimate.input_tokens,
        token_estimate_exact=False,
        available_fact_count=available_fact_count,
        included_fact_count=included_fact_count,
        required_fact_count=required_fact_count,
        optional_fact_count=optional_fact_count,
        deduplicated_fact_count=deduplicated_fact_count,
        deduplicated_bytes=deduplicated_bytes,
        compacted_observation_count=compacted_observation_count,
        evidence_ids=sorted(set(evidence_ids))[:256],
        evidence_kind_counts=dict(sorted(kind_counts.items())[:16]),
        truncated=truncated if truncated is not None else bool(normalized_truncated_ids),
        truncated_candidate_ids=normalized_truncated_ids,
        context_digest=context_digest,
        visible_tool_names=tool_names,
        visible_tool_definition_digests=tool_definition_digests,
        visible_tool_schema_digests=tool_schema_digests,
        manifest_digest="0" * 64,
    )
    sink(manifest)
    return manifest


def evidence_ids_from_payload(value: object, *, limit: int = 256) -> list[str]:
    """Extract explicitly named evidence identifiers from bounded structured data."""
    found: set[str] = set()

    def visit(item: object, depth: int = 0) -> None:
        if depth > 8 or len(found) >= limit:
            return
        if isinstance(item, dict):
            for key, child in list(item.items())[:128]:
                if key in {"evidence_id", "evidence_refs", "primary_evidence_refs"}:
                    if isinstance(child, str) and child:
                        found.add(child[:256])
                    elif isinstance(child, (list, tuple)):
                        found.update(str(entry)[:256] for entry in child[:limit] if isinstance(entry, str) and entry)
                else:
                    visit(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            for child in item[:128]:
                visit(child, depth + 1)

    visit(value)
    return sorted(found)[:limit]


def _baseline_context_policy_digest() -> str:
    from app.evaluation.context_tool.policy import context_policy_identity

    return context_policy_identity()


__all__ = [
    "active_context_tool_overlay",
    "effective_context_budget",
    "effective_max_chunks",
    "evaluation_context_tool_overlay",
    "evidence_ids_from_payload",
    "record_model_presentation",
]
