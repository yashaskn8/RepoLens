"""Closed, deterministic policy for evaluation-local context/tool presentation."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from app.agent_runtime.policy import permitted_tool_names
from app.agent_tools.registry import AgentToolRegistry
from app.evaluation.context_tool.contracts import (
    ContextToolDimension,
    ContextToolOverlay,
    MANIFEST_SCHEMA_VERSION,
    canonical_digest,
)
from app.evaluation.ground_truth.public_dev import PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS
from app.security.redaction import redact_secrets


POLICY_VERSION = "context-tool-experiment-policy/1.2"
SCREEN_SELECTION_VERSION = "context-tool-screen-selection/1.1"
MANIFEST_VERSION = MANIFEST_SCHEMA_VERSION
PARETO_POLICY_VERSION = "context-tool-pareto/1.1"
QUALITY_COMPARISON_POLICY_VERSION = "context-tool-quality-comparison/1.1"
MAX_CANDIDATES = 8
MAX_FULL_CANDIDATES = 2
MAX_TRIAL_WORK_UNITS = 768
MAX_CASES = 64
MAX_TRIALS_PER_CASE = 5
MAX_WALL_CLOCK_SECONDS = 3_600
MAX_MODEL_CALLS_PER_WORK_UNIT = 32
_CONTEXT_ORDER = {
    "security": ["static_findings", "chunks", "graph_edges", "contracts"],
    "integration": ["contracts", "chunks", "graph_edges", "static_findings"],
    "architecture": ["graph_edges", "contracts", "chunks", "static_findings"],
    "bug": ["chunks", "static_findings", "graph_edges", "contracts"],
    "verification": ["chunks", "static_findings", "graph_edges", "contracts"],
}
BASELINE_CONTEXT_POLICY_DIGEST = canonical_digest({
    "version": "context-packing/1.0",
    "orders": _CONTEXT_ORDER,
    "bytes_per_token": 3,
})

_COMPONENT_CATEGORY = {
    "security-agent": "security",
    "architecture-agent": "architecture",
    "integration-agent": "integration",
    "bug-agent": "bug",
    "evidence-investigator": "bug",
    "verifier-agent": "verification",
    "revision-agent": "bug",
}
_FORBIDDEN_DESCRIPTION = re.compile(
    r"\b(write|modify|delete|execute|run|publish|commit|push|network|shell|install|deploy|approve)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"(?:https?://|www\.)", re.IGNORECASE)
_BENCHMARK_PATH = re.compile(r"\b(?:evaluation_data|ground_truth|private_holdout|cases)/", re.IGNORECASE)
_MODEL_ROUTING_COPY = re.compile(r"\b(always|never|must|should|choose|select|prefer|call|for all cases)\b", re.IGNORECASE)
_CASE_IDS = tuple(sorted(PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS))


@lru_cache(maxsize=1)
def _public_benchmark_terms() -> tuple[str, ...]:
    """Public fixture paths and concise grader labels used only by the sanitizer."""
    from app.evaluation.ground_truth.public_dev import load_public_dev_repository_cases

    terms: set[str] = set(_CASE_IDS)
    for case in load_public_dev_repository_cases():
        terms.update(path.replace("\\", "/") for path in case.fixture.files)
        for claim in case.annotation.claims:
            for value in (claim.rule_id, *claim.permitted_files, *claim.permitted_symbols):
                text = str(value or "").strip()
                if len(text) >= 12:
                    terms.add(text)
    return tuple(sorted(terms, key=lambda item: (-len(item), item.casefold())))


def context_policy_identity() -> str:
    from app.evaluation.system.identity import context_policy_identity_digest

    return context_policy_identity_digest()


def context_component_for_intent(intent: str) -> str:
    return {
        "security": "security-agent",
        "architecture": "architecture-agent",
        "integration": "integration-agent",
        "bug": "bug-agent",
        "verification": "verifier-agent",
    }.get(intent, "bug-agent")


def validate_overlay_identity(
    overlay: ContextToolOverlay,
    *,
    system_digest: str,
    tool_manifest_digest: str,
    context_policy_digest: str | None = None,
) -> None:
    if overlay.baseline_system_digest != system_digest:
        raise ValueError("context/tool candidate is bound to a different baseline system")
    if overlay.baseline_tool_manifest_digest != tool_manifest_digest:
        raise ValueError("context/tool candidate is bound to a different tool contract manifest")
    expected_context_digest = context_policy_digest
    if expected_context_digest is None:
        from app.evaluation.system.identity import context_policy_identity_digest

        expected_context_digest = context_policy_identity_digest()
    if overlay.baseline_context_policy_digest != expected_context_digest:
        raise ValueError("context/tool candidate is bound to a stale context policy")
    if overlay.target_component not in _COMPONENT_CATEGORY:
        raise ValueError("context/tool candidate targets an unknown production component")
    if overlay.dimension in {
        ContextToolDimension.CONTEXT_TOKEN_BUDGET,
        ContextToolDimension.MAX_RETRIEVED_CHUNKS,
        ContextToolDimension.OPTIONAL_CONTEXT_KIND,
    } and overlay.target_component not in {
        "architecture-agent", "bug-agent", "security-agent", "evidence-investigator",
    }:
        raise ValueError("context ablations require a currently model-driven context component")
    if overlay.dimension in {
        ContextToolDimension.TOOL_VISIBILITY,
        ContextToolDimension.TOOL_DESCRIPTION_PRESENTATION,
    } and overlay.target_component != "evidence-investigator":
        raise ValueError("tool presentation experiments are limited to the Evidence Investigator")


def validate_overlay_contract(
    overlay: ContextToolOverlay,
    *,
    tool_manifest_digest: str,
    context_policy_digest: str,
) -> None:
    """Check immutable tool/context contracts for a separate security boundary probe."""
    if overlay.baseline_tool_manifest_digest != tool_manifest_digest:
        raise ValueError("context/tool candidate tool contract changed")
    if overlay.baseline_context_policy_digest != context_policy_digest:
        raise ValueError("context/tool candidate context policy changed")


def validate_tool_description_candidate(
    registry: AgentToolRegistry,
    *,
    tool_name: str,
    description: str,
) -> str:
    """Validate presentation copy without modifying the canonical tool contract."""
    metadata = registry.get_tool(tool_name)
    if metadata is None or not metadata.read_only:
        raise ValueError("description candidates must target an existing read-only tool")
    text = description.strip()
    if not text or len(text) > 600 or _URL.search(text) or _BENCHMARK_PATH.search(text) or redact_secrets(text) != text:
        raise ValueError("tool description candidate is empty, oversized, URL-bearing, or secret-bearing")
    if _FORBIDDEN_DESCRIPTION.search(text):
        raise ValueError("tool description candidate claims an unsupported capability")
    if _MODEL_ROUTING_COPY.search(text):
        raise ValueError("tool description candidate contains model-selection or tool-routing instructions")
    lowered = text.casefold()
    if any(term.casefold() in lowered for term in _public_benchmark_terms()):
        raise ValueError("tool description candidate contains a public benchmark identifier, path, or label")
    # Preserve security-critical semantics already advertised by canonical copy.
    original = metadata.description.casefold()
    for clause in ("read-only", "evidence", "snapshot", "truncated", "partial", "coverage"):
        if clause in original and clause not in lowered:
            raise ValueError(f"tool description candidate omits mandatory contract wording: {clause}")
    return text


def validate_overlay_for_registry(overlay: ContextToolOverlay, registry: AgentToolRegistry) -> None:
    category = _COMPONENT_CATEGORY.get(overlay.target_component)
    if category is None:
        raise ValueError("unknown context/tool experiment component")
    if overlay.hidden_tool_name is not None:
        possible_tools = set(permitted_tool_names(category))
        if overlay.hidden_tool_name not in possible_tools:
            raise ValueError("only a tool currently visible to the target component can be hidden")
        if registry.get_tool(overlay.hidden_tool_name) is None:
            raise ValueError("hidden tool is not part of the canonical registry")
    if overlay.description_tool_name is not None:
        if overlay.description_tool_name not in set(permitted_tool_names(category)):
            raise ValueError("description candidates must target a tool visible to the target component")
        validate_tool_description_candidate(
            registry,
            tool_name=overlay.description_tool_name,
            description=overlay.description_text or "",
        )


def deterministic_overlay_candidates(
    *,
    run_id: str,
    system_digest: str,
    tool_manifest_digest: str,
    target_component: str,
    baseline_token_budget: int,
    context_policy_digest: str | None = None,
    baseline_max_chunks: int = 6,
    optional_context_kinds: tuple[str, ...] = ("graph_edges", "contracts", "static_findings"),
    visible_tool_names: tuple[str, ...] = (),
    limit: int = MAX_CANDIDATES,
) -> tuple[ContextToolOverlay, ...]:
    """Create a small one-factor diagnostic inventory in stable order."""
    if not 1 <= limit <= MAX_CANDIDATES:
        raise ValueError("candidate limit exceeds the fixed experiment policy")
    candidates: list[ContextToolOverlay] = []
    common = {
        "run_id": run_id,
        "target_component": target_component,
        "baseline_system_digest": system_digest,
        "baseline_context_policy_digest": context_policy_digest or context_policy_identity(),
        "baseline_tool_manifest_digest": tool_manifest_digest,
    }

    def add(candidate_id: str, dimension: ContextToolDimension, **value: Any) -> None:
        if len(candidates) < limit:
            candidates.append(ContextToolOverlay(
                candidate_id=candidate_id,
                dimension=dimension,
                **common,
                **value,
            ))

    add("context-budget-75", ContextToolDimension.CONTEXT_TOKEN_BUDGET, context_budget_fraction=0.75)
    add("context-budget-50", ContextToolDimension.CONTEXT_TOKEN_BUDGET, context_budget_fraction=0.5)
    for kind in optional_context_kinds:
        add(f"omit-{kind}", ContextToolDimension.OPTIONAL_CONTEXT_KIND, excluded_context_kind=kind)
    for reduction in (1, 2):
        add(
            f"max-chunks-minus-{reduction}",
            ContextToolDimension.MAX_RETRIEVED_CHUNKS,
            max_chunks_reduction=reduction,
        )
    for name in sorted(set(visible_tool_names)):
        add(f"hide-{name}", ContextToolDimension.TOOL_VISIBILITY, hidden_tool_name=name)
    return tuple(candidates)


__all__ = [
    "BASELINE_CONTEXT_POLICY_DIGEST", "MAX_CANDIDATES", "MAX_CASES", "MAX_FULL_CANDIDATES",
    "MAX_MODEL_CALLS_PER_WORK_UNIT",
    "PARETO_POLICY_VERSION",
    "QUALITY_COMPARISON_POLICY_VERSION",
    "MAX_TRIALS_PER_CASE", "MAX_TRIAL_WORK_UNITS", "MAX_WALL_CLOCK_SECONDS", "POLICY_VERSION",
    "SCREEN_SELECTION_VERSION",
    "context_component_for_intent", "context_policy_identity", "deterministic_overlay_candidates",
    "validate_overlay_for_registry", "validate_overlay_identity", "validate_tool_description_candidate",
    "validate_overlay_contract", "_public_benchmark_terms",
]
