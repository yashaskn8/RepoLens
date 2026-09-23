"""Supported LangGraph checkpoint discovery for factual-only replay sources."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.evaluation.counterfactual.contracts import canonical_digest


def _json_safe(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "value"):
        return _json_safe(value.value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(type(value).__name__)


def checkpoint_state_digest(values: Mapping[str, Any]) -> str:
    """Hash full checkpoint values locally without serializing them to artifacts."""
    return canonical_digest(_json_safe(values))


def checkpoint_id_digest(config: Mapping[str, Any]) -> str | None:
    configurable = config.get("configurable") if isinstance(config, Mapping) else None
    checkpoint_id = configurable.get("checkpoint_id") if isinstance(configurable, Mapping) else None
    if not isinstance(checkpoint_id, str) or not checkpoint_id:
        return None
    return canonical_digest({"checkpoint_id": checkpoint_id})


def _finding_id(value: Any) -> str:
    raw = value.get("id") if isinstance(value, Mapping) else getattr(value, "id", None)
    return str(raw or "")


def _trace_last_node(values: Mapping[str, Any]) -> str | None:
    trace = values.get("workflow_trace")
    if not isinstance(trace, list) or not trace:
        return None
    event = trace[-1]
    return str(event.get("node")) if isinstance(event, Mapping) and event.get("node") else None


async def locate_factual_checkpoint(
    graph: Any,
    factual_config: Mapping[str, Any],
    *,
    target_node: str,
    target_finding_id: str,
    expected_snapshot_id: str,
    max_history: int,
) -> tuple[Any | None, str]:
    """Return one exact historical checkpoint or a fail-closed reason code.

    The caller must invoke this before creating any replay branch. Selection is
    based on node trace, state membership, snapshot binding and pending edge,
    never on history ordering or list position.
    """
    matches = []
    try:
        async for snapshot in graph.aget_state_history(factual_config, limit=max_history):
            values = getattr(snapshot, "values", None)
            if not isinstance(values, Mapping) or not values:
                continue
            if str(values.get("commit_hash") or "") != expected_snapshot_id:
                continue
            config = getattr(snapshot, "config", None)
            if checkpoint_id_digest(config or {}) is None:
                continue
            next_nodes = tuple(str(item) for item in (getattr(snapshot, "next", ()) or ()))
            if target_node == "verifier":
                trace_matches = _trace_last_node(values) == "verifier"
                rejected = any(
                    str(item.get("finding_id") or "") == target_finding_id
                    for item in values.get("rejected_findings", [])
                    if isinstance(item, Mapping)
                )
                verified = any(_finding_id(item) == target_finding_id for item in values.get("verified_findings", []))
                target_present = rejected or verified
                has_successor = bool(next_nodes)
                suitable = trace_matches and target_present and has_successor
            elif target_node == "revise":
                trace_matches = _trace_last_node(values) == "revise"
                candidates = values.get("candidate_findings", [])
                target_present = any(_finding_id(item) == target_finding_id for item in candidates)
                revised = values.get("revision_candidates", [])
                target_revised = any(_finding_id(item) == target_finding_id for item in revised)
                suitable = trace_matches and target_present and target_revised and "verifier" in next_nodes
            else:
                return None, "POLICY_BLOCKED"
            if suitable:
                matches.append(snapshot)
    except Exception:
        return None, "CHECKPOINT_HISTORY_UNAVAILABLE"
    if not matches:
        return None, "CHECKPOINT_NOT_FOUND"
    if len(matches) != 1:
        return None, "CHECKPOINT_AMBIGUOUS"
    return matches[0], "SELECTED"


async def locate_pre_revision_checkpoint(
    graph: Any,
    factual_config: Mapping[str, Any],
    *,
    target_finding_id: str,
    expected_snapshot_id: str,
    max_history: int,
) -> tuple[Any | None, str]:
    """Find the exact predecessor that proves the restored candidate existed."""
    matches = []
    try:
        async for snapshot in graph.aget_state_history(factual_config, limit=max_history):
            values = getattr(snapshot, "values", None)
            if not isinstance(values, Mapping) or not values:
                continue
            if str(values.get("commit_hash") or "") != expected_snapshot_id:
                continue
            if "revise" not in tuple(str(item) for item in (getattr(snapshot, "next", ()) or ())):
                continue
            if _trace_last_node(values) not in {"mcp_enrich", "investigator_complete"}:
                continue
            if target_finding_id not in set(map(str, values.get("revision_target_ids", []))):
                continue
            if not any(_finding_id(item) == target_finding_id for item in values.get("candidate_findings", [])):
                continue
            if checkpoint_id_digest(getattr(snapshot, "config", {}) or {}) is None:
                continue
            matches.append(snapshot)
    except Exception:
        return None, "CHECKPOINT_HISTORY_UNAVAILABLE"
    if not matches:
        return None, "PRE_REVISION_CHECKPOINT_NOT_FOUND"
    if len(matches) != 1:
        return None, "PRE_REVISION_CHECKPOINT_AMBIGUOUS"
    return matches[0], "SELECTED"


__all__ = [
    "checkpoint_id_digest",
    "checkpoint_state_digest",
    "locate_factual_checkpoint",
]
