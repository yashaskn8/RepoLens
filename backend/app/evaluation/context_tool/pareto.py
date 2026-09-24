"""Small Pareto-set helper; deliberately does not produce a scalar score."""

from __future__ import annotations

from typing import Iterable

from app.evaluation.context_tool.contracts import ContextToolCandidateResult


_EFFICIENCY_AXES = (
    "estimated_context_tokens_delta",
    "tool_calls_delta",
    "latency_ms_per_trial_delta",
    "measured_cost_usd_delta",
)


def _eligible_axes(item: ContextToolCandidateResult) -> dict[str, float] | None:
    if item.evaluation_stage != "FULL_DEV" or item.scripted_security_gate != "PASS":
        return None
    if item.recommendation.value != "HUMAN_REVIEW_ELIGIBLE":
        return None
    values = {
        axis: float(item.efficiency_deltas[axis])
        for axis in _EFFICIENCY_AXES
        if item.efficiency_deltas.get(axis) is not None
    }
    if not values:
        return None
    return values


def pareto_frontier(candidates: Iterable[ContextToolCandidateResult]) -> list[str]:
    """Return nondominated eligible candidate IDs across measured efficiency deltas."""
    selected = [(item, _eligible_axes(item)) for item in candidates]
    selected = [(item, axes) for item, axes in selected if axes is not None]
    frontier: list[str] = []
    for item, axes in selected:
        assert axes is not None
        dominated = False
        for other, other_axes in selected:
            if other.candidate_id == item.candidate_id or other_axes is None:
                continue
            # Compare only candidates measured on the same axes. Missing usage
            # is unknown, not an implicit zero or an opportunity to dominate.
            if set(axes) != set(other_axes):
                continue
            if all(other_axes[axis] <= axes[axis] for axis in axes) and any(
                other_axes[axis] < axes[axis] for axis in axes
            ):
                dominated = True
                break
        if not dominated:
            frontier.append(item.candidate_id)
    return sorted(frontier)


__all__ = ["pareto_frontier"]
