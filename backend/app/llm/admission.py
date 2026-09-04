"""Deterministic admission planning for repository AI work.

The admission layer answers whether a specialist needs model reasoning at all.
It only consumes facts already extracted by ingestion/scanners and never calls
or selects a model.  The LLMRouter remains the sole provider authority for
requests admitted as cloud work.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping


class AdmissionDecision(str, Enum):
    SKIP = "SKIP"
    DETERMINISTIC_ONLY = "DETERMINISTIC_ONLY"
    LOCAL_ELIGIBLE = "LOCAL_ELIGIBLE"
    CLOUD_REQUIRED = "CLOUD_REQUIRED"


@dataclass(frozen=True, slots=True)
class AIAdmissionPlan:
    """Immutable, serializable decision and reason for one specialist."""

    specialist: str
    decision: AdmissionDecision
    reason: str
    evidence_count: int = 0
    unresolved: bool = True
    priority: int = 0
    max_output_tokens: int = 800

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["decision"] = self.decision.value
        value["cloud_authorized"] = self.decision == AdmissionDecision.CLOUD_REQUIRED
        return value


# Friendly alias for callers that use the shorter name from the architecture
# contract.
AIWorkPlan = AIAdmissionPlan


def _has_locator(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("file_path"):
        return True
    for key in ("evidences", "evidence"):
        entries = value.get(key)
        if isinstance(entries, Mapping):
            entries = [entries]
        if isinstance(entries, (list, tuple)) and any(_has_locator(item) for item in entries):
            return True
    return False


def _deterministic_finding(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    source = str(value.get("source_tool") or value.get("tool") or "").lower()
    detector = str(value.get("detector_kind") or value.get("detector_id") or "").lower()
    return bool(source in {"semgrep", "trivy", "osv", "static_scanner"} or "scanner" in detector) and _has_locator(value)


def _output_budget(evidence_count: int) -> int:
    # Structured findings are intentionally small.  This is a deterministic
    # cap, not a promise that a model will use the entire allowance.
    return min(2_400, 640 + max(1, evidence_count) * 240)


def build_admission_plan(state: Mapping[str, Any], specialist: str) -> AIAdmissionPlan:
    """Build a conservative deterministic plan from current workflow facts."""
    specialist = specialist.strip().lower()
    static_findings = list(state.get("static_findings") or [])
    routes = list(state.get("routes") or [])
    frontend_calls = list(state.get("frontend_calls") or [])
    manifest = state.get("manifest_summary") or {}
    graph_coverage = state.get("graph_coverage") or manifest.get("graph_coverage") or {}
    source_available = bool(
        state.get("source_evidence_available", manifest.get("source_evidence_available", False))
    )
    tool_coverage = state.get("tool_coverage") or manifest.get("scanners_executed") or {}
    # A non-empty repository still has source evidence available to the
    # context engine even when no route/scanner projection was produced yet.
    evidence_count = len(static_findings) + len(routes) + len(frontend_calls)
    if not evidence_count and source_available and int(manifest.get("total_files", 0) or 0) > 0:
        evidence_count = 1
    explicit_unresolved = state.get(f"{specialist}_unresolved")
    unresolved = True if explicit_unresolved is None else bool(explicit_unresolved)

    if specialist == "integration" and (routes or frontend_calls):
        return AIAdmissionPlan(
            specialist=specialist,
            decision=AdmissionDecision.DETERMINISTIC_ONLY,
            reason="Route and frontend contract facts are evaluated deterministically.",
            evidence_count=evidence_count,
            unresolved=False,
            priority=80,
            max_output_tokens=0,
        )

    if specialist == "integration" and not source_available:
        return AIAdmissionPlan(
            specialist=specialist,
            decision=AdmissionDecision.SKIP,
            reason="Integration analysis is not available because source evidence was not ingested.",
            evidence_count=0,
            unresolved=False,
            priority=80,
            max_output_tokens=0,
        )

    if evidence_count == 0:
        return AIAdmissionPlan(
            specialist=specialist,
            decision=AdmissionDecision.SKIP,
            reason="No locatable evidence or contract facts require specialist reasoning.",
            evidence_count=0,
            unresolved=False,
            priority=0,
            max_output_tokens=0,
        )

    if explicit_unresolved is False:
        return AIAdmissionPlan(
            specialist=specialist,
            decision=AdmissionDecision.DETERMINISTIC_ONLY,
            reason="Deterministic analysis marked this specialist question resolved.",
            evidence_count=evidence_count,
            unresolved=False,
            priority=100 if specialist in {"security", "bug"} else 40,
            max_output_tokens=0,
        )

    security_flow_candidates = state.get("deterministic_security_flow_candidates") or []
    if (
        specialist == "security"
        and static_findings
        and all(_deterministic_finding(item) for item in static_findings)
        and not security_flow_candidates
    ):
        return AIAdmissionPlan(
            specialist=specialist,
            decision=AdmissionDecision.DETERMINISTIC_ONLY,
            reason="Scanner findings are locatable and independently verifiable; no model restatement is needed.",
            evidence_count=evidence_count,
            unresolved=False,
            priority=100,
            max_output_tokens=0,
        )

    graph_complete = bool(
        manifest.get("graph_complete")
        or graph_coverage.get("complete") is True
    )
    unresolved_graph = int(
        state.get("unresolved_graph_relationships", graph_coverage.get("unresolved_graph_relationships", 0))
        or 0
    )
    architecture_candidates = state.get("deterministic_architecture_candidates") or []
    if specialist == "architecture" and graph_complete and unresolved_graph == 0 and not architecture_candidates:
        return AIAdmissionPlan(
            specialist=specialist,
            decision=AdmissionDecision.DETERMINISTIC_ONLY,
            reason="Manifest and complete graph facts cover architecture scope with no unresolved relationships.",
            evidence_count=evidence_count,
            unresolved=False,
            priority=40,
            max_output_tokens=0,
        )

    correctness_key_present = "correctness_candidates" in state or "deterministic_correctness_candidates" in state
    correctness_candidates = state.get("correctness_candidates", state.get("deterministic_correctness_candidates"))
    if specialist == "bug" and correctness_key_present and correctness_candidates is not None and not correctness_candidates:
        return AIAdmissionPlan(
            specialist=specialist,
            decision=AdmissionDecision.SKIP,
            reason=(
                "No candidate detected by the available deterministic correctness analysis."
                if source_available
                else "Correctness analysis not available; no clean-result claim is made."
            ),
            evidence_count=evidence_count,
            unresolved=False,
            priority=90,
            max_output_tokens=0,
        )

    priority = {"security": 100, "bug": 90, "integration": 80, "architecture": 40}.get(specialist, 50)
    if specialist == "security" and any(
        str(value).upper() in {"UNAVAILABLE", "FAILED", "TIMEOUT"}
        for value in tool_coverage.values()
    ):
        priority = 95
    return AIAdmissionPlan(
        specialist=specialist,
        decision=AdmissionDecision.CLOUD_REQUIRED,
        reason="Locatable evidence leaves a specialist question unresolved; bounded model reasoning is justified.",
        evidence_count=evidence_count,
        unresolved=unresolved,
        priority=priority,
        max_output_tokens=_output_budget(evidence_count),
    )


def build_admission_map(state: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Return serializable plans for all repository specialist nodes."""
    return {
        name: build_admission_plan(state, name).as_dict()
        for name in ("architecture", "integration", "security", "bug")
    }


def admission_for_state(state: Mapping[str, Any], specialist: str) -> AIAdmissionPlan:
    """Read a persisted plan, falling back to deterministic recomputation."""
    raw = (state.get("ai_admission") or {}).get(specialist)
    if isinstance(raw, Mapping):
        try:
            return AIAdmissionPlan(
                specialist=specialist,
                decision=AdmissionDecision(str(raw.get("decision"))),
                reason=str(raw.get("reason") or "Admission plan available."),
                evidence_count=max(0, int(raw.get("evidence_count", 0))),
                unresolved=bool(raw.get("unresolved", True)),
                priority=max(0, int(raw.get("priority", 0))),
                max_output_tokens=max(0, int(raw.get("max_output_tokens", 0))),
            )
        except (TypeError, ValueError):
            pass
    return build_admission_plan(state, specialist)


__all__ = [
    "AdmissionDecision",
    "AIAdmissionPlan",
    "AIWorkPlan",
    "admission_for_state",
    "build_admission_map",
    "build_admission_plan",
]
