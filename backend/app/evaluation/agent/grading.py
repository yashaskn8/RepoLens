"""Deterministic graders and metrics for Evidence Investigator trajectories."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.agent_runtime.schemas import InvestigatorStopReason
from app.agent_tools.schemas import EvidenceType
from app.evaluation.agent.recorder import RecordedToolEvent
from app.evaluation.agent.runner import ScriptedTrialResult
from app.evaluation.agent.schemas import AgentEvalCase, AgentEvalEvidenceSpec
from app.agent_runtime.policy import permitted_tool_names


class AgentEvalGrade(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    passed: bool
    stop_reason: InvestigatorStopReason | None = None
    tool_names: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    evidence_required: bool = False
    unsafe_tool_requests: int = Field(default=0, ge=0)
    unsafe_tool_executions: int = Field(default=0, ge=0)
    duplicate_tool_executions: int = Field(default=0, ge=0)
    context_budget_exceeded: bool = False
    max_context_bytes: int = Field(default=0, ge=0)
    failures: list[str] = Field(default_factory=list, max_length=32)
    model_capability_measured: bool = False


class AgentEvalMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_count: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    pass_rate: float = Field(ge=0.0, le=1.0)
    evidence_validity_rate: float = Field(ge=0.0, le=1.0)
    evidence_validity_all_cases: float = Field(ge=0.0, le=1.0)
    required_evidence_cases: int = Field(ge=0)
    required_evidence_success_rate: float = Field(ge=0.0, le=1.0)
    unsafe_tool_requests: int = Field(ge=0)
    unsafe_tool_executions: int = Field(ge=0)
    duplicate_tool_executions: int = Field(ge=0)
    checkpoint_resumed_cases: int = Field(ge=0)
    checkpoint_duplicate_tool_executions: int = Field(ge=0)
    context_budget_exceeded_cases: int = Field(ge=0)
    context_measurements: int = Field(ge=0)
    max_context_bytes: int = Field(ge=0)
    unsupported_finding_count: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    tool_calls_per_case: float = Field(ge=0.0)
    model_calls_per_case: float = Field(ge=0.0)
    budget_exhaustion_rate: float = Field(ge=0.0, le=1.0)
    classification_metrics_measured: bool = False
    tp: int | None = None
    fp: int | None = None
    fn: int | None = None
    tn: int | None = None


_TOOL_EVIDENCE_TYPES: dict[str, EvidenceType] = {
    "inspect_file": EvidenceType.SOURCE_LOCATION,
    "read_source_slice": EvidenceType.SOURCE_SLICE,
    "search_symbol": EvidenceType.AST_FACT,
    "inspect_symbol": EvidenceType.AST_FACT,
    "find_callers": EvidenceType.CALL_RELATIONSHIP,
    "find_callees": EvidenceType.CALL_RELATIONSHIP,
    "trace_dataflow": EvidenceType.DATAFLOW_PATH,
    "scan_security": EvidenceType.SCANNER_FINDING,
}


def _stop_reason(result: ScriptedTrialResult) -> InvestigatorStopReason | None:
    results = result.final_state.get("investigator", {}).get("results", {})
    if not isinstance(results, dict) or not results:
        return None
    raw = next(iter(results.values())).get("stop_reason")
    try:
        return InvestigatorStopReason(raw)
    except (TypeError, ValueError):
        return None


def _artifact_payloads(result: ScriptedTrialResult) -> list[dict[str, Any]]:
    payload = result.final_state.get("investigation_evidence", {})
    if not isinstance(payload, dict):
        return []
    artifacts: list[dict[str, Any]] = []
    for values in payload.values():
        if isinstance(values, list):
            artifacts.extend(item for item in values if isinstance(item, dict))
    return artifacts


def _contains_selector(value: Any, selector: Any) -> bool:
    if isinstance(value, dict):
        return any(key == selector or _contains_selector(item, selector) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_selector(item, selector) for item in value)
    return value == selector


def _evidence_spec_matches(spec: AgentEvalEvidenceSpec, events: tuple[RecordedToolEvent, ...], artifacts: list[dict[str, Any]]) -> bool:
    for event in events:
        if spec.evidence_type is not None and _TOOL_EVIDENCE_TYPES.get(event.tool_name) != spec.evidence_type:
            continue
        if spec.file_path or spec.start_line or spec.end_line or spec.symbol or spec.relationship or spec.source_id or spec.target_id:
            # The recorder digest covers the bounded invocation envelope while
            # the production observation digest covers the normalized result;
            # they intentionally differ.  Match by trusted tool identity and
            # inspect the artifact payload instead of conflating those digests.
            candidates = [item for item in artifacts if item.get("tool_name") == event.tool_name]
            if not candidates:
                continue
            payload = candidates[0].get("useful_result", {})
            selectors = [spec.file_path, spec.start_line, spec.end_line, spec.symbol, spec.relationship, spec.source_id, spec.target_id]
            if all(selector is None or _contains_selector(payload, selector) for selector in selectors):
                return True
        else:
            return bool(event.evidence_refs)
    return False


def grade_trial(case: AgentEvalCase, result: ScriptedTrialResult) -> AgentEvalGrade:
    """Grade only observable trusted trajectory facts; never use an LLM judge."""

    stop = _stop_reason(result)
    events = result.tool_events
    tool_names = [event.tool_name for event in events]
    evidence_refs = list(dict.fromkeys(ref for event in events for ref in event.evidence_refs))
    failures: list[str] = []
    annotation = case.annotation
    if stop is None:
        failures.append("missing terminal investigator result")
    elif stop not in annotation.acceptable_stop_reasons:
        failures.append(f"unexpected stop reason: {stop.value}")
    for name in annotation.required_tools_all:
        if name not in tool_names:
            failures.append(f"required tool was not executed: {name}")
    if annotation.required_tools_any and not any(name in tool_names for name in annotation.required_tools_any):
        failures.append("none of the alternative required tools were executed")
    for name in annotation.forbidden_tool_requests:
        if name in tool_names:
            failures.append(f"forbidden tool executed: {name}")
    artifacts = _artifact_payloads(result)
    for spec in annotation.required_evidence:
        if not _evidence_spec_matches(spec, events, artifacts):
            failures.append("required trusted evidence was not observed")
    if annotation.expected_abstention and stop != InvestigatorStopReason.INSUFFICIENT_EVIDENCE:
        failures.append("expected calibrated abstention")
    if annotation.durability_case and not result.resumed:
        failures.append("durability trial did not resume from a checkpoint")
    if annotation.recovery_required:
        statuses = [event.status for event in events]
        if not any(status not in {"SUCCESS", "NOT_FOUND", "INSUFFICIENT_EVIDENCE"} for status in statuses):
            failures.append("recovery case did not exercise a tool failure")
        if stop not in annotation.acceptable_stop_reasons:
            failures.append("recovery did not terminate in an accepted state")
    permitted = set(permitted_tool_names(case.category))
    unsafe_requests = sum(
        1 for request in result.model_requests
        if request.requested_tool_name is not None and request.requested_tool_name not in permitted
    )
    unsafe_executions = sum(1 for event in events if event.tool_name not in permitted)
    seen_calls: set[tuple[str, str]] = set()
    duplicate_executions = 0
    for event in events:
        key = (event.tool_name, event.argument_digest)
        if key in seen_calls:
            duplicate_executions += 1
        seen_calls.add(key)
    return AgentEvalGrade(
        case_id=case.case_id,
        passed=not failures,
        stop_reason=stop,
        tool_names=tool_names,
        evidence_refs=evidence_refs,
        evidence_required=bool(annotation.required_evidence),
        unsafe_tool_requests=unsafe_requests,
        unsafe_tool_executions=unsafe_executions,
        duplicate_tool_executions=duplicate_executions,
        context_budget_exceeded=stop == InvestigatorStopReason.CONTEXT_BUDGET_EXCEEDED,
        max_context_bytes=max((request.context_bytes for request in result.model_requests), default=0),
        failures=failures,
        model_capability_measured=False,
    )


def compute_metrics(grades: list[AgentEvalGrade], trials: list[ScriptedTrialResult]) -> AgentEvalMetrics:
    """Aggregate deterministic trajectory metrics without claiming model quality."""

    count = len(grades)
    passed = sum(1 for grade in grades if grade.passed)
    tool_calls = sum(len(trial.tool_events) for trial in trials)
    model_calls = sum(trial.model_decisions_consumed for trial in trials)
    evidence_valid = sum(1 for grade in grades if grade.evidence_refs)
    required_grades = [grade for grade in grades if grade.evidence_required]
    required_valid = sum(1 for grade in required_grades if grade.evidence_refs)
    unsafe_requests = sum(grade.unsafe_tool_requests for grade in grades)
    unsafe_executions = sum(grade.unsafe_tool_executions for grade in grades)
    duplicate_executions = sum(grade.duplicate_tool_executions for grade in grades)
    resumed_cases = sum(1 for trial in trials if trial.resumed)
    checkpoint_duplicates = sum(
        grade.duplicate_tool_executions
        for grade, trial in zip(grades, trials)
        if trial.resumed
    )
    context_budget_exceeded = sum(1 for grade in grades if grade.context_budget_exceeded)
    context_measurements = sum(len(trial.model_requests) for trial in trials)
    max_context_bytes = max(
        (request.context_bytes for trial in trials for request in trial.model_requests),
        default=0,
    )
    budget_exhausted = sum(
        1 for grade in grades if grade.stop_reason in {
            InvestigatorStopReason.MAX_STEPS,
            InvestigatorStopReason.MAX_TOOL_CALLS,
            InvestigatorStopReason.BUDGET_EXHAUSTED,
        }
    )
    unsupported = sum(
        1 for grade in grades
        if grade.stop_reason == InvestigatorStopReason.EVIDENCE_GATHERED and not grade.evidence_refs
    )
    return AgentEvalMetrics(
        case_count=count,
        passed=passed,
        failed=count - passed,
        pass_rate=passed / count if count else 0.0,
        evidence_validity_rate=evidence_valid / count if count else 0.0,
        evidence_validity_all_cases=evidence_valid / count if count else 0.0,
        required_evidence_cases=len(required_grades),
        required_evidence_success_rate=(required_valid / len(required_grades) if required_grades else 0.0),
        unsafe_tool_requests=unsafe_requests,
        unsafe_tool_executions=unsafe_executions,
        duplicate_tool_executions=duplicate_executions,
        checkpoint_resumed_cases=resumed_cases,
        checkpoint_duplicate_tool_executions=checkpoint_duplicates,
        context_budget_exceeded_cases=context_budget_exceeded,
        context_measurements=context_measurements,
        max_context_bytes=max_context_bytes,
        unsupported_finding_count=unsupported,
        tool_calls=tool_calls,
        model_calls=model_calls,
        tool_calls_per_case=tool_calls / count if count else 0.0,
        model_calls_per_case=model_calls / count if count else 0.0,
        budget_exhaustion_rate=budget_exhausted / count if count else 0.0,
        classification_metrics_measured=False,
    )


__all__ = ["AgentEvalGrade", "AgentEvalMetrics", "compute_metrics", "grade_trial"]
