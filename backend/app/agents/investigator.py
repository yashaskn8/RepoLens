"""Durable LangGraph steps for bounded model-directed evidence investigation."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional

from langgraph.runtime import Runtime
from pydantic import ValidationError

from app.agent_runtime.context import (
    InvestigatorContextBudgetExceeded,
    compact_observation,
    normalize_tool_result,
    pack_decision_context,
)
from app.agent_runtime.prompt_overlay import resolve_agent_prompt_version
from app.agent_runtime.policy import (
    InvestigatorPolicyViolation,
    authorize_decision,
    category_model_policy,
    compact_tool_definitions,
)
from app.agent_runtime.schemas import (
    INVESTIGATOR_DECISION_OUTPUT_SCHEMA,
    INVESTIGATOR_DECISION_SCHEMA_VERSION,
    INVESTIGATOR_PROMPT_VERSION,
    EvidenceLedgerEntry,
    InvestigatorAction,
    InvestigatorBudget,
    InvestigatorDecision,
    InvestigatorFindingContext,
    InvestigatorResult,
    InvestigatorRunState,
    InvestigatorStopReason,
    InvestigatorTargetState,
    InvestigatorTrajectoryStep,
    InvestigatorWorkingMemory,
    MemoryEntry,
    MemoryKind,
    VerifierGap,
)
from app.agent_runtime.stuck_detector import is_stuck, tool_call_fingerprint
from app.agent_tools.schemas import ToolError, ToolInvocationResult, ToolResultStatus
from app.agents.helpers import extract_json_block
from app.agents.state import AnalysisState
from app.atomic_claims import ClaimVerificationState, claims_from_metadata
from app.context.runtime import AnalysisRuntimeContext
from app.core.config import get_settings
from app.llm.exceptions import LLMQuotaExhaustedError
from app.llm.router import get_llm_router
from app.llm.types import AIRequestBudget, LLMRequest, ModelCostTier
from app.llm.workflow_contracts import lineage_for_scan
from app.security.redaction import redact_secrets


def _runtime_context(
    runtime: Optional[Runtime[AnalysisRuntimeContext]],
) -> AnalysisRuntimeContext | None:
    if runtime is None:
        return None
    return getattr(runtime, "context", None)


def _run_state(state: AnalysisState) -> InvestigatorRunState:
    return InvestigatorRunState.model_validate(state.get("investigator") or {})


def _candidate_map(state: AnalysisState) -> dict[str, Any]:
    return {str(item.id): item for item in state.get("candidate_findings", [])}


def _initial_target(state: AnalysisState, target_id: str) -> InvestigatorTargetState | None:
    candidate = _candidate_map(state).get(target_id)
    if candidate is None:
        return None
    evidence = candidate.evidences[0] if candidate.evidences else None
    category = str(candidate.category or "bug").lower()
    claims = claims_from_metadata(candidate.model_metadata)
    claim_summaries = [redact_secrets(item.claim_text)[:500] for item in claims[:12]]
    unresolved = [
        redact_secrets(item.claim_text)[:500]
        for item in claims
        if item.verification_state == ClaimVerificationState.INSUFFICIENT
    ][:12]
    rejection = next(
        (
            item for item in state.get("rejected_findings", [])
            if str(item.get("finding_id")) == target_id
        ),
        {},
    )
    verifier_reason = redact_secrets(
        str(rejection.get("reason") or candidate.verification_reason or "Semantic evidence remains unresolved.")
    )[:2_000]
    snapshot = str(state.get("commit_hash") or "unknown")[:128]
    known_ids = [str(item.id) for item in candidate.evidences[:32]]
    finding = InvestigatorFindingContext(
        finding_id=target_id,
        title=redact_secrets(candidate.title)[:300],
        category=category,
        description=redact_secrets(candidate.description)[:2_000],
        severity=getattr(candidate.severity, "value", str(candidate.severity))[:32],
        primary_file=evidence.file_path if evidence else None,
        primary_start_line=evidence.start_line if evidence else None,
        primary_end_line=evidence.end_line if evidence else None,
        known_evidence_ids=known_ids,
        atomic_claim_summary=claim_summaries,
        repository_snapshot=snapshot,
    )
    gap = VerifierGap(
        finding_id=target_id,
        reason=verifier_reason,
        unresolved_claims=unresolved or [verifier_reason[:500]],
    )
    memory = InvestigatorWorkingMemory(
        important_files=[evidence.file_path] if evidence and evidence.file_path else [],
        entries=[
            MemoryEntry(kind=MemoryKind.OPEN_QUESTION, text=item)
            for item in (unresolved or [verifier_reason[:500]])[:12]
            if item
        ],
    )
    ledger: list[EvidenceLedgerEntry] = []
    for item in candidate.evidences[:16]:
        ledger.append(EvidenceLedgerEntry(
            evidence_id=str(item.id),
            source="independent_verifier_attestation",
            tool="initial_attestation",
            status="SUCCESS",
            repository_snapshot=snapshot,
            tool_contract_version="verifier/2.0",
            file_path=item.file_path,
            start_line=item.start_line,
            end_line=item.end_line,
            fact_summary=(
                f"Independent verifier attested source bytes at {item.file_path}"
                f"{':' + str(item.start_line) if item.start_line else ''}."
            ),
        ))
    settings = get_settings()
    return InvestigatorTargetState(
        finding=finding,
        verifier_gap=gap,
        budget=InvestigatorBudget(
            max_steps=settings.AGENT_INVESTIGATOR_MAX_STEPS,
            max_tool_calls=settings.AGENT_INVESTIGATOR_MAX_TOOL_CALLS,
        ),
        evidence_ledger=ledger,
        working_memory=memory,
    )


async def run_investigator_prepare_node(
    state: AnalysisState,
    runtime: Optional[Runtime[AnalysisRuntimeContext]] = None,
) -> dict[str, Any]:
    """Prepare exactly one target without placing runtime services in state."""

    settings = get_settings()
    run = _run_state(state)
    if not run.targets:
        run.targets = list(dict.fromkeys(state.get("revision_target_ids", [])))[
            : settings.AGENT_INVESTIGATOR_MAX_TARGETS
        ]
    while run.active is None and run.target_index < len(run.targets):
        target_id = run.targets[run.target_index]
        run.active = _initial_target(state, target_id)
        if run.active is None:
            run.results[target_id] = InvestigatorResult(
                finding_id=target_id,
                stop_reason=InvestigatorStopReason.INFRASTRUCTURE_FAILURE,
                trajectory_summary="The verifier target was unavailable when investigation resumed.",
                unresolved_uncertainty=["Target finding unavailable."],
            )
            run.target_index += 1
    return {
        "investigator": run.model_dump(mode="json"),
        "completed_nodes": ["investigator_prepare"],
        "status": "INVESTIGATING",
    }


def _terminal_without_model(
    run: InvestigatorRunState,
    reason: InvestigatorStopReason,
) -> dict[str, Any]:
    if run.active is not None:
        run.active.stop_reason = reason
        run.active.pending_decision = None
    return {
        "investigator": run.model_dump(mode="json"),
        "completed_nodes": ["investigator_decide"],
        "status": "INVESTIGATING",
    }


async def run_investigator_decide_node(
    state: AnalysisState,
    runtime: Optional[Runtime[AnalysisRuntimeContext]] = None,
) -> dict[str, Any]:
    """Ask the canonical router for exactly one validated next action."""

    run = _run_state(state)
    target = run.active
    if target is None:
        return _terminal_without_model(run, InvestigatorStopReason.INFRASTRUCTURE_FAILURE)
    if target.budget.step_number >= target.budget.max_steps:
        return _terminal_without_model(run, InvestigatorStopReason.MAX_STEPS)
    context = _runtime_context(runtime)
    registry = context.agent_tools if context is not None else None
    if registry is None:
        return _terminal_without_model(run, InvestigatorStopReason.INFRASTRUCTURE_FAILURE)

    settings = get_settings()
    target.budget.step_number += 1
    tools = compact_tool_definitions(registry, target.finding.category)
    if not tools:
        return _terminal_without_model(run, InvestigatorStopReason.POLICY_BLOCKED)
    try:
        packed = pack_decision_context(
            target,
            tools,
            max_context_tokens=settings.AGENT_INVESTIGATOR_CONTEXT_TOKENS,
        )
    except InvestigatorContextBudgetExceeded:
        target.stop_reason = InvestigatorStopReason.CONTEXT_BUDGET_EXCEEDED
        target.trajectory.append(InvestigatorTrajectoryStep(
            step_number=target.budget.step_number,
            reason="CONTEXT_BUDGET_EXCEEDED",
            duration_ms=0.0,
            status="CONTEXT_BUDGET_EXCEEDED",
            remaining_steps=target.budget.max_steps - target.budget.step_number,
            remaining_tool_calls=target.budget.max_tool_calls - target.budget.tool_calls,
            stop_reason=target.stop_reason,
        ))
        run.active = target
        return {
            "investigator": run.model_dump(mode="json"),
            "completed_nodes": ["investigator_decide"],
            "status": "INVESTIGATING",
        }

    policy, capability = category_model_policy(target.finding.category)
    request = LLMRequest(
        messages=list(packed.messages),
        task_policy=policy,
        capability=capability,
        output_schema=INVESTIGATOR_DECISION_OUTPUT_SCHEMA,
        temperature=0.0,
        max_tokens=700,
        timeout_seconds=settings.AGENT_INVESTIGATOR_MODEL_TIMEOUT_SECONDS,
        cache_mode="disabled",
        allow_escalation=True,
        budget=AIRequestBudget(
            max_ai_calls=1,
            max_input_tokens=settings.AGENT_INVESTIGATOR_CONTEXT_TOKENS,
            max_output_tokens=700,
            max_escalation_tier=ModelCostTier.CHEAP,
            max_context_tokens=settings.AGENT_INVESTIGATOR_CONTEXT_TOKENS + 700,
        ),
        lineage=lineage_for_scan(
            str(state.get("scan_id", "")),
            prompt_template_version=resolve_agent_prompt_version("evidence-investigator", INVESTIGATOR_PROMPT_VERSION),
            output_schema_version=INVESTIGATOR_DECISION_SCHEMA_VERSION,
            evidence={
                "finding_id": target.finding.finding_id,
                "repository_snapshot": target.finding.repository_snapshot,
                "step": target.budget.step_number,
                "context_digest": packed.evidence_digest,
            },
        ),
        context_metrics=packed.metrics,
    )
    response = None
    started = time.perf_counter()
    try:
        from app.observability import span

        with span(
            "agent.investigator.plan",
            attributes={
                "gen_ai.operation.name": "plan",
                "gen_ai.agent.name": "EvidenceInvestigator",
                "repolens.investigator.step": target.budget.step_number,
                "repolens.investigator.remaining_steps": target.budget.max_steps - target.budget.step_number,
                "repolens.investigator.remaining_tool_calls": target.budget.max_tool_calls - target.budget.tool_calls,
                "repolens.investigator.context_bytes": packed.telemetry.get("packed_context_bytes", 0),
                "repolens.investigator.context_tokens": packed.telemetry.get("estimated_context_tokens", 0),
                "repolens.investigator.evidence_count": len(target.evidence_ledger),
            },
        ):
            router = context.llm_router if context is not None and context.llm_router is not None else get_llm_router()
            response = await asyncio.wait_for(
                router.generate(request),
                timeout=settings.AGENT_INVESTIGATOR_MODEL_TIMEOUT_SECONDS + 1.0,
            )
        decision = InvestigatorDecision.model_validate(
            json.loads(extract_json_block(response.content))
        )
        status = "DECIDED"
        stop_reason = None
    except LLMQuotaExhaustedError:
        decision = None
        status = "MODEL_BUDGET_EXHAUSTED"
        stop_reason = InvestigatorStopReason.BUDGET_EXHAUSTED
    except (ValidationError, ValueError, TypeError, json.JSONDecodeError):
        decision = None
        status = "MODEL_INVALID_OUTPUT"
        stop_reason = InvestigatorStopReason.INVALID_MODEL_OUTPUT
    except asyncio.TimeoutError:
        decision = None
        status = "MODEL_PROVIDER_TIMEOUT"
        stop_reason = InvestigatorStopReason.INFRASTRUCTURE_FAILURE
    except Exception:
        decision = None
        status = "MODEL_PROVIDER_FAILURE"
        stop_reason = InvestigatorStopReason.INFRASTRUCTURE_FAILURE

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    action = decision.action if decision is not None else None
    reason_text = decision.reason if decision is not None else status
    if decision is not None:
        target.pending_decision = decision
        if decision.action == InvestigatorAction.FINISH:
            stop_reason = InvestigatorStopReason.EVIDENCE_GATHERED
        elif decision.action == InvestigatorAction.ABSTAIN:
            stop_reason = InvestigatorStopReason.INSUFFICIENT_EVIDENCE
    target.stop_reason = stop_reason
    target.trajectory.append(InvestigatorTrajectoryStep(
        step_number=target.budget.step_number,
        action=action,
        reason=reason_text,
        tool_name=decision.tool_name if decision else None,
        provider=str(response.provider.value) if response is not None else None,
        model=response.model if response is not None else None,
        duration_ms=elapsed_ms,
        status=status,
        remaining_steps=target.budget.max_steps - target.budget.step_number,
        remaining_tool_calls=target.budget.max_tool_calls - target.budget.tool_calls,
        context_metrics=packed.telemetry,
        stop_reason=stop_reason,
    ))
    run.active = target
    result: dict[str, Any] = {
        "investigator": run.model_dump(mode="json"),
        "completed_nodes": ["investigator_decide"],
        "status": "INVESTIGATING",
    }
    if response is not None:
        result["model_executions"] = [response.metadata]
    return result


def route_after_investigator_decide(state: AnalysisState) -> str:
    run = _run_state(state)
    if run.active is None or run.active.stop_reason is not None:
        return "complete"
    decision = run.active.pending_decision
    return "tool" if decision and decision.action == InvestigatorAction.TOOL_CALL else "complete"


def _update_tool_step(
    target: InvestigatorTargetState,
    *,
    status: str,
    argument_digest: str | None = None,
    result_digest: str | None = None,
    evidence_refs: list[str] | None = None,
    tool_contract_version: str | None = None,
    duration_ms: float = 0.0,
    stop_reason: InvestigatorStopReason | None = None,
) -> None:
    if not target.trajectory:
        return
    step = target.trajectory[-1]
    step.status = status
    step.argument_digest = argument_digest
    step.result_digest = result_digest
    step.evidence_refs = evidence_refs or []
    step.tool_contract_version = tool_contract_version
    step.duration_ms += max(0.0, duration_ms)
    step.remaining_tool_calls = target.budget.max_tool_calls - target.budget.tool_calls
    step.stop_reason = stop_reason


async def run_investigator_tool_node(
    state: AnalysisState,
    runtime: Optional[Runtime[AnalysisRuntimeContext]] = None,
) -> dict[str, Any]:
    """Validate policy/schema/budgets and execute one canonical registry tool."""

    run = _run_state(state)
    target = run.active
    decision = target.pending_decision if target is not None else None
    context = _runtime_context(runtime)
    registry = context.agent_tools if context is not None else None
    if target is None or decision is None or decision.action != InvestigatorAction.TOOL_CALL or registry is None:
        if target is not None:
            target.stop_reason = InvestigatorStopReason.INFRASTRUCTURE_FAILURE
        return {
            "investigator": run.model_dump(mode="json"),
            "completed_nodes": ["investigator_tool"],
            "status": "INVESTIGATING",
        }

    assert decision.tool_name is not None
    try:
        authorize_decision(decision, category=target.finding.category, registry=registry)
    except InvestigatorPolicyViolation as exc:
        target.stop_reason = InvestigatorStopReason.POLICY_BLOCKED
        target.pending_decision = None
        _update_tool_step(target, status=exc.code, stop_reason=target.stop_reason)
        run.active = target
        return {
            "investigator": run.model_dump(mode="json"),
            "completed_nodes": ["investigator_tool"],
            "status": "INVESTIGATING",
        }

    validation_error = registry.validate_arguments(decision.tool_name, decision.arguments)
    if validation_error is not None:
        target.stop_reason = InvestigatorStopReason.POLICY_BLOCKED
        target.pending_decision = None
        _update_tool_step(
            target,
            status="TOOL_ARGUMENT_INVALID",
            stop_reason=target.stop_reason,
        )
        run.active = target
        return {
            "investigator": run.model_dump(mode="json"),
            "completed_nodes": ["investigator_tool"],
            "status": "INVESTIGATING",
        }

    if target.budget.tool_calls >= target.budget.max_tool_calls:
        target.stop_reason = InvestigatorStopReason.MAX_TOOL_CALLS
        target.pending_decision = None
        _update_tool_step(target, status="TOOL_BUDGET_EXCEEDED", stop_reason=target.stop_reason)
        run.active = target
        return {
            "investigator": run.model_dump(mode="json"),
            "completed_nodes": ["investigator_tool"],
            "status": "INVESTIGATING",
        }

    fingerprint = tool_call_fingerprint(
        target.finding.finding_id,
        decision.tool_name,
        decision.arguments,
    )
    if is_stuck(target.call_fingerprints, fingerprint):
        target.stop_reason = InvestigatorStopReason.STUCK
        target.pending_decision = None
        _update_tool_step(
            target,
            status="STUCK_LOOP",
            argument_digest=fingerprint,
            stop_reason=target.stop_reason,
        )
        run.active = target
        return {
            "investigator": run.model_dump(mode="json"),
            "completed_nodes": ["investigator_tool"],
            "status": "INVESTIGATING",
        }

    target.budget.tool_calls += 1
    target.pending_call_fingerprint = fingerprint
    metadata = registry.get_tool(decision.tool_name)
    started = time.perf_counter()
    try:
        tool_result = await asyncio.wait_for(
            asyncio.to_thread(registry.invoke, decision.tool_name, decision.arguments),
            timeout=get_settings().AGENT_INVESTIGATOR_TOOL_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        tool_result = ToolInvocationResult(
            tool=decision.tool_name,
            tool_version=metadata.tool_version if metadata else "unknown",
            status=ToolResultStatus.INTERNAL_ERROR,
            errors=[ToolError(code="TOOL_TIMEOUT", message="The deterministic tool exceeded its timeout.")],
        )
    duration_ms = (time.perf_counter() - started) * 1000.0
    observation = normalize_tool_result(
        tool_result,
        step_number=target.budget.step_number,
        arguments=decision.arguments,
    )
    target.pending_observation = observation
    if tool_result.status == ToolResultStatus.INTERNAL_ERROR:
        target.stop_reason = InvestigatorStopReason.TOOL_FAILURE
    _update_tool_step(
        target,
        status=(tool_result.errors[0].code if tool_result.errors else tool_result.status.value),
        argument_digest=fingerprint,
        result_digest=observation.result_digest,
        evidence_refs=observation.evidence_refs,
        tool_contract_version=tool_result.contract_version,
        duration_ms=duration_ms,
        stop_reason=target.stop_reason,
    )
    run.active = target
    return {
        "investigator": run.model_dump(mode="json"),
        "completed_nodes": ["investigator_tool"],
        "status": "INVESTIGATING",
    }


async def run_investigator_compact_node(
    state: AnalysisState,
    runtime: Optional[Runtime[AnalysisRuntimeContext]] = None,
) -> dict[str, Any]:
    """Compact one normalized checkpointed observation without another model call."""

    run = _run_state(state)
    target = run.active
    if target is not None and target.pending_observation is not None and target.pending_call_fingerprint:
        snapshot_mismatch = any(
            warning.startswith("CROSS_SNAPSHOT_EVIDENCE:")
            for warning in target.pending_observation.warnings
        ) or target.pending_observation.repository_snapshot != target.finding.repository_snapshot
        target = compact_observation(
            target,
            target.pending_observation,
            call_fingerprint=target.pending_call_fingerprint,
            recent_limit=get_settings().AGENT_INVESTIGATOR_RECENT_OBSERVATIONS,
        )
        certificate = target.progress_history[-1] if target.progress_history else None
        if snapshot_mismatch:
            target.stop_reason = InvestigatorStopReason.INFRASTRUCTURE_FAILURE
        if certificate is not None:
            from app.observability import span

            with span(
                "agent.investigator.progress",
                attributes={
                    "repolens.investigator.progress.class": certificate.progress_class.value,
                    "repolens.investigator.progress.new_files": certificate.new_file_count,
                    "repolens.investigator.progress.new_symbols": certificate.new_symbol_count,
                    "repolens.investigator.progress.new_relationships": certificate.new_relationship_count,
                    "repolens.investigator.progress.new_evidence": certificate.new_evidence_count,
                    "repolens.investigator.progress.no_progress_streak": certificate.consecutive_no_progress,
                    "repolens.investigator.progress.knowledge_state_cycle": certificate.knowledge_state_cycle,
                },
            ):
                pass
            if certificate.knowledge_state_cycle:
                target.stop_reason = InvestigatorStopReason.SEMANTIC_STAGNATION
        if target.stop_reason is None and target.budget.step_number >= target.budget.max_steps:
            target.stop_reason = InvestigatorStopReason.MAX_STEPS
        run.active = target
    return {
        "investigator": run.model_dump(mode="json"),
        "completed_nodes": ["investigator_compact"],
        "status": "INVESTIGATING",
    }


def route_after_investigator_compact(state: AnalysisState) -> str:
    run = _run_state(state)
    target = run.active
    if target is None or target.stop_reason is not None:
        return "complete"
    return "decide"


async def run_investigator_complete_node(
    state: AnalysisState,
    runtime: Optional[Runtime[AnalysisRuntimeContext]] = None,
) -> dict[str, Any]:
    """Finalize one target and expose only bounded trusted investigation artifacts."""

    run = _run_state(state)
    evidence_map = dict(state.get("investigation_evidence") or {})
    target = run.active
    if target is not None:
        stop = target.stop_reason or InvestigatorStopReason.INSUFFICIENT_EVIDENCE
        evidence_refs = list(dict.fromkeys(
            ref for item in target.evidence_ledger for ref in ([item.evidence_id] if item.evidence_id else [])
        ))[:64]
        locations = list(dict.fromkeys(
            f"{item.file_path}:{item.start_line or 1}-{item.end_line or item.start_line or 1}"
            for item in target.evidence_ledger if item.file_path
        ))[:32]
        unresolved = [
            item.text for item in target.working_memory.entries
            if item.kind in {MemoryKind.OPEN_QUESTION, MemoryKind.COVERAGE_LIMITATION}
        ][:16]
        observations = [item.fact_summary for item in target.evidence_artifacts[-8:]]
        result = InvestigatorResult(
            finding_id=target.finding.finding_id,
            stop_reason=stop,
            evidence_refs=evidence_refs,
            source_locations=locations,
            important_observations=observations,
            unresolved_uncertainty=unresolved,
            trajectory_summary=(
                f"Investigation stopped with {stop.value} after {target.budget.step_number} "
                f"model decisions and {target.budget.tool_calls} tool executions."
            ),
        )
        target.result = result
        run.results[target.finding.finding_id] = result
        evidence_map[target.finding.finding_id] = [
            item.model_dump(mode="json") for item in target.evidence_artifacts
        ]
        run.target_index += 1
        run.active = None
    return {
        "investigator": run.model_dump(mode="json"),
        "investigation_evidence": evidence_map,
        "completed_nodes": ["investigator_complete"],
        "status": "INVESTIGATING" if run.target_index < len(run.targets) else "INVESTIGATED",
    }


def route_after_investigator_complete(state: AnalysisState) -> str:
    run = _run_state(state)
    if run.target_index < len(run.targets):
        return "prepare"
    fail_closed = {
        InvestigatorStopReason.INVALID_MODEL_OUTPUT,
        InvestigatorStopReason.CONTEXT_BUDGET_EXCEEDED,
        InvestigatorStopReason.POLICY_BLOCKED,
        InvestigatorStopReason.BUDGET_EXHAUSTED,
        InvestigatorStopReason.INFRASTRUCTURE_FAILURE,
        InvestigatorStopReason.SEMANTIC_STAGNATION,
    }
    if any(item.stop_reason in fail_closed for item in run.results.values()):
        return "uncertain"
    return "revise"


__all__ = [
    "route_after_investigator_compact",
    "route_after_investigator_complete",
    "route_after_investigator_decide",
    "run_investigator_compact_node",
    "run_investigator_complete_node",
    "run_investigator_decide_node",
    "run_investigator_prepare_node",
    "run_investigator_tool_node",
]
