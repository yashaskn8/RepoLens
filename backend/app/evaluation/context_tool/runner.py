"""Bounded context/tool presentation experiments on RepoLens' real evaluators."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Sequence
from uuid import uuid4

from app.core.config import get_settings
from app.agent_runtime.prompt_overlay import active_prompt_overlay
from app.evaluation.agent.loader import load_agent_dataset
from app.evaluation.context_tool.comparison import (
    classify_screen,
    compare_experiment,
    context_evidence_reference_proxy,
    screen_regressions as compute_screen_regressions,
)
from app.evaluation.context_tool.contracts import (
    ContextAblationClass,
    ContextPresentationManifest,
    ContextToolCandidateResult,
    ContextToolDimension,
    ContextToolExperimentReport,
    ContextToolOverlay,
    ContextToolRecommendation,
    ToolSelectionProbe,
    build_experiment_report,
    canonical_digest,
)
from app.evaluation.context_tool.micro_eval import run_tool_selection_micro_eval
from app.evaluation.context_tool.policy import (
    MAX_CANDIDATES,
    MAX_CASES,
    MAX_FULL_CANDIDATES,
    MAX_MODEL_CALLS_PER_WORK_UNIT,
    MAX_TRIALS_PER_CASE,
    MAX_TRIAL_WORK_UNITS,
    MAX_WALL_CLOCK_SECONDS,
    PARETO_POLICY_VERSION,
    POLICY_VERSION,
    QUALITY_COMPARISON_POLICY_VERSION,
    SCREEN_SELECTION_VERSION,
    context_policy_identity,
    validate_overlay_identity,
)
from app.evaluation.ground_truth.public_dev import (
    PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS,
    load_public_dev_repository_cases,
)
from app.evaluation.security.contracts import AgentSecurityMode
from app.evaluation.security.runner import run_agent_security_evaluation
from app.evaluation.system.full_analysis import run_full_analysis_evaluation
from app.evaluation.system.schemas import SystemEvalMode, SystemEvalSuite, SystemEvaluationReport
from app.llm.types import LLMProvider


SCREEN_CASE_LIMIT = 4
MAX_PRESENTATION_MANIFESTS = 4_096
TOTAL_WORK_UNIT_LIMIT = MAX_TRIAL_WORK_UNITS
MAX_TOTAL_MODEL_CALL_RESERVATION = TOTAL_WORK_UNIT_LIMIT * MAX_MODEL_CALLS_PER_WORK_UNIT


def _select_public_cases(case_ids: Sequence[str] | None, max_cases: int):
    eligible = sorted(load_public_dev_repository_cases(), key=lambda item: item.case_id)
    if not 1 <= max_cases <= MAX_CASES:
        raise ValueError("max_cases must remain within the fixed public DEV workload bound")
    if case_ids is None:
        by_category: dict[str, list[Any]] = {}
        for case in eligible:
            by_category.setdefault(str(case.category.value).upper(), []).append(case)
        selected: list[Any] = []
        for category in ("SECURITY", "CORRECTNESS", "CONTRACT", "CHANGE_IMPACT"):
            candidates = by_category.get(category, [])
            if candidates and len(selected) < max_cases:
                selected.append(candidates[0])
        for case in eligible:
            if len(selected) >= max_cases:
                break
            if case.case_id not in {item.case_id for item in selected}:
                selected.append(case)
        return sorted(selected, key=lambda item: item.case_id)
    if not case_ids or len(set(case_ids)) != len(case_ids):
        raise ValueError("case selection must be non-empty and unique")
    by_id = {case.case_id: case for case in eligible}
    if not set(case_ids) <= set(by_id) or len(case_ids) > max_cases:
        raise ValueError("context/tool experiments accept only fixed public DEV case IDs")
    return [by_id[item] for item in sorted(case_ids)]


def _screen_selection(cases, baseline: SystemEvaluationReport) -> tuple[list[str], dict[str, list[str]]]:
    """Select a stable four-group screen; label use is evaluator-only, never model context."""
    inventory = {case.case_id: case for case in cases}
    groups: dict[str, list[str]] = {
        "TARGET_FAILURES": [],
        "VALIDATION": [],
        "SECURITY": [],
        "PRESERVE_REGRESSION": [],
    }
    details = baseline.full_analysis.trial_details if baseline.full_analysis is not None else []
    failures = sorted({
        item.case_id for item in details
        if item.case_id in inventory and item.failure_attribution is not None
    })
    if failures:
        groups["TARGET_FAILURES"].append(failures[0])

    categories = {case.case_id: str(case.category.value).upper() for case in cases}
    validation = sorted(
        case_id for case_id, category in categories.items()
        if category in {"CORRECTNESS", "CONTRACT"}
    )
    if validation:
        groups["VALIDATION"].append(validation[0])
    security = sorted(case_id for case_id, category in categories.items() if category == "SECURITY")
    if security:
        groups["SECURITY"].append(security[0])

    successful = sorted({
        case.case_id for case in baseline.case_results
        if case.case_id in inventory and any(trial.task_success is True for trial in case.trials)
    })
    already_selected = {
        case_id for name, values in groups.items() if name != "PRESERVE_REGRESSION" for case_id in values
    }
    preserve = next((case_id for case_id in successful if case_id not in already_selected), None)
    if preserve is None and successful:
        preserve = successful[0]
    if preserve is not None:
        groups["PRESERVE_REGRESSION"].append(preserve)

    # Ensure a nonempty bounded screen for deliberately narrow public selections.
    selected = sorted({case_id for values in groups.values() for case_id in values})
    if not selected:
        fallback = min(inventory)
        groups["VALIDATION"].append(fallback)
        selected = [fallback]
    if len(selected) > SCREEN_CASE_LIMIT:
        # Group priorities are explicit and deterministic; preserve remains a
        # separately recorded group even if its case overlaps another group.
        priority = ("TARGET_FAILURES", "VALIDATION", "SECURITY", "PRESERVE_REGRESSION")
        keep: list[str] = []
        for name in priority:
            for case_id in groups[name]:
                if case_id not in keep and len(keep) < SCREEN_CASE_LIMIT:
                    keep.append(case_id)
        selected = sorted(keep)
        groups = {name: [case_id for case_id in values if case_id in selected] for name, values in groups.items()}
    return selected, groups


def _new_overlay(
    *, run_id: str, candidate_id: str, dimension: ContextToolDimension,
    target_component: str, identity: SystemEvaluationReport, **intervention,
) -> ContextToolOverlay:
    return ContextToolOverlay(
        run_id=run_id,
        candidate_id=candidate_id,
        dimension=dimension,
        target_component=target_component,
        baseline_system_digest=identity.system_identity.system_digest,
        baseline_context_policy_digest=identity.system_identity.context_policy_digest,
        baseline_tool_manifest_digest=identity.system_identity.tool_manifest_digest,
        **intervention,
    )


def default_experiment_candidates(
    *,
    run_id: str,
    baseline: SystemEvaluationReport,
    limit: int = 4,
) -> tuple[ContextToolOverlay, ...]:
    """A stable, small, one-factor diagnostic set; no model-generated policies."""
    if not 1 <= limit <= MAX_CANDIDATES:
        raise ValueError("candidate limit exceeds fixed policy")
    settings = get_settings()
    identity = baseline.system_identity
    inventory = [
        _new_overlay(
            run_id=run_id, candidate_id="investigator-context-75pct",
            dimension=ContextToolDimension.CONTEXT_TOKEN_BUDGET,
            target_component="evidence-investigator", identity=baseline,
            context_budget_fraction=0.75,
        ),
        _new_overlay(
            run_id=run_id, candidate_id="security-context-no-graph",
            dimension=ContextToolDimension.OPTIONAL_CONTEXT_KIND,
            target_component="security-agent", identity=baseline,
            excluded_context_kind="graph_edges",
        ),
        _new_overlay(
            run_id=run_id, candidate_id="security-context-max-chunks-minus-one",
            dimension=ContextToolDimension.MAX_RETRIEVED_CHUNKS,
            target_component="security-agent", identity=baseline,
            max_chunks_reduction=1,
        ),
        _new_overlay(
            run_id=run_id, candidate_id="investigator-hide-find-callers",
            dimension=ContextToolDimension.TOOL_VISIBILITY,
            target_component="evidence-investigator", identity=baseline,
            hidden_tool_name="find_callers",
        ),
    ]
    # Check that configured context budget is positive; candidates otherwise
    # fail before any provider call and the report remains an invalid experiment.
    if settings.AGENT_INVESTIGATOR_CONTEXT_TOKENS <= 0:
        raise ValueError("baseline investigator context budget is invalid")
    return tuple(inventory[:limit])


def _append_manifest(target: list[ContextPresentationManifest], item: ContextPresentationManifest) -> None:
    if len(target) >= MAX_PRESENTATION_MANIFESTS:
        raise RuntimeError("context presentation manifest bound exhausted")
    target.append(item)


def _metric_total(report: SystemEvaluationReport, key: str) -> int:
    value = getattr(report.metrics, key, None)
    return int(value or 0)


def _measured_sum(reports: list[SystemEvaluationReport], key: str) -> float | None:
    metrics = [getattr(report.metrics, key, None) for report in reports]
    if not metrics or any(item is None or item.status.value != "MEASURED" for item in metrics):
        return None
    return sum(float(item.value) for item in metrics)


def _probe_measured_sum(probes: list[ToolSelectionProbe], key: str) -> float | None:
    values = [getattr(item, key) for item in probes]
    if not values or any(item is None for item in values):
        return None
    return sum(float(item) for item in values)


async def _run_full(
    *,
    mode: SystemEvalMode,
    provider: LLMProvider | str | None,
    model: str | None,
    case_ids: list[str],
    trials: int,
    overlay: ContextToolOverlay | None,
    allow_live: bool,
    manifests: list[ContextPresentationManifest],
    timeout_seconds: float,
    stage: str,
) -> SystemEvaluationReport:
    if timeout_seconds <= 0:
        raise asyncio.TimeoutError
    return await asyncio.wait_for(
        run_full_analysis_evaluation(
            suite=SystemEvalSuite.ALL,
            mode=mode,
            provider=provider,
            model=model,
            trials_per_case=trials,
            max_cases=max(1, len(case_ids)),
            case_ids=case_ids,
            allow_live=allow_live,
            context_tool_overlay=overlay,
            allow_context_tool_experiments=allow_live,
            presentation_manifest_sink=lambda item: _append_manifest(manifests, item),
            presentation_stage=stage,
            counterfactual_replay=False,
        ),
        timeout=max(0.05, timeout_seconds),
    )


def _remaining_seconds(started: float, limit: int) -> float:
    remaining = float(limit) - (time.monotonic() - started)
    if remaining <= 0:
        raise asyncio.TimeoutError
    return remaining


async def run_context_tool_experiment(
    *,
    mode: SystemEvalMode | str = SystemEvalMode.SCRIPTED,
    provider: LLMProvider | str | None = None,
    model: str | None = None,
    case_ids: Sequence[str] | None = None,
    max_cases: int = 4,
    trials_per_case: int | None = None,
    candidate_overlays: Sequence[ContextToolOverlay] | None = None,
    candidate_limit: int = 4,
    allow_live: bool = False,
    allow_context_tool_experiments: bool = False,
    max_wall_clock_seconds: int = MAX_WALL_CLOCK_SECONDS,
) -> ContextToolExperimentReport:
    """Run baseline, low-confidence elimination screens, and at most two full candidates.

    Only fixed public DEV inventories are loaded.  A context/tool candidate is
    evaluation-local and never edits production settings, tool metadata, or code.
    """
    mode = SystemEvalMode(mode)
    if active_prompt_overlay() is not None:
        raise ValueError("context/tool experiments cannot run inside an active prompt candidate overlay")
    started = time.monotonic()
    if not 1 <= max_wall_clock_seconds <= MAX_WALL_CLOCK_SECONDS:
        raise ValueError("wall-clock budget exceeds the fixed experiment ceiling")
    if mode == SystemEvalMode.LIVE:
        if not (allow_live and allow_context_tool_experiments and provider and model):
            raise ValueError("live context/tool optimization requires both explicit opt-ins and exact model identity")
        trials = 5 if trials_per_case is None else trials_per_case
        if not 1 <= trials <= MAX_TRIALS_PER_CASE:
            raise ValueError("live trial count exceeds the system evaluator limit")
        selected_provider = LLMProvider(provider)
    else:
        if provider is not None or model is not None or allow_live or allow_context_tool_experiments:
            raise ValueError("scripted context/tool evaluation is zero-key and rejects live credentials/flags")
        trials = 1 if trials_per_case is None else trials_per_case
        if trials != 1:
            raise ValueError("scripted context/tool evaluation uses one synthetic trial")
        selected_provider = None
    if not 1 <= candidate_limit <= MAX_CANDIDATES:
        raise ValueError("candidate limit exceeds the fixed experiment policy")
    selected = _select_public_cases(case_ids, max_cases)
    selected_ids = [case.case_id for case in selected]
    screen_ids: list[str] = []
    screen_groups: dict[str, list[str]] = {
        "TARGET_FAILURES": [], "VALIDATION": [], "SECURITY": [], "PRESERVE_REGRESSION": [],
    }
    run_id = uuid4().hex
    usage = {
        "work_units": 0,
        "workflow_runs": 0,
        "model_calls": 0,
        "baseline_evaluation_model_executions": 0,
        "candidate_evaluation_model_executions": 0,
        "baseline_workflows": 0,
        "candidate_screen_workflows": 0,
        "candidate_full_workflows": 0,
        "measured_input_tokens": "NOT_MEASURED",
        "measured_output_tokens": "NOT_MEASURED",
        "measured_cost_usd": "NOT_MEASURED",
        "baseline_measured_input_tokens": "NOT_MEASURED",
        "baseline_measured_output_tokens": "NOT_MEASURED",
        "baseline_measured_cost_usd": "NOT_MEASURED",
        "candidate_measured_input_tokens": "NOT_MEASURED",
        "candidate_measured_output_tokens": "NOT_MEASURED",
        "candidate_measured_cost_usd": "NOT_MEASURED",
        "estimated_context_tokens": 0,
        "tool_selection_probes": 0,
        "elapsed_wall_clock_seconds": 0.0,
        "model_call_reservation": 0,
        "cloud_call_ceiling": 0,
        "cloud_token_reservation_ceiling": 0,
        "retry_count": "NOT_MEASURED",
        "fallback_count": "NOT_MEASURED",
    }
    termination_reason = "COMPLETED"
    scripted_gate = "NOT_EXECUTED"
    baseline_manifests: list[ContextPresentationManifest] = []
    baseline_screen_manifests: list[ContextPresentationManifest] = []
    baseline_probes: list[ToolSelectionProbe] = []
    candidates: list[ContextToolCandidateResult] = []
    baseline_report: SystemEvaluationReport | None = None
    baseline_screen_report: SystemEvaluationReport | None = None
    baseline_reference_proxy = None
    evaluation_reports: list[SystemEvaluationReport] = []
    baseline_evaluation_reports: list[SystemEvaluationReport] = []
    candidate_evaluation_reports: list[SystemEvaluationReport] = []
    candidate_probes: list[ToolSelectionProbe] = []
    inventory = tuple(candidate_overlays or ())

    try:
        remaining = _remaining_seconds(started, max_wall_clock_seconds)
        baseline_report = await _run_full(
            mode=mode, provider=selected_provider, model=model,
            case_ids=selected_ids, trials=trials, overlay=None,
            allow_live=allow_live, manifests=baseline_manifests, timeout_seconds=remaining,
            stage="FULL_DEV",
        )
        usage["work_units"] += len(selected_ids) * trials
        usage["workflow_runs"] += 1
        baseline_calls = _metric_total(baseline_report, "model_calls")
        usage["model_calls"] += baseline_calls
        usage["baseline_evaluation_model_executions"] += baseline_calls
        usage["baseline_workflows"] += 1
        usage["estimated_context_tokens"] += sum(item.estimated_input_tokens for item in baseline_manifests)
        baseline_reference_proxy = context_evidence_reference_proxy(baseline_report, baseline_manifests)
        evaluation_reports.append(baseline_report)
        baseline_evaluation_reports.append(baseline_report)
        screen_ids, screen_groups = _screen_selection(selected, baseline_report)
        if candidate_overlays is None:
            inventory = default_experiment_candidates(
                run_id=run_id,
                baseline=baseline_report,
                limit=candidate_limit,
            )
        if len(inventory) > candidate_limit or len(inventory) > MAX_CANDIDATES:
            raise ValueError("candidate inventory exceeds fixed limits")
        if len({item.candidate_id for item in inventory}) != len(inventory):
            raise ValueError("candidate inventory contains duplicate identities")
        for item in inventory:
            validate_overlay_identity(
                item,
                system_digest=baseline_report.system_identity.system_digest,
                tool_manifest_digest=baseline_report.system_identity.tool_manifest_digest,
            )

        baseline_screen_report = await _run_full(
            mode=mode, provider=selected_provider, model=model,
            case_ids=screen_ids, trials=1, overlay=None,
            allow_live=allow_live, manifests=baseline_screen_manifests,
            timeout_seconds=_remaining_seconds(started, max_wall_clock_seconds),
            stage="SCREEN",
        )
        usage["work_units"] += len(screen_ids)
        usage["workflow_runs"] += 1
        baseline_screen_calls = _metric_total(baseline_screen_report, "model_calls")
        usage["model_calls"] += baseline_screen_calls
        usage["baseline_evaluation_model_executions"] += baseline_screen_calls
        usage["baseline_workflows"] += 1
        usage["estimated_context_tokens"] += sum(item.estimated_input_tokens for item in baseline_screen_manifests)
        evaluation_reports.append(baseline_screen_report)
        baseline_evaluation_reports.append(baseline_screen_report)

        if not baseline_probes:
            baseline_probes = await asyncio.wait_for(
                run_tool_selection_micro_eval(
                    mode=mode,
                    provider=selected_provider,
                    model=model,
                    allow_live=allow_live,
                    allow_context_tool_experiments=allow_context_tool_experiments,
                    manifest_sink=lambda item: _append_manifest(baseline_manifests, item),
                ),
                timeout=_remaining_seconds(started, max_wall_clock_seconds),
            )
            usage["tool_selection_probes"] += len(baseline_probes)
            usage["work_units"] += len(baseline_probes)
            baseline_probe_calls = len(baseline_probes) if mode == SystemEvalMode.LIVE else 0
            usage["model_calls"] += baseline_probe_calls
            usage["baseline_evaluation_model_executions"] += baseline_probe_calls
            usage["estimated_context_tokens"] += sum(
                item.estimated_input_tokens for item in baseline_manifests
                if item.evaluation_stage == "MICRO_EVAL"
            )

        full_candidate_count = 0
        security_gate_ran = False
        for candidate in inventory:
            if time.monotonic() - started >= max_wall_clock_seconds:
                termination_reason = "OPTIMIZATION_BUDGET_EXHAUSTED"
                break
            work_remaining = TOTAL_WORK_UNIT_LIMIT - int(usage["work_units"])
            if work_remaining < len(screen_ids) + 16:
                termination_reason = "OPTIMIZATION_BUDGET_EXHAUSTED"
                break
            candidate_manifests: list[ContextPresentationManifest] = []
            screen_report = await _run_full(
                mode=mode, provider=selected_provider, model=model,
                case_ids=screen_ids, trials=1, overlay=candidate,
                allow_live=allow_live, manifests=candidate_manifests,
                timeout_seconds=_remaining_seconds(started, max_wall_clock_seconds),
                stage="SCREEN",
            )
            usage["work_units"] += len(screen_ids)
            usage["workflow_runs"] += 1
            screen_calls = _metric_total(screen_report, "model_calls")
            usage["model_calls"] += screen_calls
            usage["candidate_evaluation_model_executions"] += screen_calls
            usage["candidate_screen_workflows"] += 1
            usage["estimated_context_tokens"] += sum(item.estimated_input_tokens for item in candidate_manifests)
            evaluation_reports.append(screen_report)
            candidate_evaluation_reports.append(screen_report)
            probes = await asyncio.wait_for(
                run_tool_selection_micro_eval(
                    mode=mode,
                    overlay=candidate,
                    provider=selected_provider,
                    model=model,
                    allow_live=allow_live,
                    allow_context_tool_experiments=allow_context_tool_experiments,
                    manifest_sink=lambda item: _append_manifest(candidate_manifests, item),
                ),
                timeout=_remaining_seconds(started, max_wall_clock_seconds),
            )
            usage["tool_selection_probes"] += len(probes)
            usage["work_units"] += len(probes)
            candidate_probe_calls = len(probes) if mode == SystemEvalMode.LIVE else 0
            usage["model_calls"] += candidate_probe_calls
            usage["candidate_evaluation_model_executions"] += candidate_probe_calls
            candidate_probes.extend(probes)
            usage["estimated_context_tokens"] += sum(
                item.estimated_input_tokens for item in candidate_manifests
                if item.evaluation_stage == "MICRO_EVAL"
            )
            target_was_presented = any(
                manifest.component == candidate.target_component
                and manifest.overlay_digest == candidate.overlay_digest
                and manifest.evaluation_stage in {"SCREEN", "MICRO_EVAL"}
                for manifest in candidate_manifests
            )
            screen_issues = compute_screen_regressions(
                baseline_screen_report,
                screen_report,
                target_was_presented=target_was_presented,
            )
            screen_passed = not screen_issues

            evaluated = screen_report
            stage = "SCREEN_ONLY"
            security_gate = "NOT_EXECUTED"
            statistical_comparison = None
            ablation_class = ContextAblationClass.INCONCLUSIVE
            recommendation = ContextToolRecommendation.INCONCLUSIVE
            deltas = {}
            explanation = "One-trial deterministic screen is elimination evidence only; it is not promotion evidence."

            may_full_evaluate = (
                mode == SystemEvalMode.LIVE
                and screen_passed
                and full_candidate_count < MAX_FULL_CANDIDATES
            )
            if may_full_evaluate:
                full_units = len(selected_ids) * trials
                if usage["work_units"] + full_units + 30 > TOTAL_WORK_UNIT_LIMIT:
                    termination_reason = "OPTIMIZATION_BUDGET_EXHAUSTED"
                    # Preserve the completed screen as a diagnostic artifact.
                    may_full_evaluate = False
                else:
                    evaluated = await _run_full(
                        mode=mode, provider=selected_provider, model=model,
                        case_ids=selected_ids, trials=trials, overlay=candidate,
                        allow_live=allow_live, manifests=candidate_manifests,
                        timeout_seconds=_remaining_seconds(started, max_wall_clock_seconds),
                        stage="FULL_DEV",
                    )
                    usage["work_units"] += full_units
                    usage["workflow_runs"] += 1
                    full_calls = _metric_total(evaluated, "model_calls")
                    usage["model_calls"] += full_calls
                    usage["candidate_evaluation_model_executions"] += full_calls
                    usage["candidate_full_workflows"] += 1
                    usage["estimated_context_tokens"] += sum(
                        item.estimated_input_tokens for item in candidate_manifests
                        if item.evaluation_stage == "FULL_DEV"
                    )
                    evaluation_reports.append(evaluated)
                    candidate_evaluation_reports.append(evaluated)
                    stage = "FULL_DEV"
                    full_candidate_count += 1
                    security_report = await asyncio.wait_for(
                        run_agent_security_evaluation(
                            mode=AgentSecurityMode.SCRIPTED,
                            context_tool_overlay=candidate,
                        ),
                        timeout=_remaining_seconds(started, max_wall_clock_seconds),
                    )
                    security_gate = security_report.gate.value
                    scripted_gate = security_gate
                    security_gate_ran = True
                    usage["work_units"] += 30
                    complete_dev = set(evaluated.evaluated_case_ids) == set(PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS)
                    from app.evaluation.system.comparison import compare_system_reports

                    statistical_comparison = compare_system_reports(baseline_report, evaluated)
                    ablation_class, recommendation, deltas, explanation = compare_experiment(
                        baseline_report,
                        evaluated,
                        baseline_manifests=baseline_manifests,
                        candidate_manifests=candidate_manifests,
                        complete_dev=complete_dev,
                        repeated_trials=trials >= 3,
                        security_gate=security_gate,
                        scripted=False,
                        statistical_outcome=statistical_comparison.outcome.value,
                        statistical_valid=statistical_comparison.valid,
                    )
                    target_full_presented = any(
                        manifest.component == candidate.target_component
                        and manifest.overlay_digest == candidate.overlay_digest
                        and manifest.evaluation_stage == "FULL_DEV"
                        for manifest in candidate_manifests
                    )
                    if (
                        not target_full_presented
                        and recommendation != ContextToolRecommendation.SAFETY_BLOCKED
                    ):
                        ablation_class = ContextAblationClass.INCONCLUSIVE
                        recommendation = ContextToolRecommendation.INCONCLUSIVE
                        explanation = "The target presentation was absent from actual full-DEV model requests."
            elif screen_issues:
                ablation_class, recommendation, explanation = classify_screen(screen_issues)

            candidates.append(ContextToolCandidateResult(
                candidate_id=candidate.candidate_id,
                overlay=candidate,
                evaluation_report=evaluated,
                screen_report=screen_report,
                evaluation_stage=stage,
                screen_report_digest=screen_report.report_digest,
                screen_case_ids=screen_ids,
                screen_passed=screen_passed,
                presentation_manifests=candidate_manifests,
                tool_selection_probes=probes,
                evidence_reference_proxy=context_evidence_reference_proxy(evaluated, candidate_manifests),
                statistical_comparison=(
                    statistical_comparison.model_dump(mode="json")
                    if statistical_comparison is not None else None
                ),
                ablation_class=ablation_class,
                recommendation=recommendation,
                scripted_security_gate=security_gate,
                efficiency_deltas=deltas,
                explanation=explanation,
            ))
            if termination_reason == "OPTIMIZATION_BUDGET_EXHAUSTED":
                break

        # Scripted evaluation always reports security-gate status explicitly.
        if mode == SystemEvalMode.SCRIPTED:
            first = next((item for item in candidates if item.candidate_id), None)
            if first is not None:
                security_report = await asyncio.wait_for(
                    run_agent_security_evaluation(
                        mode=AgentSecurityMode.SCRIPTED,
                        context_tool_overlay=first.overlay,
                    ),
                    timeout=_remaining_seconds(started, max_wall_clock_seconds),
                )
                scripted_gate = "PASS" if security_report.gate.value == "PASS" else "FAIL"
                update = {"scripted_security_gate": scripted_gate}
                if scripted_gate != "PASS":
                    update.update({
                        "recommendation": ContextToolRecommendation.SAFETY_BLOCKED,
                        "ablation_class": ContextAblationClass.ESSENTIAL_UNDER_TEST,
                        "explanation": "The candidate failed the scripted agent-security boundary gate.",
                    })
                candidates[0] = candidates[0].model_copy(update=update)
                security_gate_ran = True
                usage["work_units"] += 30
        else:
            scripted_gate = "NOT_EXECUTED"
    except asyncio.TimeoutError:
        termination_reason = "OPTIMIZATION_BUDGET_EXHAUSTED"
    except (ValueError, RuntimeError):
        termination_reason = "INVALID_EXPERIMENT"
        if baseline_report is None:
            raise
    except Exception:
        termination_reason = "PROVIDER_FAILURE" if mode == SystemEvalMode.LIVE else "HARNESS_FAILURE"
        if baseline_report is None:
            raise

    if baseline_report is None or baseline_screen_report is None:
        raise RuntimeError("context/tool run ended before a valid public baseline could be produced")
    usage["elapsed_wall_clock_seconds"] = round(time.monotonic() - started, 3)
    if usage["elapsed_wall_clock_seconds"] > max_wall_clock_seconds:
        termination_reason = "OPTIMIZATION_BUDGET_EXHAUSTED"
    if int(usage["work_units"]) > TOTAL_WORK_UNIT_LIMIT:
        termination_reason = "OPTIMIZATION_BUDGET_EXHAUSTED"
    usage["case_trial_work_units"] = int(usage["work_units"])
    usage["case_trial_work_unit_ceiling"] = TOTAL_WORK_UNIT_LIMIT
    usage["candidate_inventory_count"] = len(inventory)
    reservation = int(usage["work_units"]) * MAX_MODEL_CALLS_PER_WORK_UNIT
    if reservation > MAX_TOTAL_MODEL_CALL_RESERVATION:
        termination_reason = "OPTIMIZATION_BUDGET_EXHAUSTED"
    usage["model_call_reservation"] = reservation
    max_calls_per_workflow = baseline_report.system_identity.budget_profile.max_workflow_cloud_calls
    max_tokens_per_workflow = baseline_report.system_identity.budget_profile.max_workflow_cloud_tokens
    usage["cloud_call_ceiling"] = int(usage["work_units"]) * max_calls_per_workflow
    usage["cloud_token_reservation_ceiling"] = int(usage["work_units"]) * max_tokens_per_workflow
    if mode == SystemEvalMode.SCRIPTED:
        # Provider token use is not meaningful in scripted mode, including zero.
        usage["measured_input_tokens"] = "NOT_MEASURED"
        usage["measured_output_tokens"] = "NOT_MEASURED"
        usage["measured_cost_usd"] = "NOT_MEASURED"
    else:
        all_candidate_probes = candidate_probes
        live_probes = baseline_probes + all_candidate_probes
        for report_key, usage_key, probe_key in (
            ("input_tokens", "measured_input_tokens", "measured_input_tokens"),
            ("output_tokens", "measured_output_tokens", "measured_output_tokens"),
            ("cost_usd", "measured_cost_usd", "measured_cost_usd"),
        ):
            workflow_total = _measured_sum(evaluation_reports, report_key)
            probe_total = _probe_measured_sum(live_probes, probe_key)
            usage[usage_key] = (
                workflow_total + probe_total
                if workflow_total is not None and probe_total is not None
                else "NOT_MEASURED"
            )
        retry_total = _measured_sum(evaluation_reports, "retry_count")
        probe_retries = _probe_measured_sum(live_probes, "retries")
        usage["retry_count"] = retry_total + probe_retries if retry_total is not None and probe_retries is not None else "NOT_MEASURED"
        fallback_total = _measured_sum(evaluation_reports, "fallback_count")
        probe_fallbacks = _probe_measured_sum(live_probes, "fallbacks")
        usage["fallback_count"] = fallback_total + probe_fallbacks if fallback_total is not None and probe_fallbacks is not None else "NOT_MEASURED"
        for scope, reports, probes in (
            ("baseline", baseline_evaluation_reports, baseline_probes),
            ("candidate", candidate_evaluation_reports, all_candidate_probes),
        ):
            for report_key, usage_key, probe_key in (
                ("input_tokens", f"{scope}_measured_input_tokens", "measured_input_tokens"),
                ("output_tokens", f"{scope}_measured_output_tokens", "measured_output_tokens"),
                ("cost_usd", f"{scope}_measured_cost_usd", "measured_cost_usd"),
            ):
                workflow_total = _measured_sum(reports, report_key)
                probe_total = _probe_measured_sum(probes, probe_key)
                usage[usage_key] = (
                    workflow_total + probe_total
                    if workflow_total is not None and probe_total is not None
                    else "NOT_MEASURED"
                )
    from app.evaluation.context_tool.pareto import pareto_frontier

    probe_dataset = load_agent_dataset()

    report = build_experiment_report(
        run_id=run_id,
        mode=mode.value,
        experiment_policy_version=POLICY_VERSION,
        termination_reason=termination_reason,
        resource_usage=usage,
        dataset_version=baseline_report.dataset_version,
        dataset_digest=baseline_report.dataset_hash,
        baseline_report=baseline_report,
        baseline_screen_report=baseline_screen_report,
        tool_probe_dataset_version=probe_dataset.manifest.dataset_version,
        tool_probe_dataset_digest=probe_dataset.dataset_hash,
        baseline_evidence_reference_proxy=baseline_reference_proxy,
        baseline_screen_manifests=baseline_screen_manifests,
        screen_selection_policy_version=SCREEN_SELECTION_VERSION,
        pareto_policy_version=PARETO_POLICY_VERSION,
        quality_comparison_policy_version=QUALITY_COMPARISON_POLICY_VERSION,
        screen_case_ids=screen_ids,
        screen_groups=screen_groups,
        screen_selection_digest=canonical_digest({
            "policy_version": SCREEN_SELECTION_VERSION,
            "groups": screen_groups,
            "case_ids": screen_ids,
        }),
        baseline_manifests=baseline_manifests,
        baseline_tool_selection_probes=baseline_probes,
        candidates=candidates,
        pareto_candidate_ids=pareto_frontier(candidates),
        scripted_security_gate=scripted_gate,
        live_security_gate="NOT_EXECUTED",
        report_digest="0" * 64,
    )
    return report


__all__ = [
    "MAX_PRESENTATION_MANIFESTS", "SCREEN_CASE_LIMIT", "TOTAL_WORK_UNIT_LIMIT",
    "default_experiment_candidates", "run_context_tool_experiment",
]
