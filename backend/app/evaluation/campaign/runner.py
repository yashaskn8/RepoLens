"""Staged, sequential campaign execution over RepoLens' canonical evaluator."""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.core.config import get_settings
from app.evaluation.campaign.contracts import (
    CampaignExecutionStatus,
    CampaignStage,
    CampaignStageReport,
    CampaignTrialUnit,
    CampaignUnitResult,
    CampaignUnitStatus,
    ModelEvaluationCampaignPlan,
    build_digested_model,
    canonical_digest,
    utc_now,
)
from app.evaluation.campaign.schedule import build_stage_schedule
from app.evaluation.system.full_analysis import run_full_analysis_evaluation
from app.evaluation.system.schemas import SystemEvalMode, SystemEvalSuite
from app.evaluation.ground_truth.public_dev import load_public_dev_repository_cases
from app.llm.types import LLMProvider
from app.llm.router import get_llm_router


MAX_UNIT_TIMEOUT_SECONDS = 120
LIVE_OPT_IN_REQUIRED = "live campaign execution requires --allow-live and --allow-model-campaign"


def campaign_artifact_root() -> Path:
    return Path(__file__).resolve().parents[3] / "evaluation_artifacts" / "model_campaigns"


def _private_path(path: Path) -> bool:
    return any("private" in part.casefold() or "holdout" in part.casefold() for part in path.parts)


def _safe_campaign_directory(campaign_id: str) -> Path:
    if len(campaign_id) != 32 or any(char not in "0123456789abcdef" for char in campaign_id):
        raise ValueError("campaign ID is invalid")
    lexical_root = campaign_artifact_root()
    backend_root = Path(__file__).resolve().parents[3]
    if lexical_root.is_symlink():
        raise ValueError("campaign artifact root cannot be a symlink")
    current = backend_root
    for part in ("evaluation_artifacts",):
        current = current / part
        if current.is_symlink():
            raise ValueError("campaign artifact root cannot contain symlinks")
    root = lexical_root.resolve()
    if not root.is_relative_to(backend_root):
        raise ValueError("campaign artifact root escapes the backend directory")
    if _private_path(root):
        raise ValueError("campaign artifact path cannot be under a private or holdout directory")
    directory = (root / campaign_id).resolve(strict=False)
    if not directory.is_relative_to(root) or _private_path(directory):
        raise ValueError("campaign artifact path escapes the dedicated campaign area")
    existing = root
    for part in directory.relative_to(root).parts:
        existing = existing / part
        if existing.is_symlink():
            raise ValueError("campaign artifact directory cannot contain symlinks")
    return directory


def save_plan(plan: ModelEvaluationCampaignPlan) -> Path:
    directory = _safe_campaign_directory(plan.campaign_id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "plan.json"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(plan.model_dump_json(indent=2) + "\n")
    return path


def load_plan(campaign_id: str) -> ModelEvaluationCampaignPlan:
    path = _safe_campaign_directory(campaign_id) / "plan.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("frozen campaign plan is missing")
    try:
        plan = ModelEvaluationCampaignPlan.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"frozen campaign plan is invalid: {type(exc).__name__}") from exc
    if plan.campaign_id != campaign_id:
        raise ValueError("campaign plan identity does not match its artifact path")
    return plan


def load_stage_report(campaign_id: str, stage: CampaignStage | str) -> CampaignStageReport:
    stage = CampaignStage(stage)
    path = _safe_campaign_directory(campaign_id) / f"{stage.value.casefold()}.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"campaign {stage.value} report is missing")
    try:
        report = CampaignStageReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"campaign stage report is invalid: {type(exc).__name__}") from exc
    if report.campaign_id != campaign_id or report.stage != stage:
        raise ValueError("campaign stage report identity does not match its artifact path")
    return report


def _git_state() -> tuple[str, bool]:
    import subprocess

    repository = Path(__file__).resolve().parents[4]
    safe = f"safe.directory={repository.as_posix()}"
    head = subprocess.run(
        ["git", "-c", safe, "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout.strip().lower()
    dirty = bool(subprocess.run(
        ["git", "-c", safe, "status", "--porcelain", "--untracked-files=all"],
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout.strip())
    return head, dirty


def _assert_frozen_source(plan: ModelEvaluationCampaignPlan) -> None:
    head, dirty = _git_state()
    if head != plan.source_revision:
        raise ValueError("campaign source commit differs from the frozen plan")
    if dirty:
        raise ValueError("campaign execution requires a clean worktree matching the frozen source commit")


def _configured_without_disclosure(provider: LLMProvider) -> bool:
    adapter = get_llm_router().get_adapter(provider)
    settings = get_settings()
    if provider == LLMProvider.CLOUDFLARE:
        return bool(getattr(adapter, "api_token", "") and getattr(adapter, "account_id", ""))
    if provider == LLMProvider.OLLAMA:
        # No network probe is made during preflight; runtime availability remains unmeasured.
        return bool(settings.LOCAL_LLM_ENABLED)
    return bool(getattr(adapter, "api_key", ""))


def _validate_live_permissions(
    stage: CampaignStage,
    *,
    allow_live: bool,
    allow_model_campaign: bool,
    allow_full_campaign: bool,
) -> None:
    if not (allow_live and allow_model_campaign):
        raise ValueError(LIVE_OPT_IN_REQUIRED)
    if stage == CampaignStage.LIVE_FULL and not allow_full_campaign:
        raise ValueError("full evaluation additionally requires --allow-full-campaign")


def _validate_prior_stage(
    plan: ModelEvaluationCampaignPlan,
    stage: CampaignStage,
    prior_report: CampaignStageReport | None,
    selected_candidate_ids: list[str] | None,
) -> list[str] | None:
    if stage == CampaignStage.LIVE_SMOKE:
        if prior_report is not None or selected_candidate_ids is not None:
            raise ValueError("smoke is the first stage and does not accept a prior report or selected arms")
        return None
    expected_previous = CampaignStage.LIVE_SMOKE if stage == CampaignStage.LIVE_PILOT else CampaignStage.LIVE_PILOT
    if prior_report is None:
        raise ValueError(f"{stage.value} requires its completed {expected_previous.value} report")
    if (
        prior_report.campaign_id != plan.campaign_id
        or prior_report.plan_digest != plan.plan_digest
        or prior_report.source_revision != plan.source_revision
        or prior_report.stage != expected_previous
        or prior_report.mode != "LIVE"
        or prior_report.execution_status != CampaignExecutionStatus.COMPLETED
    ):
        raise ValueError("prior stage report is invalid, incomplete, or belongs to another frozen campaign")
    eligible = set(prior_report.full_stage_eligible_candidate_ids)
    if selected_candidate_ids is None or not selected_candidate_ids:
        raise ValueError("stage candidates must be explicitly selected from the prior-stage eligible set")
    if len(selected_candidate_ids) != len(set(selected_candidate_ids)) or not set(selected_candidate_ids) <= eligible:
        raise ValueError("selected candidate is unknown or was not eligible from the prior stage")
    baseline = plan.baseline_candidate_id
    selected = [baseline, *(item for item in selected_candidate_ids if item != baseline)]
    if stage == CampaignStage.LIVE_FULL and len(selected) != 2:
        raise ValueError("full evaluation requires the baseline plus exactly one human-selected model finalist")
    if len(selected) > plan.stage_policy.max_candidate_arms:
        raise ValueError("selected candidate set exceeds the frozen policy")
    return selected


def _unit_path(plan: ModelEvaluationCampaignPlan, stage: CampaignStage, unit: CampaignTrialUnit) -> Path:
    directory = _safe_campaign_directory(plan.campaign_id) / stage.value.casefold() / "units"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{unit.unit_key}.json"
    if path.is_symlink():
        raise ValueError("campaign unit artifact cannot be a symlink")
    return path


def _make_unit_result(
    plan: ModelEvaluationCampaignPlan,
    stage: CampaignStage,
    unit: CampaignTrialUnit,
    status: CampaignUnitStatus,
    started_at: datetime,
    *,
    report=None,
    observed_model_pairs: list[str] | None = None,
    failure_code: str | None = None,
) -> CampaignUnitResult:
    completed_at = None if status == CampaignUnitStatus.NOT_EXECUTED else utc_now()
    duration = max(0.0, (completed_at - started_at).total_seconds()) if completed_at else 0.0
    payload: dict[str, Any] = {
        "plan_digest": plan.plan_digest,
        "stage": stage.value,
        "unit": unit.model_dump(mode="json"),
        "status": status.value,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat() if completed_at else None,
        "duration_seconds": min(MAX_UNIT_TIMEOUT_SECONDS, duration),
        "report": report.model_dump(mode="json") if report is not None else None,
        "observed_model_pairs": sorted(set(observed_model_pairs or [])),
        "provider_returned_revision": None,
        "revision_status": "NOT_MEASURED",
        "safe_failure_code": failure_code,
    }
    return build_digested_model(CampaignUnitResult, payload, "result_digest")


def _load_or_run_unit(
    plan: ModelEvaluationCampaignPlan,
    stage: CampaignStage,
    unit: CampaignTrialUnit,
) -> CampaignUnitResult | None:
    path = _unit_path(plan, stage, unit)
    if not path.exists():
        return None
    try:
        result = CampaignUnitResult.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"existing campaign unit artifact is corrupt: {type(exc).__name__}") from exc
    if result.plan_digest != plan.plan_digest or result.stage != stage or result.unit.unit_key != unit.unit_key:
        raise ValueError("existing unit artifact does not match its canonical scheduled unit")
    return result


def _persist_unit(plan: ModelEvaluationCampaignPlan, stage: CampaignStage, result: CampaignUnitResult) -> None:
    path = _unit_path(plan, stage, result.unit)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(result.model_dump_json(indent=2) + "\n")


async def _execute_unit(
    plan: ModelEvaluationCampaignPlan,
    stage: CampaignStage,
    unit: CampaignTrialUnit,
    timeout_seconds: float,
) -> CampaignUnitResult:
    candidate = next(item for item in plan.candidate_arms if item.candidate_id == unit.candidate_id)
    started_at = utc_now()
    bounded_timeout = min(MAX_UNIT_TIMEOUT_SECONDS, timeout_seconds)
    if bounded_timeout <= 0:
        return _make_unit_result(
            plan, stage, unit, CampaignUnitStatus.NOT_EXECUTED, started_at,
            failure_code="STAGE_WALL_CLOCK_LIMIT",
        )
    try:
        report = await asyncio.wait_for(
            run_full_analysis_evaluation(
                suite=SystemEvalSuite.ALL,
                mode=SystemEvalMode.LIVE,
                provider=candidate.provider,
                model=candidate.requested_model,
                trials_per_case=1,
                max_cases=1,
                case_ids=[unit.case_id],
                allow_live=True,
                counterfactual_replay=False,
            ),
            timeout=bounded_timeout,
        )
    except asyncio.TimeoutError:
        return _make_unit_result(
            plan, stage, unit, CampaignUnitStatus.HARNESS_FAILURE, started_at,
            failure_code="UNIT_TIMEOUT",
        )
    except Exception as exc:
        # The evaluator retains detailed diagnostics in its own safe trace.
        # Campaign artifacts store only a bounded exception type, never its text.
        failure = "PROVIDER_FAILURE" if type(exc).__name__ in {
            "LLMAuthenticationError", "LLMProviderUnavailableError", "LLMQuotaExhaustedError",
            "LLMRateLimitError", "LLMTimeoutError", "LLMAllFallbacksFailedError",
        } else "EVALUATOR_EXCEPTION_" + type(exc).__name__[:40]
        status = CampaignUnitStatus.PROVIDER_FAILURE if failure == "PROVIDER_FAILURE" else CampaignUnitStatus.HARNESS_FAILURE
        return _make_unit_result(plan, stage, unit, status, started_at, failure_code=failure)

    expected_pair = f"{candidate.provider.value.lower()}:{candidate.requested_model}"
    actual_pairs: set[str] = set()
    for case in report.case_results:
        for trial in case.trials:
            if trial.provider is not None and trial.model:
                actual_pairs.add(f"{trial.provider.value.lower()}:{trial.model}")
    identity = report.system_identity
    identity_valid = (
        report.scope == "FULL_ANALYSIS_GRAPH"
        and report.system_identity.compatibility_digest == plan.system_compatibility_digest
        and report.system_identity.system_digest == candidate.system_identity_digest
        and report.system_identity.model_provider == candidate.provider.value
        and report.system_identity.model_identifier == candidate.requested_model
        and report.system_identity.graph_identity_digest == plan.graph_identity_digest
        and report.system_identity.evaluation_contract_hash == plan.evaluation_contract_hash
        and report.system_identity.tool_manifest_digest == plan.tool_manifest_digest
        and report.system_identity.context_policy_digest == plan.context_policy_digest
        and canonical_digest([item.model_dump(mode="json") for item in identity.prompt_components])
        == plan.prompt_inventory_digest
    )
    if report.metrics.provider_failures > 0:
        status, failure = CampaignUnitStatus.PROVIDER_FAILURE, "PROVIDER_FAILURE"
    elif not identity_valid or actual_pairs != {expected_pair}:
        status, failure = CampaignUnitStatus.IDENTITY_INVALID, "PINNED_MODEL_IDENTITY_MISMATCH"
    elif report.metrics.budget_exhaustions > 0:
        status, failure = CampaignUnitStatus.BUDGET_EXHAUSTED, "WORKFLOW_BUDGET_EXHAUSTED"
    elif report.metrics.harness_failures > 0:
        status, failure = CampaignUnitStatus.HARNESS_FAILURE, "EVALUATION_HARNESS_FAILURE"
    else:
        status, failure = CampaignUnitStatus.COMPLETED, None
    return _make_unit_result(
        plan, stage, unit, status, started_at, report=report,
        observed_model_pairs=sorted(actual_pairs), failure_code=failure,
    )


def _existing_units(plan: ModelEvaluationCampaignPlan) -> list[CampaignUnitResult]:
    collected: list[CampaignUnitResult] = []
    for stage in (CampaignStage.LIVE_SMOKE, CampaignStage.LIVE_PILOT, CampaignStage.LIVE_FULL):
        directory = _safe_campaign_directory(plan.campaign_id) / stage.value.casefold() / "units"
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("campaign unit artifact directory is invalid")
        paths = sorted(directory.glob("*.json"))
        if len(paths) > plan.stage_policy.max_total_full_analysis_work_units:
            raise ValueError("campaign unit artifacts exceed the frozen total work-unit ceiling")
        for path in paths:
            if path.is_symlink() or not path.is_file():
                raise ValueError("campaign unit artifacts cannot be symlinks or non-files")
            try:
                result = CampaignUnitResult.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValidationError, ValueError) as exc:
                raise ValueError(f"existing campaign unit artifact is corrupt: {type(exc).__name__}") from exc
            if (
                result.plan_digest != plan.plan_digest
                or result.stage != stage
                or path.stem != result.unit.unit_key
            ):
                raise ValueError("existing campaign unit artifact has invalid plan, stage, or key binding")
            collected.append(result)
    return collected


async def run_live_stage(
    plan: ModelEvaluationCampaignPlan,
    stage: CampaignStage | str,
    *,
    allow_live: bool = False,
    allow_model_campaign: bool = False,
    allow_full_campaign: bool = False,
    prior_report: CampaignStageReport | None = None,
    candidate_ids: list[str] | None = None,
) -> CampaignStageReport:
    """Run one bounded, explicitly authorized live campaign stage.

    Every unit is one fresh production-graph run. Completed immutable unit
    artifacts are reused on resume; the evaluator supplies the isolated
    fixture, checkpointer, no-cache route, model budget, and grading.
    """
    stage = CampaignStage(stage)
    _validate_live_permissions(
        stage,
        allow_live=allow_live,
        allow_model_campaign=allow_model_campaign,
        allow_full_campaign=allow_full_campaign,
    )
    if stage not in {CampaignStage.LIVE_SMOKE, CampaignStage.LIVE_PILOT, CampaignStage.LIVE_FULL}:
        raise ValueError("security/context-tool evaluation is a separate, independently opted-in gate")
    _assert_frozen_source(plan)
    selected_ids = _validate_prior_stage(plan, stage, prior_report, candidate_ids)
    schedule = build_stage_schedule(plan, stage, candidate_ids=selected_ids)
    campaign_age = max(0.0, (utc_now() - plan.created_at).total_seconds())
    if campaign_age >= plan.stage_policy.max_total_wall_clock_seconds:
        raise ValueError("campaign-wide wall-clock budget is exhausted from the frozen plan start")
    existing_report_path = _safe_campaign_directory(plan.campaign_id) / f"{stage.value.casefold()}.json"
    if existing_report_path.exists():
        existing = load_stage_report(plan.campaign_id, stage)
        if (
            existing.plan_digest != plan.plan_digest
            or [item.model_dump(mode="json") for item in existing.schedule]
            != [item.model_dump(mode="json") for item in schedule]
        ):
            raise ValueError("existing immutable stage report does not match the requested frozen stage")
        return existing
    if stage == CampaignStage.LIVE_FULL and len(schedule) > plan.stage_policy.max_full_work_units:
        raise ValueError("full schedule exceeds the frozen 350-unit total ceiling")
    previous_units = _existing_units(plan)
    current_stage_units = [item for item in previous_units if item.stage == stage]
    other_stage_units = [item for item in previous_units if item.stage != stage]
    existing_keys = {item.unit.unit_key for item in current_stage_units}
    missing_units = sum(item.unit_key not in existing_keys for item in schedule)
    if len(previous_units) + missing_units > plan.stage_policy.max_total_full_analysis_work_units:
        raise ValueError("planned work would exceed the campaign-wide hard work-unit ceiling")
    previous_elapsed = sum(item.duration_seconds for item in other_stage_units)
    current_elapsed = sum(item.duration_seconds for item in current_stage_units)
    if max(campaign_age, previous_elapsed + current_elapsed) >= plan.stage_policy.max_total_wall_clock_seconds:
        raise ValueError("campaign-wide wall-clock budget is exhausted before this stage")

    missing_candidate_ids = sorted({
        item.candidate_id for item in schedule if item.unit_key not in existing_keys
    })
    for candidate_id in missing_candidate_ids:
        candidate = next(item for item in plan.candidate_arms if item.candidate_id == candidate_id)
        if not _configured_without_disclosure(candidate.provider):
            raise ValueError(f"candidate {candidate_id} credentials are not configured; no provider call was attempted")

    started_at = utc_now()
    monotonic_start = time.monotonic()
    results: list[CampaignUnitResult] = []
    stage_timeout = plan.stage_policy.max_wall_clock_seconds
    for unit in schedule:
        previous = _load_or_run_unit(plan, stage, unit)
        if previous is not None:
            results.append(previous)
            continue
        elapsed = time.monotonic() - monotonic_start
        remaining_stage = stage_timeout - current_elapsed - elapsed
        remaining_total = plan.stage_policy.max_total_wall_clock_seconds - campaign_age - elapsed
        if remaining_stage <= 0 or remaining_total <= 0:
            result = _make_unit_result(
                plan, stage, unit, CampaignUnitStatus.NOT_EXECUTED, utc_now(),
                failure_code="STAGE_WALL_CLOCK_LIMIT",
            )
        else:
            result = await _execute_unit(plan, stage, unit, min(remaining_stage, remaining_total))
            _persist_unit(plan, stage, result)
        results.append(result)

    from app.evaluation.campaign.analysis import summarize_stage

    summaries, comparisons, eligible = summarize_stage(plan, stage, schedule, results)
    completed = all(item.status != CampaignUnitStatus.NOT_EXECUTED for item in results)
    payload = {
        "campaign_id": plan.campaign_id,
        "plan_digest": plan.plan_digest,
        "source_revision": plan.source_revision,
        "stage": stage.value,
        "mode": "LIVE",
        "semantics": "PINNED_SINGLE_MODEL_CAMPAIGN",
        "execution_status": CampaignExecutionStatus.COMPLETED.value if completed else CampaignExecutionStatus.PARTIAL.value,
        "started_at": started_at.isoformat(),
        "completed_at": utc_now().isoformat(),
        "schedule_policy_version": plan.stage_policy.schedule_policy_version,
        "schedule": [item.model_dump(mode="json") for item in schedule],
        "schedule_digest": canonical_digest([item.model_dump(mode="json") for item in schedule]),
        "unit_results": [item.model_dump(mode="json") for item in results],
        "candidate_summaries": [item.model_dump(mode="json") for item in summaries],
        "pairwise_comparisons": [item.model_dump(mode="json") for item in comparisons],
        "full_stage_eligible_candidate_ids": eligible,
        "resource_usage": {
            "scheduled_work_units": len(schedule),
            "attempted_work_units": sum(item.status != CampaignUnitStatus.NOT_EXECUTED for item in results),
            "total_full_analysis_work_units": len(previous_units) + missing_units,
            "completed_workflows": sum(item.report is not None for item in results),
            "candidate_evaluation_model_calls": sum(
                item.report.metrics.model_calls for item in results if item.report is not None
            ),
            "candidate_evaluation_input_tokens": _aggregate_report_usage(results, "input_tokens"),
            "candidate_evaluation_output_tokens": _aggregate_report_usage(results, "output_tokens"),
            "candidate_evaluation_cost_usd": _aggregate_report_usage(results, "cost_usd"),
            "elapsed_wall_clock_seconds": round(time.monotonic() - monotonic_start, 3),
            "total_campaign_elapsed_seconds": round(max(
                (utc_now() - plan.created_at).total_seconds(),
                previous_elapsed + current_elapsed + (time.monotonic() - monotonic_start),
            ), 3),
            "cache_policy": "DISABLED",
            "fallback_policy": "EXACT_CANDIDATE_ONLY_NO_CROSS_MODEL_FALLBACK",
        },
        "review_status": "NOT_REVIEWED",
    }
    report = build_digested_model(CampaignStageReport, payload, "report_digest")
    output = _safe_campaign_directory(plan.campaign_id) / f"{stage.value.casefold()}.json"
    if output.exists() or output.is_symlink():
        raise ValueError("stage report already exists; refusing to overwrite immutable campaign artifact")
    if report.execution_status == CampaignExecutionStatus.COMPLETED:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(report.model_dump_json(indent=2) + "\n")
    return report


def _aggregate_report_usage(results: list[CampaignUnitResult], metric_name: str) -> int | float | str:
    reports = [item.report for item in results if item.report is not None]
    values = [getattr(report.metrics, metric_name) for report in reports]
    if not values or any(item.status.value != "MEASURED" or item.value is None for item in values):
        return "NOT_MEASURED"
    return sum(float(item.value) for item in values)


__all__ = ["campaign_artifact_root", "load_plan", "load_stage_report", "run_live_stage", "save_plan"]
