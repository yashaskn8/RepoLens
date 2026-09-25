"""Deterministic stage selection and paired, interleaved trial scheduling."""

from __future__ import annotations

from hashlib import sha256

from app.evaluation.campaign.contracts import (
    CampaignStage,
    CampaignTrialUnit,
    ModelEvaluationCampaignPlan,
    canonical_digest,
)
from app.evaluation.campaign.smoke_paths import SMOKE_MODEL_PATH_MANIFEST
from app.evaluation.ground_truth.loader import compute_canonical_benchmark_hash
from app.evaluation.ground_truth.public_dev import load_public_dev_repository_cases


def _rank(seed: int, policy: str, value: str) -> str:
    return sha256(f"{policy}\0{seed}\0{value}".encode("utf-8")).hexdigest()


def _fixed_cases(plan: ModelEvaluationCampaignPlan):
    cases = load_public_dev_repository_cases()
    if sorted(case.case_id for case in cases) != plan.case_ids:
        raise ValueError("public DEV inventory differs from the frozen campaign plan")
    if compute_canonical_benchmark_hash(cases) != plan.dataset_digest:
        raise ValueError("public DEV dataset digest differs from the frozen campaign plan")
    return cases


def select_smoke_case_ids(plan: ModelEvaluationCampaignPlan) -> list[str]:
    """Select one statically model-exercising case per required smoke category.

    Execution-path expectations are versioned campaign metadata, separate
    from benchmark labels and runtime AnalysisInput. Refuse to spend live
    calls when either category lacks a qualified public DEV case.
    """
    cases = _fixed_cases(plan)
    by_group: dict[str, list[str]] = {"CORRECTNESS": [], "SECURITY": []}
    cases_by_id = {case.case_id: case for case in cases}
    for entry in SMOKE_MODEL_PATH_MANIFEST.entries:
        case = cases_by_id.get(entry.case_id)
        if case is None or str(case.category.value).upper() != entry.category:
            raise ValueError("smoke model-path manifest does not match the fixed public DEV inventory")
        by_group[entry.category].append(entry.case_id)
    missing = [group.lower() for group, choices in by_group.items() if not choices]
    if missing:
        joined = " and ".join(missing)
        raise ValueError(
            f"fixed public DEV corpus has no {joined} case with an expected live model path"
        )
    selected: list[str] = []
    for group in ("CORRECTNESS", "SECURITY"):
        choices = by_group[group]
        selected.append(min(choices, key=lambda item: _rank(
            plan.schedule_seed, "smoke/2.0/" + group, item,
        )))
    return sorted(selected)


def select_pilot_case_ids(plan: ModelEvaluationCampaignPlan) -> list[str]:
    """Select four correctness plus four security cases, falling back only if a
    category has fewer than four public cases (not true for the current DEV set).
    """
    cases = _fixed_cases(plan)
    by_group: dict[str, list[str]] = {"CORRECTNESS": [], "SECURITY": []}
    for case in cases:
        group = str(case.category.value).upper()
        if group in by_group:
            by_group[group].append(case.case_id)
    selected: list[str] = []
    for group in ("CORRECTNESS", "SECURITY"):
        ordered = sorted(
            by_group[group],
            key=lambda item: _rank(plan.schedule_seed, "pilot/1.0/" + group, item),
        )
        selected.extend(ordered[:4])
    if len(set(selected)) < plan.stage_policy.pilot_cases:
        remainder = sorted(
            set(plan.case_ids) - set(selected),
            key=lambda item: _rank(plan.schedule_seed, "pilot/fallback/1.0", item),
        )
        selected.extend(remainder[: plan.stage_policy.pilot_cases - len(set(selected))])
    if len(set(selected)) != plan.stage_policy.pilot_cases:
        raise ValueError("the fixed DEV inventory cannot satisfy the bounded pilot selection")
    return sorted(set(selected))


def build_stage_schedule(
    plan: ModelEvaluationCampaignPlan,
    stage: CampaignStage | str,
    *,
    candidate_ids: list[str] | None = None,
) -> list[CampaignTrialUnit]:
    stage = CampaignStage(stage)
    candidates = {item.candidate_id: item for item in plan.candidate_arms}
    if stage == CampaignStage.LIVE_SMOKE:
        selected_candidates = list(candidates)
        case_ids = select_smoke_case_ids(plan)
        trials = plan.stage_policy.smoke_trials_per_case
    elif stage == CampaignStage.LIVE_PILOT:
        selected_candidates = candidate_ids or []
        if not selected_candidates or len(selected_candidates) > plan.stage_policy.max_candidate_arms:
            raise ValueError("pilot requires one to four explicitly smoke-eligible candidate arms")
        case_ids = select_pilot_case_ids(plan)
        trials = plan.stage_policy.pilot_trials_per_case
    elif stage == CampaignStage.LIVE_FULL:
        selected_candidates = candidate_ids or []
        if not selected_candidates or len(selected_candidates) > plan.stage_policy.max_full_finalists:
            raise ValueError("full evaluation requires one or two explicitly pilot-eligible finalists")
        case_ids = plan.case_ids
        trials = plan.stage_policy.full_trials_per_case
    else:
        raise ValueError("schedule supports only the staged LIVE smoke, pilot, and full evaluations")
    if len(selected_candidates) != len(set(selected_candidates)) or not set(selected_candidates) <= set(candidates):
        raise ValueError("stage candidate selection contains an unknown or duplicate candidate")

    units: list[CampaignTrialUnit] = []
    for case_id in case_ids:
        for trial_number in range(1, trials + 1):
            paired = sorted(
                selected_candidates,
                key=lambda candidate_id: _rank(
                    plan.schedule_seed,
                    f"schedule/1.0/{stage.value}/{case_id}/{trial_number}",
                    candidate_id,
                ),
            )
            for candidate_id in paired:
                units.append(CampaignTrialUnit(
                    ordinal=len(units) + 1,
                    candidate_id=candidate_id,
                    case_id=case_id,
                    trial_number=trial_number,
                    unit_key=canonical_digest({
                        "candidate_id": candidate_id,
                        "case_id": case_id,
                        "trial_number": trial_number,
                    }),
                ))
    if len(units) > plan.stage_policy.max_full_work_units:
        raise ValueError("stage schedule exceeds the fixed full-campaign work-unit ceiling")
    return units


__all__ = ["build_stage_schedule", "select_pilot_case_ids", "select_smoke_case_ids"]
