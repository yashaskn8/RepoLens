"""Zero-key integrity and scheduling tests for live model campaigns."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.evaluation.campaign.analysis import build_analysis_report
from app.evaluation.campaign.cli import _parse_arm
from app.evaluation.campaign.contracts import (
    CampaignCandidate,
    CampaignCandidateStatus,
    CampaignStage,
    CampaignStageReport,
    CampaignSupplementalGateReport,
    CampaignCandidateSummary,
    CampaignExecutionStatus,
    CampaignStagePolicy,
    CampaignUnitStatus,
    ModelEvaluationCampaignPlan,
    ModelStability,
    SupplementalGateKind,
    SupplementalGateStatus,
    UsageMetric,
    build_digested_model,
    canonical_digest,
    utc_now,
)
from app.evaluation.campaign.runner import (
    _load_or_run_unit,
    _make_unit_result,
    _persist_unit,
    _safe_campaign_directory,
    _validate_live_permissions,
    _validate_prior_stage,
)
from app.evaluation.campaign.smoke_paths import (
    SMOKE_MODEL_PATH_MANIFEST,
    SmokeModelPathManifest,
)
from app.evaluation.campaign.schedule import build_stage_schedule, select_smoke_case_ids
from app.evaluation.ground_truth.loader import compute_canonical_benchmark_hash
from app.evaluation.ground_truth.public_dev import load_public_dev_repository_cases
from app.llm.types import LLMProvider


def _with_digest(model_type, payload: dict, field: str):
    return build_digested_model(model_type, payload, field)


def _candidate(candidate_id: str, provider: LLMProvider, model: str, identity_char: str) -> CampaignCandidate:
    payload = {
        "candidate_id": candidate_id,
        "provider": provider.value,
        "requested_model": model,
        "registry_status": "REGISTERED_ENABLED",
        "structured_output_declared": True,
        "context_window_tokens": 100_000,
        "max_output_tokens": 8_000,
        "declared_capabilities": ["repository_analysis", "code_reasoning", "security_reasoning", "verification"],
        "declared_capability_gaps": [],
        "model_revision": None,
        "model_stability": ModelStability.UNKNOWN_STABILITY.value,
        "role": "PINNED_MODEL",
        "system_identity_digest": identity_char * 64,
        "compatibility_digest": "c" * 64,
    }
    return CampaignCandidate(**payload, candidate_digest=canonical_digest(payload))


def _plan() -> ModelEvaluationCampaignPlan:
    cases = load_public_dev_repository_cases()
    arms = [
        _candidate("baseline", LLMProvider.GEMINI, "gemini-exact", "a"),
        _candidate("candidate-a", LLMProvider.GROQ, "groq-exact", "b"),
        _candidate("candidate-b", LLMProvider.MISTRAL, "mistral-exact", "d"),
    ]
    created_at = utc_now()
    payload = {
        "schema_version": "live-model-campaign-plan/1.1",
        "campaign_id": "f" * 32,
        "created_at": created_at,
        "source_revision": "1" * 40,
        "dataset_version": "public-dev-v1",
        "dataset_digest": compute_canonical_benchmark_hash(cases),
        "case_ids": sorted(case.case_id for case in cases),
        "graph_identity_digest": "2" * 64,
        "evaluation_contract_hash": "3" * 64,
        "prompt_inventory_digest": "4" * 64,
        "tool_manifest_digest": "5" * 64,
        "context_policy_digest": "6" * 64,
        "system_compatibility_digest": "c" * 64,
        "candidate_arms": arms,
        "baseline_candidate_id": "baseline",
        "schedule_seed": 17,
        "stage_policy": CampaignStagePolicy(),
    }
    return _with_digest(ModelEvaluationCampaignPlan, payload, "plan_digest")


def _summary(candidate_id: str) -> CampaignCandidateSummary:
    unknown = lambda unit: UsageMetric(status="NOT_MEASURED", value=None, unit=unit)
    return CampaignCandidateSummary(
        candidate_id=candidate_id,
        status=CampaignCandidateStatus.INCONCLUSIVE,
        planned_units=0,
        completed_units=0,
        successful_trials=0,
        failed_trials=0,
        provider_failures=0,
        harness_failures=0,
        identity_failures=0,
        hard_safety_violations=0,
        unsupported_confirmations=0,
        task_success_rate=unknown("proportion"),
        precision=unknown("proportion"),
        recall=unknown("proportion"),
        f1=unknown("proportion"),
        input_tokens=unknown("tokens"),
        output_tokens=unknown("tokens"),
        measured_cost_usd=unknown("USD"),
        mean_latency_ms=unknown("ms/trial"),
        tool_calls=0,
        model_calls=0,
        fallback_count=unknown("calls"),
        retry_count=unknown("calls"),
        model_stability=ModelStability.UNKNOWN_STABILITY,
        metric_scope="LIVE_PINNED_MODEL",
    )


def _empty_stage(plan, stage: CampaignStage, summaries=()) -> CampaignStageReport:
    payload = {
        "campaign_id": plan.campaign_id,
        "plan_digest": plan.plan_digest,
        "source_revision": plan.source_revision,
        "stage": stage,
        "mode": "LIVE",
        "semantics": "PINNED_SINGLE_MODEL_CAMPAIGN",
        "execution_status": CampaignExecutionStatus.COMPLETED,
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "schedule": [],
        "schedule_digest": canonical_digest([]),
        "unit_results": [],
        "candidate_summaries": list(summaries),
        "pairwise_comparisons": [],
        "full_stage_eligible_candidate_ids": [],
        "resource_usage": {},
        "review_status": "NOT_REVIEWED",
    }
    return _with_digest(CampaignStageReport, payload, "report_digest")


def test_plan_digest_binds_creation_time_and_rejects_timestamp_edit() -> None:
    plan = _plan()
    edited = plan.model_dump(mode="json")
    edited["created_at"] = (plan.created_at - timedelta(days=3)).isoformat()
    with pytest.raises(ValidationError, match="plan digest mismatch"):
        ModelEvaluationCampaignPlan.model_validate(edited)


def test_campaign_arm_parser_preserves_colons_inside_model_name() -> None:
    assert _parse_arm("model-b=ollama:namespace:model:tag") == (
        "model-b", LLMProvider.OLLAMA, "namespace:model:tag",
    )


def test_deterministic_campaign_stage_schedules_are_bounded_and_paired() -> None:
    plan = _plan()
    with pytest.raises(ValueError, match="security case.*expected live model path"):
        select_smoke_case_ids(plan)
    with pytest.raises(ValueError, match="security case.*expected live model path"):
        build_stage_schedule(plan, CampaignStage.LIVE_SMOKE)

    selected = ["baseline", "candidate-a"]
    pilot = build_stage_schedule(plan, CampaignStage.LIVE_PILOT, candidate_ids=selected)
    assert len(pilot) == 8 * 2 * 2
    assert pilot == build_stage_schedule(plan, CampaignStage.LIVE_PILOT, candidate_ids=selected)
    for case_id in {unit.case_id for unit in pilot}:
        for trial in (1, 2):
            assert {
                unit.candidate_id for unit in pilot
                if unit.case_id == case_id and unit.trial_number == trial
            } == set(selected)

    full = build_stage_schedule(
        plan, CampaignStage.LIVE_FULL, candidate_ids=["baseline", "candidate-b"],
    )
    assert len(full) == 35 * 5 * 2 == 350
    assert max(unit.ordinal for unit in full) <= plan.stage_policy.max_full_work_units


def test_smoke_selector_uses_only_reviewed_model_paths_and_never_passes_them_to_runtime(monkeypatch) -> None:
    from app.evaluation.campaign import schedule
    from app.evaluation.ground_truth.leakage import LeakageDetector

    plan = _plan()
    cases = load_public_dev_repository_cases()
    correctness = next(item for item in cases if item.case_id == "BUG-EXCEPT-01A")
    security = next(item for item in cases if item.category.value == "SECURITY")
    assert [(entry.case_id, entry.expected_model_nodes) for entry in SMOKE_MODEL_PATH_MANIFEST.entries] == [
        ("BUG-EXCEPT-01A", ("bug",)),
    ]
    assert all(entry.category != "SECURITY" for entry in SMOKE_MODEL_PATH_MANIFEST.entries)

    payload = {
        "version": SMOKE_MODEL_PATH_MANIFEST.version,
        "entries": [
            entry.model_dump(mode="json") for entry in SMOKE_MODEL_PATH_MANIFEST.entries
        ] + [{
            "case_id": security.case_id,
            "category": "SECURITY",
            "expected_model_nodes": ["security"],
        }],
    }
    qualified_manifest = SmokeModelPathManifest(**payload, digest=canonical_digest(payload))
    monkeypatch.setattr(schedule, "SMOKE_MODEL_PATH_MANIFEST", qualified_manifest)
    selected = schedule.select_smoke_case_ids(plan)
    assert selected == sorted([correctness.case_id, security.case_id])
    assert selected == schedule.select_smoke_case_ids(plan)
    units = schedule.build_stage_schedule(plan, CampaignStage.LIVE_SMOKE)
    assert len(units) == len(plan.candidate_arms) * 2
    assert {unit.case_id for unit in units} == set(selected)

    runtime_input = LeakageDetector.bifurcate_input(correctness)
    assert "expected_model_nodes" not in runtime_input.model_dump()


def test_smoke_selector_fails_closed_if_no_category_has_a_declared_model_path(monkeypatch) -> None:
    from app.evaluation.campaign import schedule

    plan = _plan()
    payload = {"version": SMOKE_MODEL_PATH_MANIFEST.version, "entries": []}
    empty_manifest = SmokeModelPathManifest(**payload, digest=canonical_digest(payload))
    monkeypatch.setattr(
        schedule,
        "SMOKE_MODEL_PATH_MANIFEST",
        empty_manifest,
    )
    with pytest.raises(ValueError, match="no correctness and security case.*expected live model path"):
        schedule.select_smoke_case_ids(plan)


def test_live_smoke_static_case_gate_runs_before_credentials_or_provider_calls(monkeypatch) -> None:
    from app.evaluation.campaign import runner

    monkeypatch.setattr(runner, "_assert_frozen_source", lambda _plan: None)
    monkeypatch.setattr(
        runner,
        "_configured_without_disclosure",
        lambda _provider: (_ for _ in ()).throw(AssertionError("case qualification must precede credentials")),
    )
    monkeypatch.setattr(
        runner,
        "run_full_analysis_evaluation",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("case qualification must precede evaluation")),
    )
    with pytest.raises(ValueError, match="no security case.*expected live model path"):
        asyncio.run(runner.run_live_stage(
            _plan(),
            CampaignStage.LIVE_SMOKE,
            allow_live=True,
            allow_model_campaign=True,
        ))


def test_prior_stage_selection_requires_human_choice_and_baseline_pair() -> None:
    plan = _plan()
    pilot = _empty_stage(plan, CampaignStage.LIVE_PILOT)
    payload = pilot.model_dump(exclude={"report_digest"})
    payload["full_stage_eligible_candidate_ids"] = ["candidate-a", "candidate-b"]
    pilot = _with_digest(CampaignStageReport, payload, "report_digest")
    assert _validate_prior_stage(plan, CampaignStage.LIVE_FULL, pilot, ["candidate-b"]) == [
        "baseline", "candidate-b",
    ]
    with pytest.raises(ValueError, match="exactly one"):
        _validate_prior_stage(plan, CampaignStage.LIVE_FULL, pilot, ["candidate-a", "candidate-b"])
    with pytest.raises(ValueError, match="explicitly selected"):
        _validate_prior_stage(plan, CampaignStage.LIVE_FULL, pilot, None)


def test_live_runner_requires_both_explicit_opt_ins_before_execution() -> None:
    with pytest.raises(ValueError, match="--allow-live and --allow-model-campaign"):
        _validate_live_permissions(
            CampaignStage.LIVE_SMOKE,
            allow_live=True,
            allow_model_campaign=False,
            allow_full_campaign=False,
        )
    with pytest.raises(ValueError, match="--allow-full-campaign"):
        _validate_live_permissions(
            CampaignStage.LIVE_FULL,
            allow_live=True,
            allow_model_campaign=True,
            allow_full_campaign=False,
        )


def test_live_stage_requires_opt_ins_before_git_or_credentials(monkeypatch) -> None:
    from app.evaluation.campaign import runner

    def must_not_run(*args, **kwargs):
        raise AssertionError("preflight boundary should stop before git/evaluator/provider access")

    monkeypatch.setattr(runner, "_assert_frozen_source", must_not_run)
    with pytest.raises(ValueError, match="--allow-live and --allow-model-campaign"):
        asyncio.run(runner.run_live_stage(_plan(), CampaignStage.LIVE_SMOKE))


def test_expired_unit_wall_clock_does_not_start_an_evaluation(monkeypatch) -> None:
    from app.evaluation.campaign import runner

    def must_not_run(*args, **kwargs):
        raise AssertionError("expired work must not invoke the evaluator")

    monkeypatch.setattr(runner, "run_full_analysis_evaluation", must_not_run)
    plan = _plan()
    from app.evaluation.campaign.contracts import CampaignTrialUnit

    unit = CampaignTrialUnit(
        ordinal=1,
        candidate_id="baseline",
        case_id="BUG-EXCEPT-01A",
        trial_number=1,
        unit_key=canonical_digest({
            "candidate_id": "baseline",
            "case_id": "BUG-EXCEPT-01A",
            "trial_number": 1,
        }),
    )
    result = asyncio.run(runner._execute_unit(plan, CampaignStage.LIVE_SMOKE, unit, 0.0))
    assert result.status == runner.CampaignUnitStatus.NOT_EXECUTED
    assert result.safe_failure_code == "STAGE_WALL_CLOCK_LIMIT"


def _classification_report(
    *,
    model_pairs=(),
    model_calls=0,
    provider_failures=0,
    budget_exhaustions=0,
    harness_failures=0,
    identity_updates=None,
):
    plan = _plan()
    plan_payload = plan.model_dump(mode="json", exclude={"plan_digest"})
    plan_payload["prompt_inventory_digest"] = canonical_digest([])
    plan = _with_digest(ModelEvaluationCampaignPlan, plan_payload, "plan_digest")
    candidate = next(item for item in plan.candidate_arms if item.candidate_id == "baseline")
    identity_values = {
        "compatibility_digest": plan.system_compatibility_digest,
        "system_digest": candidate.system_identity_digest,
        "model_provider": candidate.provider.value,
        "model_identifier": candidate.requested_model,
        "graph_identity_digest": plan.graph_identity_digest,
        "evaluation_contract_hash": plan.evaluation_contract_hash,
        "tool_manifest_digest": plan.tool_manifest_digest,
        "context_policy_digest": plan.context_policy_digest,
        "prompt_components": [],
    }
    identity_values.update(identity_updates or {})
    identity = SimpleNamespace(**identity_values)
    trials = [SimpleNamespace(provider=provider, model=model) for provider, model in model_pairs]
    report = SimpleNamespace(
        scope="FULL_ANALYSIS_GRAPH",
        system_identity=identity,
        metrics=SimpleNamespace(
            provider_failures=provider_failures,
            budget_exhaustions=budget_exhaustions,
            harness_failures=harness_failures,
            model_calls=model_calls,
        ),
        case_results=[SimpleNamespace(trials=trials)],
    )
    return plan, candidate, report


@pytest.mark.parametrize(
    ("updates", "expected_status", "expected_failure"),
    [
        ({"provider_failures": 1, "model_pairs": [(LLMProvider.GROQ, "wrong")]}, "PROVIDER_FAILURE", "PROVIDER_FAILURE"),
        ({"identity_updates": {"model_identifier": "wrong"}}, "IDENTITY_INVALID", "PINNED_MODEL_IDENTITY_MISMATCH"),
        ({"budget_exhaustions": 1}, "BUDGET_EXHAUSTED", "WORKFLOW_BUDGET_EXHAUSTED"),
        ({"harness_failures": 1}, "HARNESS_FAILURE", "EVALUATION_HARNESS_FAILURE"),
        ({}, "HARNESS_FAILURE", "MODEL_NOT_INVOKED"),
        ({"model_calls": 1}, "HARNESS_FAILURE", "MODEL_IDENTITY_UNVERIFIED"),
        ({"model_pairs": [(LLMProvider.GEMINI, "gemini-exact")]}, "HARNESS_FAILURE", "MODEL_EXECUTION_METRIC_MISMATCH"),
        ({"model_calls": 1, "model_pairs": [(LLMProvider.GROQ, "wrong")]}, "IDENTITY_INVALID", "PINNED_MODEL_IDENTITY_MISMATCH"),
        ({"model_calls": 1, "budget_exhaustions": 1, "model_pairs": [(LLMProvider.GROQ, "wrong")]}, "IDENTITY_INVALID", "PINNED_MODEL_IDENTITY_MISMATCH"),
        ({"model_calls": 2, "model_pairs": [(LLMProvider.GEMINI, "gemini-exact"), (LLMProvider.GROQ, "wrong")]}, "IDENTITY_INVALID", "PINNED_MODEL_IDENTITY_MISMATCH"),
        ({"model_calls": 1, "model_pairs": [(LLMProvider.GEMINI, "gemini-exact")]}, "COMPLETED", None),
    ],
)
def test_campaign_unit_classification_distinguishes_identity_budget_harness_and_missing_calls(
    updates, expected_status, expected_failure,
):
    from app.evaluation.campaign.runner import _classify_unit_report

    plan, candidate, report = _classification_report(**updates)
    status, failure, observed_pairs = _classify_unit_report(plan, candidate, report)
    assert status.value == expected_status
    assert failure == expected_failure
    assert observed_pairs == sorted({
        f"{provider.value.lower()}:{model}" for provider, model in updates.get("model_pairs", ())
    })


def test_model_not_invoked_classification_does_not_mask_frozen_system_identity_failure():
    from app.evaluation.campaign.runner import _classify_unit_report

    plan, candidate, report = _classification_report(
        identity_updates={"graph_identity_digest": "f" * 64},
    )
    status, failure, _ = _classify_unit_report(plan, candidate, report)
    assert status == CampaignUnitStatus.IDENTITY_INVALID
    assert failure == "PINNED_MODEL_IDENTITY_MISMATCH"


def test_exhausted_campaign_clock_blocks_supplemental_provider_calls(tmp_path, monkeypatch) -> None:
    from app.evaluation.campaign import supplemental

    plan = _plan()
    payload = plan.model_dump(mode="json", exclude={"plan_digest"})
    payload["created_at"] = (utc_now() - timedelta(days=3)).isoformat()
    expired_plan = _with_digest(ModelEvaluationCampaignPlan, payload, "plan_digest")
    full_report = SimpleNamespace(
        execution_status=CampaignExecutionStatus.COMPLETED,
        mode="LIVE",
        schedule=[
            SimpleNamespace(candidate_id="baseline"),
            SimpleNamespace(candidate_id="candidate-a"),
        ],
        resource_usage={},
    )

    monkeypatch.setattr(supplemental, "load_plan", lambda _: expired_plan)
    monkeypatch.setattr(supplemental, "_assert_frozen_source", lambda _: None)
    monkeypatch.setattr(supplemental, "load_stage_report", lambda *args: full_report)
    monkeypatch.setattr(supplemental, "_safe_campaign_directory", lambda _: tmp_path)
    monkeypatch.setattr(
        supplemental,
        "_configured_without_disclosure",
        lambda _: (_ for _ in ()).throw(AssertionError("expired budget must stop before provider readiness")),
    )
    with pytest.raises(ValueError, match="wall-clock budget is exhausted"):
        asyncio.run(supplemental.run_supplemental_gate(
            plan.campaign_id,
            SupplementalGateKind.SECURITY,
            allow_live=True,
            allow_model_campaign=True,
            allow_adversarial_security_eval=True,
        ))


def test_missing_supplemental_gates_never_yield_pareto_or_human_review() -> None:
    plan = _plan()
    smoke = _empty_stage(plan, CampaignStage.LIVE_SMOKE)
    pilot = _empty_stage(plan, CampaignStage.LIVE_PILOT)
    full = _empty_stage(plan, CampaignStage.LIVE_FULL, [_summary("baseline"), _summary("candidate-a")])
    analysis, samples = build_analysis_report(plan, smoke, pilot, full)
    assert samples == []
    assert analysis.security_gate_status == SupplementalGateStatus.INCONCLUSIVE
    assert analysis.context_tool_gate_status == SupplementalGateStatus.INCONCLUSIVE
    assert analysis.pareto_candidate_ids == []
    assert analysis.human_review_eligible_candidate_ids == []


def test_analysis_digest_catches_tampering_and_unknown_usage_stays_unknown() -> None:
    plan = _plan()
    smoke = _empty_stage(plan, CampaignStage.LIVE_SMOKE)
    pilot = _empty_stage(plan, CampaignStage.LIVE_PILOT)
    full = _empty_stage(plan, CampaignStage.LIVE_FULL, [_summary("baseline"), _summary("candidate-a")])
    analysis, _ = build_analysis_report(plan, smoke, pilot, full)
    tampered = analysis.model_dump(mode="json")
    tampered["security_gate_status"] = "PASS"
    with pytest.raises(ValidationError, match="digest mismatch|recommend"):
        type(analysis).model_validate(tampered)
    assert _summary("baseline").input_tokens.status == "NOT_MEASURED"
    assert _summary("baseline").input_tokens.value is None


def test_campaign_artifact_path_rejects_traversal_and_private_roots() -> None:
    with pytest.raises(ValueError, match="campaign ID"):
        _safe_campaign_directory("../private")


def test_campaign_artifact_root_symlink_is_rejected(tmp_path, monkeypatch) -> None:
    from pathlib import Path

    from app.evaluation.campaign import runner

    root = tmp_path / "model_campaigns"
    monkeypatch.setattr(runner, "campaign_artifact_root", lambda: root)
    original = Path.is_symlink

    def is_symlink(path: Path) -> bool:
        return path == root or original(path)

    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    with pytest.raises(ValueError, match="root cannot be a symlink"):
        runner._safe_campaign_directory("f" * 32)


def test_campaign_artifact_root_symlink_is_rejected(tmp_path, monkeypatch) -> None:
    from pathlib import Path

    from app.evaluation.campaign import runner

    root = tmp_path / "model_campaigns"
    monkeypatch.setattr(runner, "campaign_artifact_root", lambda: root)
    original = Path.is_symlink

    def is_symlink(path: Path) -> bool:
        return path == root or original(path)

    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    with pytest.raises(ValueError, match="root cannot be a symlink"):
        runner._safe_campaign_directory("f" * 32)


def test_completed_unit_artifact_is_reused_on_resume(tmp_path, monkeypatch) -> None:
    from app.evaluation.campaign import runner

    campaign_directory = tmp_path / "model_campaigns" / ("f" * 32)
    monkeypatch.setattr(runner, "_safe_campaign_directory", lambda campaign_id: campaign_directory)
    plan = _plan()
    from app.evaluation.campaign.contracts import CampaignTrialUnit

    unit = CampaignTrialUnit(
        ordinal=1,
        candidate_id="baseline",
        case_id="BUG-EXCEPT-01A",
        trial_number=1,
        unit_key=canonical_digest({
            "candidate_id": "baseline",
            "case_id": "BUG-EXCEPT-01A",
            "trial_number": 1,
        }),
    )
    result = _make_unit_result(
        plan,
        CampaignStage.LIVE_SMOKE,
        unit,
        runner.CampaignUnitStatus.PROVIDER_FAILURE,
        utc_now(),
        failure_code="PROVIDER_FAILURE",
    )
    _persist_unit(plan, CampaignStage.LIVE_SMOKE, result)
    resumed = _load_or_run_unit(plan, CampaignStage.LIVE_SMOKE, unit)
    assert resumed == result
    assert runner._existing_units(plan) == [result]


def test_complete_persisted_stage_resumes_without_provider_credentials(tmp_path, monkeypatch) -> None:
    from app.evaluation.campaign import runner

    plan = _plan()
    campaign_directory = tmp_path / "campaign"
    monkeypatch.setattr(runner, "_safe_campaign_directory", lambda _: campaign_directory)
    monkeypatch.setattr(runner, "_assert_frozen_source", lambda _: None)
    monkeypatch.setattr(
        runner,
        "_configured_without_disclosure",
        lambda _: (_ for _ in ()).throw(AssertionError("no new units means no credential check")),
    )
    from app.evaluation.campaign.contracts import CampaignTrialUnit

    schedule = [CampaignTrialUnit(
        ordinal=1,
        candidate_id="baseline",
        case_id="BUG-EXCEPT-01A",
        trial_number=1,
        unit_key=canonical_digest({
            "candidate_id": "baseline",
            "case_id": "BUG-EXCEPT-01A",
            "trial_number": 1,
        }),
    )]
    monkeypatch.setattr(runner, "build_stage_schedule", lambda *_args, **_kwargs: schedule)
    for unit in schedule:
        _persist_unit(plan, CampaignStage.LIVE_SMOKE, _make_unit_result(
            plan,
            CampaignStage.LIVE_SMOKE,
            unit,
            runner.CampaignUnitStatus.PROVIDER_FAILURE,
            utc_now(),
            failure_code="PROVIDER_FAILURE",
        ))

    report = asyncio.run(runner.run_live_stage(
        plan,
        CampaignStage.LIVE_SMOKE,
        allow_live=True,
        allow_model_campaign=True,
    ))
    assert report.execution_status == CampaignExecutionStatus.COMPLETED
    assert len(report.unit_results) == len(schedule)
    assert all(item.status == runner.CampaignUnitStatus.PROVIDER_FAILURE for item in report.unit_results)


def test_preflight_does_not_disclose_credentials_or_probe_runtime(monkeypatch) -> None:
    from app.evaluation.campaign import preflight
    from app.evaluation.campaign.plan import FULL_ANALYSIS_CAPABILITY_SET

    spec = SimpleNamespace(
        provider=LLMProvider.GEMINI,
        model="gemini-exact",
        enabled=True,
        supports_structured_output=True,
        context_window_tokens=100_000,
        max_output_tokens=8_000,
        model_revision=None,
        capabilities=FULL_ANALYSIS_CAPABILITY_SET,
    )
    registry = SimpleNamespace(get=lambda provider, model: spec if model == spec.model else None)
    router = SimpleNamespace(
        _capability_gateway=SimpleNamespace(registry=registry),
        get_adapter=lambda provider: SimpleNamespace(api_key="never-print-this-secret"),
    )
    monkeypatch.setattr(preflight, "get_llm_router", lambda: router)
    result = preflight.run_campaign_preflight([("base", LLMProvider.GEMINI, "gemini-exact")])
    serialized = result.model_dump_json()
    assert result.live_execution_performed is False
    assert result.candidate_readiness[0].status == "READY"
    assert result.candidate_readiness[0].local_runtime_reachability == "NOT_PROBED"
    assert "never-print-this-secret" not in serialized


def _run_preflight_with_spec(
    monkeypatch,
    spec,
    *,
    provider: LLMProvider = LLMProvider.GEMINI,
    adapter=None,
    adapter_error: bool = False,
):
    from app.evaluation.campaign import preflight

    class Adapter:
        api_key = "test-key-that-must-not-be-serialized"
        api_token = "test-token-that-must-not-be-serialized"
        account_id = "test-account"
        authorization_header = "Bearer test-header-that-must-not-be-serialized"

        def generate(self, *_args, **_kwargs):
            raise AssertionError("preflight must never call a provider")

        async def agenerate(self, *_args, **_kwargs):
            raise AssertionError("preflight must never call a provider")

    class Router:
        _capability_gateway = SimpleNamespace(
            registry=SimpleNamespace(
                get=lambda requested_provider, model: (
                    spec if requested_provider == provider and model == spec.model else None
                )
            )
        )

        @staticmethod
        def get_adapter(_provider):
            if adapter_error:
                raise ValueError("adapter unavailable")
            return adapter if adapter is not None else Adapter()

    monkeypatch.setattr(preflight, "get_llm_router", lambda: Router())
    monkeypatch.setattr(preflight, "get_settings", lambda: SimpleNamespace(LOCAL_LLM_ENABLED=True))
    return preflight.run_campaign_preflight([("candidate", provider, spec.model if spec else "exact-model")])


def _preflight_spec(**overrides):
    from app.evaluation.campaign.plan import FULL_ANALYSIS_CAPABILITY_SET

    values = {
        "provider": LLMProvider.GEMINI,
        "model": "exact-model",
        "enabled": True,
        "supports_structured_output": True,
        "context_window_tokens": 100_000,
        "max_output_tokens": 8_000,
        "model_revision": None,
        "capabilities": FULL_ANALYSIS_CAPABILITY_SET,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_preflight_reports_declared_capability_gaps_as_warnings(monkeypatch) -> None:
    from app.evaluation.campaign.plan import FULL_ANALYSIS_CAPABILITY_SET
    from app.llm.types import ModelCapability

    one_gap = _preflight_spec(capabilities=FULL_ANALYSIS_CAPABILITY_SET - {ModelCapability.SECURITY_REASONING})
    one_gap_result = _run_preflight_with_spec(monkeypatch, one_gap).candidate_readiness[0]
    assert one_gap_result.status == "READY_WITH_CAPABILITY_WARNINGS"
    assert one_gap_result.capability_gaps == ["SECURITY_REASONING"]

    multiple_gaps = _preflight_spec(capabilities=FULL_ANALYSIS_CAPABILITY_SET - {
        ModelCapability.SECURITY_REASONING,
        ModelCapability.VERIFICATION,
    })
    multiple_gap_result = _run_preflight_with_spec(monkeypatch, multiple_gaps).candidate_readiness[0]
    assert multiple_gap_result.status == "READY_WITH_CAPABILITY_WARNINGS"
    assert multiple_gap_result.capability_gaps == ["SECURITY_REASONING", "VERIFICATION"]
    assert multiple_gap_result.credential_configured is True
    assert multiple_gap_result.local_runtime_reachability == "NOT_PROBED"


@pytest.mark.parametrize(
    ("spec_overrides", "adapter_error", "adapter", "provider", "expected"),
    [
        ({"enabled": False}, False, None, LLMProvider.GEMINI, "DISABLED"),
        ({"supports_structured_output": False}, False, None, LLMProvider.GEMINI, "NO_STRUCTURED_OUTPUT"),
        ({"context_window_tokens": 100}, False, None, LLMProvider.GEMINI, "INSUFFICIENT_CONTEXT"),
        ({"max_output_tokens": 100}, False, None, LLMProvider.GEMINI, "INSUFFICIENT_CONTEXT"),
        ({"capabilities": frozenset()}, False, SimpleNamespace(api_key=""), LLMProvider.GEMINI, "NO_CREDENTIAL"),
        ({"capabilities": frozenset()}, True, None, LLMProvider.GEMINI, "NO_ADAPTER"),
        ({}, False, SimpleNamespace(api_token="configured-token", account_id=""), LLMProvider.CLOUDFLARE, "NO_CREDENTIAL"),
    ],
)
def test_preflight_keeps_technical_blockers_hard_and_precedes_warnings(
    monkeypatch, spec_overrides, adapter_error, adapter, provider, expected,
) -> None:
    spec = _preflight_spec(provider=provider, **spec_overrides)
    result = _run_preflight_with_spec(
        monkeypatch,
        spec,
        provider=provider,
        adapter=adapter,
        adapter_error=adapter_error,
    ).candidate_readiness[0]
    assert result.status == expected


def test_preflight_reports_unregistered_model_as_hard_blocker(monkeypatch) -> None:
    from app.evaluation.campaign import preflight

    router = SimpleNamespace(
        _capability_gateway=SimpleNamespace(registry=SimpleNamespace(get=lambda *_args: None)),
        get_adapter=lambda _provider: SimpleNamespace(api_key="unused"),
    )
    monkeypatch.setattr(preflight, "get_llm_router", lambda: router)
    result = preflight.run_campaign_preflight([("unknown", LLMProvider.GEMINI, "not-registered")])
    assert result.candidate_readiness[0].status == "NOT_REGISTERED"


def test_preflight_schema_is_versioned_and_preserves_warnings_without_secrets(monkeypatch) -> None:
    from app.evaluation.campaign import preflight
    from app.evaluation.campaign.plan import FULL_ANALYSIS_CAPABILITY_SET
    from app.llm.types import ModelCapability

    spec = _preflight_spec(capabilities=FULL_ANALYSIS_CAPABILITY_SET - {ModelCapability.SECURITY_REASONING})
    result = _run_preflight_with_spec(monkeypatch, spec)
    serialized = result.model_dump_json()
    assert result.schema_version == preflight.PREFLIGHT_SCHEMA_VERSION
    assert result.candidate_readiness[0].status == "READY_WITH_CAPABILITY_WARNINGS"
    assert result.candidate_readiness[0].capability_gaps == ["SECURITY_REASONING"]
    assert "test-key-that-must-not-be-serialized" not in serialized
    assert "test-token-that-must-not-be-serialized" not in serialized
    assert "test-header-that-must-not-be-serialized" not in serialized


def test_campaign_plan_accepts_warning_ready_candidate_and_preserves_declared_gaps(monkeypatch) -> None:
    from app.evaluation.campaign import plan as campaign_plan
    from app.evaluation.campaign.plan import FULL_ANALYSIS_CAPABILITY_SET
    from app.llm.types import ModelCapability

    gap_capabilities = FULL_ANALYSIS_CAPABILITY_SET - {ModelCapability.SECURITY_REASONING}
    specifications = {
        (LLMProvider.GEMINI, "gemini-exact"): _preflight_spec(
            provider=LLMProvider.GEMINI, model="gemini-exact", capabilities=gap_capabilities,
        ),
        (LLMProvider.GROQ, "groq-exact"): _preflight_spec(
            provider=LLMProvider.GROQ, model="groq-exact",
        ),
    }
    router = SimpleNamespace(
        _capability_gateway=SimpleNamespace(
            registry=SimpleNamespace(get=lambda provider, model: specifications.get((provider, model)))
        ),
        get_adapter=lambda _provider: object(),
    )

    class Fixture:
        def __init__(self, _case):
            self.registry = object()

        async def initialize_runtime(self):
            return None

        def close(self):
            return None

    identity = SimpleNamespace(
        system_digest="a" * 64,
        compatibility_digest="c" * 64,
        graph_identity_digest="2" * 64,
        evaluation_contract_hash="3" * 64,
        tool_manifest_digest="5" * 64,
        context_policy_digest="6" * 64,
        prompt_components=[],
    )
    cases = [SimpleNamespace(case_id=f"case-{index:02d}") for index in range(35)]
    monkeypatch.setattr(campaign_plan, "get_llm_router", lambda: router)
    monkeypatch.setattr(campaign_plan, "load_public_dev_repository_cases", lambda: cases)
    monkeypatch.setattr(campaign_plan, "compute_canonical_benchmark_hash", lambda _cases: "d" * 64)
    monkeypatch.setattr(campaign_plan, "FullAnalysisFixture", Fixture)
    monkeypatch.setattr(campaign_plan.LeakageDetector, "bifurcate_input", staticmethod(lambda case: case))
    monkeypatch.setattr(campaign_plan, "build_agent_system_identity", lambda **_kwargs: identity)
    monkeypatch.setattr(campaign_plan, "_git_head", lambda: "1" * 40)

    result = asyncio.run(campaign_plan.create_campaign_plan(
        [
            ("baseline", LLMProvider.GEMINI, "gemini-exact"),
            ("candidate", LLMProvider.GROQ, "groq-exact"),
        ],
        baseline_candidate_id="baseline",
    ))
    baseline = next(item for item in result.candidate_arms if item.candidate_id == "baseline")
    assert baseline.declared_capability_gaps == [ModelCapability.SECURITY_REASONING.value]


def test_supplemental_gate_report_digest_cannot_be_forged() -> None:
    from app.evaluation.campaign.contracts import SupplementalGateCandidate

    entries = [
        SupplementalGateCandidate(
            candidate_id=candidate_id,
            provider=provider,
            model=model,
            system_identity_digest=identity,
            report_digest="a" * 64,
            artifact_sha256="b" * 64,
            artifact_path=f"security/{candidate_id}.json",
            status=SupplementalGateStatus.PASS,
            metrics={"identity_valid": True},
        )
        for candidate_id, provider, model, identity in (
            ("baseline", LLMProvider.GEMINI, "gemini-exact", "c" * 64),
            ("candidate-a", LLMProvider.GROQ, "groq-exact", "d" * 64),
        )
    ]
    payload = {
        "campaign_id": "f" * 32,
        "plan_digest": "e" * 64,
        "source_revision": "1" * 40,
        "gate": SupplementalGateKind.SECURITY,
        "status": SupplementalGateStatus.PASS,
        "candidates": entries,
        "resource_usage": {"input_tokens": "NOT_MEASURED"},
        "evaluated_at": utc_now(),
    }
    report = _with_digest(CampaignSupplementalGateReport, payload, "report_digest")
    tampered = report.model_dump(mode="json")
    tampered["resource_usage"]["input_tokens"] = 0
    with pytest.raises(ValidationError, match="digest mismatch"):
        CampaignSupplementalGateReport.model_validate(tampered)
