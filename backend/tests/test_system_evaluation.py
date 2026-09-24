"""Deterministic contracts and red-team tests for agent system evaluation."""

from __future__ import annotations

import json

import pytest

from app.core.config import get_settings
from app.evaluation.agent.fixtures import build_fixture_runtime
from app.evaluation.agent.loader import load_agent_dataset
from app.evaluation.system.comparison import compare_system_reports, promote_check, wilson_interval
from app.evaluation.system.cli import build_parser, main as system_cli_main
from app.evaluation.system.identity import build_agent_system_identity
from app.evaluation.agent.runner import LiveTrialResult, run_scripted_trial
from app.evaluation.system.runner import _result_record, _suite_metrics, run_system_evaluation
from app.evaluation.system.schemas import (
    EvaluationRunStatus,
    MeasuredMetric,
    MetricStatus,
    PromotionOutcome,
    SystemCaseResults,
    SystemEvalMode,
    SystemEvalSuite,
    SystemEvaluationMetrics,
    SystemEvaluationReport,
    SystemTrialGrade,
    SystemTrialPolicy,
    TrialOutcome,
    system_evaluation_report_digest,
)
from app.llm.base import BaseLLMAdapter
from app.llm.capabilities import ModelCapabilityRegistry, ModelCapabilitySpec
from app.llm.economy import WorkflowCloudBudget, bind_workflow_cloud_budget, reset_workflow_cloud_budget
from app.llm.gateway import CapabilityAIGateway
from app.llm.router import LLMRouter
from app.llm.types import LLMProvider, LLMResponse, ModelCapability, ModelCostTier
from app.schemas.metadata import ModelExecutionMetadata


def _metric(value: float | None, unit: str) -> MeasuredMetric:
    return MeasuredMetric(
        status=MetricStatus.NOT_MEASURED if value is None else MetricStatus.MEASURED,
        value=value,
        unit=unit,
    )


def _live_report(dataset, identity, *, candidate_successes: int, violation: bool = False, trials: int = 5):
    cases = []
    success_index = 0
    all_trials = []
    for case in dataset.cases:
        case_trials = []
        for trial_number in range(1, trials + 1):
            success = success_index < candidate_successes
            success_index += 1
            unsafe = int(violation and case.case_id == dataset.cases[0].case_id and trial_number == 1)
            grade = SystemTrialGrade(
                case_id=case.case_id,
                trial_number=trial_number,
                outcome=TrialOutcome.SECURITY_VIOLATION if unsafe else TrialOutcome.SUCCESS if success else TrialOutcome.TASK_FAILED,
                task_success=success and not unsafe,
                stop_reason="EVIDENCE_GATHERED" if success else "INSUFFICIENT_EVIDENCE",
                evidence_valid=True,
                abstained=not success,
                tool_calls=1,
                model_calls=2,
                unsafe_tool_requests=0,
                unsafe_tool_executions=unsafe,
                invalid_tool_arguments=0,
                duplicate_tool_calls=0,
                provider=identity.model_provider,
                model=identity.model_identifier,
                latency_ms=_metric(100.0, "ms"),
                input_tokens=_metric(None, "tokens"),
                output_tokens=_metric(None, "tokens"),
                cost_usd=_metric(None, "USD"),
                fallback_count=None,
                retry_count=None,
                safety_violation_codes=["UNAUTHORIZED_TOOL_EXECUTED"] if unsafe else [],
            )
            case_trials.append(grade)
            all_trials.append(grade)
        cases.append(SystemCaseResults(
            case_id=case.case_id,
            category=case.category.lower(),
            split=case.split.value,
            trials=case_trials,
        ))
    count = len(all_trials)
    successes = sum(item.task_success is True for item in all_trials)
    metric_count = len(cases)
    metrics = SystemEvaluationMetrics(
        task_count=metric_count,
        trial_count=count,
        successful_trials=successes,
        failed_trials=count - successes,
        task_success_rate=_metric(successes / count, "proportion"),
        mean_per_case_success_rate=_metric(successes / count, "proportion"),
        all_trials_consistency_rate=_metric(1.0, "proportion"),
        required_evidence_trials=0,
        evidence_success_rate=_metric(None, "proportion"),
        correct_abstentions=0,
        correct_abstention_rate=_metric(None, "proportion"),
        false_abstentions=0,
        false_abstention_rate=_metric(0.0, "proportion"),
        unsafe_tool_requests=0,
        unsafe_tool_executions=sum(item.unsafe_tool_executions for item in all_trials),
        invalid_tool_arguments=0,
        duplicate_tool_calls=0,
        provider_failures=0,
        harness_failures=0,
        budget_exhaustions=0,
        context_budget_exhaustions=0,
        checkpoint_resumed_trials=0,
        checkpoint_duplicate_tool_calls=0,
        hard_safety_violations=sum(item.outcome == TrialOutcome.SECURITY_VIOLATION for item in all_trials),
        tool_calls=count,
        model_calls=count * 2,
        tool_calls_per_trial=_metric(1.0, "calls/trial"),
        model_calls_per_trial=_metric(2.0, "calls/trial"),
        tool_calls_per_successful_task=_metric(1.0, "calls/success"),
        model_calls_per_successful_task=_metric(2.0, "calls/success"),
        latency_ms_per_trial=_metric(100.0, "ms"),
        input_tokens=_metric(None, "tokens"),
        output_tokens=_metric(None, "tokens"),
        cost_usd=_metric(None, "USD"),
        fallback_count=_metric(None, "calls"),
        retry_count=_metric(None, "calls"),
        max_context_bytes=_metric(None, "bytes"),
        regression_failures=sum(
            item.task_success is not True
            for case_result in cases if case_result.split == "REGRESSION"
            for item in case_result.trials
        ),
        security_case_count=sum(case.category.lower() == "security" for case in dataset.cases),
    )
    report_data = {
        "schema_version": "agent-system-eval-report/1.0",
        "mode": "LIVE",
        "scope": "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH",
        "dataset_version": dataset.manifest.dataset_version,
        "dataset_hash": dataset.dataset_hash,
        "evaluation_contract_hash": identity.evaluation_contract_hash,
        "suite": "ALL",
        "expected_case_ids": [case.case_id for case in dataset.cases],
        "evaluated_case_ids": [case.case_id for case in dataset.cases],
        "trial_policy": {
            "trials_per_case": trials,
            "max_cases": 32,
            "concurrency": 1,
            "fresh_checkpoint_per_trial": True,
            "cache_policy": "DISABLED",
        },
        "execution_status": "COMPLETED",
        "system_identity": identity.model_dump(mode="json"),
        "case_results": [case.model_dump(mode="json") for case in cases],
        "suite_metrics": [item.model_dump(mode="json") for item in _suite_metrics(dataset.cases, cases)],
        "metrics": metrics.model_dump(mode="json"),
    }
    return SystemEvaluationReport.model_validate({
        **report_data,
        "report_digest": system_evaluation_report_digest(report_data),
    })


@pytest.fixture(scope="module")
def dataset():
    return load_agent_dataset()


def test_system_identity_is_stable_model_specific_and_policy_compatible(dataset):
    settings = get_settings()
    with build_fixture_runtime(dataset.cases[0]) as fixture:
        baseline = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
        repeated = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
        candidate = build_agent_system_identity(
            provider=LLMProvider.GROQ,
            model=settings.MODEL_SECURITY_REASONING,
            registry=fixture.registry,
        )
    assert baseline.system_digest == repeated.system_digest
    assert baseline.system_digest != candidate.system_digest
    assert baseline.compatibility_digest == candidate.compatibility_digest
    assert baseline.tool_manifest_count == 11
    assert baseline.fallback_policy == "EXACT_CANDIDATE_ONLY_NO_CROSS_MODEL_FALLBACK"


def test_system_evaluator_uses_production_graph_and_does_not_report_hidden_canary(dataset):
    case_id = "security-hostile-source"
    report = __import__("asyncio").run(run_system_evaluation(
        dataset=dataset,
        suite=SystemEvalSuite.SECURITY,
        mode=SystemEvalMode.SCRIPTED,
        trials_per_case=2,
        max_cases=1,
        case_ids=[case_id],
    ))
    serialized = json.dumps(report.model_dump(mode="json"), sort_keys=True)
    assert report.scope == "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH"
    assert report.execution_status == EvaluationRunStatus.PARTIAL
    assert report.evaluated_case_ids == [case_id]
    assert len(report.case_results[0].trials) == 2
    assert report.case_results[0].trials[0].provider is None
    assert report.metrics.input_tokens.status == MetricStatus.NOT_MEASURED
    assert report.metrics.cost_usd.status == MetricStatus.NOT_MEASURED
    selected_case = next(case for case in dataset.cases if case.case_id == case_id)
    assert selected_case.annotation.hidden_canary not in serialized


def test_live_trial_uses_production_graph_and_exact_mocked_router_candidate(dataset):
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    from app.evaluation.agent.runner import run_live_trial

    case = next(item for item in dataset.cases if item.category.upper() == "ARCHITECTURE")
    provider = LLMProvider.GEMINI
    model = "system-eval-exact-mock"
    adapter = MagicMock(spec=BaseLLMAdapter)
    adapter.generate = AsyncMock(return_value=LLMResponse(
        content='{"action":"FINISH","tool_name":null,"arguments":{},"reason":"Bounded evidence is ready for verification."}',
        provider=provider,
        model=model,
        metadata=ModelExecutionMetadata(
            model_name=model,
            provider=provider.value,
            prompt_tokens=120,
            completion_tokens=18,
            total_tokens=138,
        ),
    ))
    registry = ModelCapabilityRegistry((ModelCapabilitySpec(
        provider=provider,
        model=model,
        capabilities=frozenset(ModelCapability),
        cost_tier=ModelCostTier.CHEAP,
        quality_rank=1,
        context_window_tokens=32_768,
        max_output_tokens=4_096,
    ),))
    gateway = CapabilityAIGateway({provider: adapter}, registry=registry, max_retries=4)
    router = LLMRouter(adapters={provider: adapter}, capability_gateway=gateway)
    budget = WorkflowCloudBudget(mode="strict", max_cloud_calls=4, max_cloud_tokens=40_000)
    token = bind_workflow_cloud_budget(budget)
    try:
        trial = asyncio.run(run_live_trial(case, provider=provider, model=model, router=router))
    finally:
        reset_workflow_cloud_budget(token)

    assert trial.error is None
    assert trial.live_provider_used is True
    assert adapter.generate.await_count == 1
    executions = trial.final_state["model_executions"]
    assert len(executions) == 1
    assert executions[0].provider == provider.value
    assert executions[0].model_name == model
    assert trial.trajectory_steps[-1]["provider"] == provider.value
    assert trial.trajectory_steps[-1]["model"] == model


def test_scripted_system_evaluation_rejects_live_candidate_overrides(dataset):
    import asyncio

    with pytest.raises(ValueError, match="SCRIPTED evaluation does not accept"):
        asyncio.run(run_system_evaluation(
            dataset=dataset,
            suite=SystemEvalSuite.SECURITY,
            mode=SystemEvalMode.SCRIPTED,
            provider=LLMProvider.GEMINI,
            model="candidate-model",
            max_cases=1,
        ))


def test_system_runner_enforces_case_and_trial_ceiling(dataset):
    import asyncio

    with pytest.raises(ValueError, match="trials_per_case must be between 1 and 5"):
        asyncio.run(run_system_evaluation(dataset=dataset, trials_per_case=1_000_000))
    with pytest.raises(ValueError, match="max_cases must be between 1 and 32"):
        asyncio.run(run_system_evaluation(dataset=dataset, max_cases=33))


def test_system_cli_has_help_and_rejects_implicit_live_provider(capsys):
    with pytest.raises(SystemExit) as help_exit:
        build_parser().parse_args(["--help"])
    assert help_exit.value.code == 0
    assert system_cli_main([
        "run", "--mode", "live", "--provider", "gemini", "--model", "candidate-model",
    ]) == 2
    assert "explicit --allow-live" in capsys.readouterr().out


def test_prompt_identity_changes_system_digest_without_changing_compatibility(dataset, monkeypatch):
    import app.evaluation.system.identity as identity_module

    with build_fixture_runtime(dataset.cases[0]) as fixture:
        first = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=get_settings().MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
        original = identity_module.INVESTIGATOR_SYSTEM_PROMPT
        monkeypatch.setattr(identity_module, "INVESTIGATOR_SYSTEM_PROMPT", original + " Additional stable policy.")
        second = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=get_settings().MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
    assert first.system_digest != second.system_digest
    assert first.compatibility_digest == second.compatibility_digest
    assert first.evaluation_contract_hash == second.evaluation_contract_hash


def test_comparison_allows_only_explicitly_versioned_prompt_candidates(dataset, monkeypatch):
    import app.agent_runtime.context as context_module
    import app.agent_runtime.prompts as prompts_module
    import app.evaluation.system.identity as identity_module

    settings = get_settings()
    with build_fixture_runtime(dataset.cases[0]) as fixture:
        baseline_identity = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
        candidate_prompt = prompts_module.INVESTIGATOR_SYSTEM_PROMPT + " Candidate policy wording."
        monkeypatch.setattr(prompts_module, "INVESTIGATOR_SYSTEM_PROMPT", candidate_prompt)
        monkeypatch.setattr(context_module, "INVESTIGATOR_SYSTEM_PROMPT", candidate_prompt)
        monkeypatch.setattr(prompts_module, "INVESTIGATOR_PROMPT_VERSION", "evidence-investigator/1.1")
        monkeypatch.setattr(identity_module, "INVESTIGATOR_SYSTEM_PROMPT", candidate_prompt)
        monkeypatch.setattr(identity_module, "INVESTIGATOR_PROMPT_VERSION", "evidence-investigator/1.1")
        candidate_identity = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )

    baseline = _live_report(dataset, baseline_identity, candidate_successes=160)
    candidate = _live_report(dataset, candidate_identity, candidate_successes=160)
    comparison = compare_system_reports(baseline, candidate)
    assert comparison.valid is True
    assert baseline_identity.system_digest != candidate_identity.system_digest
    assert baseline_identity.compatibility_digest == candidate_identity.compatibility_digest
    assert baseline_identity.evaluation_contract_hash == candidate_identity.evaluation_contract_hash

    monkeypatch.setattr(prompts_module, "INVESTIGATOR_PROMPT_VERSION", "evidence-investigator/1.0")
    monkeypatch.setattr(identity_module, "INVESTIGATOR_PROMPT_VERSION", "evidence-investigator/1.0")
    unversioned_identity = build_agent_system_identity(
        provider=LLMProvider.GEMINI,
        model=settings.MODEL_ARCHITECTURE,
        registry=fixture.registry,
    )
    unversioned = _live_report(dataset, unversioned_identity, candidate_successes=160)
    rejected = compare_system_reports(baseline, unversioned)
    assert rejected.valid is False
    assert "prompt content changed without a version increment" in " ".join(rejected.reasons)


def test_wilson_uncertainty_does_not_call_a_small_difference_proven():
    baseline = wilson_interval(9, 10)
    candidate = wilson_interval(10, 10)
    assert baseline is not None and candidate is not None
    assert candidate[0] <= baseline[1]


def test_live_candidate_without_actual_provider_metadata_cannot_pass(dataset):
    import asyncio

    case = dataset.cases[0]
    scripted = asyncio.run(run_scripted_trial(case))
    state = dict(scripted.final_state)
    state["model_executions"] = []
    trial = LiveTrialResult(
        final_state=state,
        interrupted_state=None,
        tool_events=scripted.tool_events,
        model_requests=(),
        model_decisions_consumed=0,
        resumed=False,
        trajectory_steps=scripted.trajectory_steps,
        live_provider_used=False,
    )

    grade = _result_record(
        case,
        trial,
        trial_number=1,
        mode=SystemEvalMode.LIVE,
        selected_provider=LLMProvider.GEMINI,
        selected_model=get_settings().MODEL_ARCHITECTURE,
    )

    assert grade.outcome == TrialOutcome.HARNESS_FAILED
    assert grade.task_success is False
    assert "CANDIDATE_IDENTITY_UNVERIFIED" in grade.safety_violation_codes


def test_live_candidate_fallback_metadata_is_a_hard_safety_failure(dataset):
    import asyncio

    case = dataset.cases[0]
    scripted = asyncio.run(run_scripted_trial(case))
    state = dict(scripted.final_state)
    state["model_executions"] = [ModelExecutionMetadata(
        model_name="baseline-model",
        provider=LLMProvider.GROQ.value,
    )]
    trial = LiveTrialResult(
        final_state=state,
        interrupted_state=None,
        tool_events=scripted.tool_events,
        model_requests=(),
        model_decisions_consumed=1,
        resumed=False,
        trajectory_steps=scripted.trajectory_steps,
        live_provider_used=True,
    )

    grade = _result_record(
        case,
        trial,
        trial_number=1,
        mode=SystemEvalMode.LIVE,
        selected_provider=LLMProvider.GEMINI,
        selected_model=get_settings().MODEL_ARCHITECTURE,
    )

    assert grade.outcome == TrialOutcome.SECURITY_VIOLATION
    assert grade.task_success is False
    assert "CANDIDATE_IDENTITY_MISMATCH" in grade.safety_violation_codes


def test_live_report_cannot_call_a_fallback_model_successful(dataset):
    settings = get_settings()
    with build_fixture_runtime(dataset.cases[0]) as fixture:
        identity = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
    report = _live_report(dataset, identity, candidate_successes=160)
    cases = list(report.case_results)
    trials = list(cases[0].trials)
    trials[0] = trials[0].model_copy(update={
        "provider": LLMProvider.GROQ,
        "model": "baseline-model",
    })
    cases[0] = cases[0].model_copy(update={"trials": trials})
    payload = report.model_dump(mode="json", exclude={"report_digest"})
    payload["case_results"] = [item.model_dump(mode="json") for item in cases]
    with pytest.raises(ValueError, match="selected provider/model"):
        SystemEvaluationReport.model_validate({
            **payload,
            "report_digest": system_evaluation_report_digest(payload),
        })


def test_promotion_safety_block_cannot_be_offset_by_task_success(dataset):
    settings = get_settings()
    with build_fixture_runtime(dataset.cases[0]) as fixture:
        baseline_identity = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
        candidate_identity = build_agent_system_identity(
            provider=LLMProvider.GROQ,
            model=settings.MODEL_SECURITY_REASONING,
            registry=fixture.registry,
        )
    baseline = _live_report(dataset, baseline_identity, candidate_successes=160)
    candidate = _live_report(dataset, candidate_identity, candidate_successes=160, violation=True)
    decision = promote_check(baseline, candidate)
    assert decision.outcome == PromotionOutcome.SAFETY_BLOCKED
    assert decision.eligible_for_human_review is False
    assert decision.automatic_production_change is False


def test_promotion_requires_current_harness_identity(dataset, monkeypatch):
    settings = get_settings()
    with build_fixture_runtime(dataset.cases[0]) as fixture:
        baseline_identity = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
        candidate_identity = build_agent_system_identity(
            provider=LLMProvider.GROQ,
            model=settings.MODEL_SECURITY_REASONING,
            registry=fixture.registry,
        )
    baseline = _live_report(dataset, baseline_identity, candidate_successes=160)
    candidate = _live_report(dataset, candidate_identity, candidate_successes=160)

    import app.evaluation.system.identity as identity_module
    original_source_digest = identity_module._source_digest

    def changed_context_policy_digest(module_names):
        result = original_source_digest(module_names)
        if set(module_names) == {
            "app.agent_runtime.context", "app.agent_runtime.policy", "app.agent_runtime.progress",
        }:
            return identity_module._digest({"prior": result, "context_policy_revision": "changed"})
        return result

    monkeypatch.setattr(identity_module, "_source_digest", changed_context_policy_digest)
    decision = promote_check(baseline, candidate)
    assert decision.outcome == PromotionOutcome.INVALID_COMPARISON
    assert "stale or materially different" in " ".join(decision.reasons)


def test_promotion_refuses_a_forged_alternate_all_suite_corpus(dataset):
    settings = get_settings()
    with build_fixture_runtime(dataset.cases[0]) as fixture:
        baseline_identity = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
        candidate_identity = build_agent_system_identity(
            provider=LLMProvider.GROQ,
            model=settings.MODEL_SECURITY_REASONING,
            registry=fixture.registry,
        )
    baseline = _live_report(dataset, baseline_identity, candidate_successes=160)
    candidate = _live_report(dataset, candidate_identity, candidate_successes=160)

    def mutate_dataset(report):
        payload = report.model_dump(mode="json", exclude={"report_digest"})
        payload["dataset_hash"] = "0" * 64
        payload["dataset_version"] = "alternate-eval-v1"
        return SystemEvaluationReport.model_validate({
            **payload,
            "report_digest": system_evaluation_report_digest(payload),
        })

    decision = promote_check(mutate_dataset(baseline), mutate_dataset(candidate))
    assert decision.outcome == PromotionOutcome.INVALID_COMPARISON
    assert decision.eligible_for_human_review is False
    assert "pinned committed ALL-suite dataset" in " ".join(decision.reasons)


def test_comparison_rejects_incomplete_or_modified_reports(dataset):
    settings = get_settings()
    with build_fixture_runtime(dataset.cases[0]) as fixture:
        identity = build_agent_system_identity(
            provider=LLMProvider.GEMINI,
            model=settings.MODEL_ARCHITECTURE,
            registry=fixture.registry,
        )
    report = _live_report(dataset, identity, candidate_successes=160)
    mutated_results = list(report.case_results)
    mutated_results[0] = mutated_results[0].model_copy(update={"category": "poisoned"})
    tampered = report.model_copy(update={"case_results": mutated_results})
    comparison = compare_system_reports(report, tampered)
    assert comparison.valid is False
    assert comparison.outcome.value == "INVALID_COMPARISON"

    partial = report.model_copy(update={"execution_status": EvaluationRunStatus.PARTIAL})
    comparison = compare_system_reports(partial, report)
    assert comparison.valid is False
