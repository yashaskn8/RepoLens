"""No-key path qualification for naturally reachable production model nodes."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from pydantic import ValidationError

from app.evaluation.campaign.path_qualification import (
    ModelPathQualificationCase,
    ModelPathQualificationReport,
    _UnavailableCacheStore,
    _offline_router,
    _BoundaryRecorder,
    qualify_public_dev_model_paths,
)
from app.evaluation.campaign.contracts import canonical_digest
from app.evaluation.ground_truth.public_dev import (
    PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS,
    load_public_dev_repository_cases,
)
from app.evaluation.system.full_analysis import _execute_trial
from app.evaluation.system.schemas import SystemEvalMode
from app.evaluation.ground_truth.leakage import LeakageDetector
from app.evaluation.ground_truth.schemas import BenchmarkCategory
from app.llm.cache import AIResponseCache
from app.llm.types import LLMMessage, LLMRequest, ModelCapability, TaskPolicy


def test_offline_qualification_covers_fixed_dev_inventory_without_network(monkeypatch) -> None:
    calls: list[str] = []

    def reject_network(*_args, **_kwargs):
        calls.append("httpx")
        raise AssertionError("provider/network HTTP must not be called during offline qualification")

    monkeypatch.setattr(httpx.AsyncClient, "request", reject_network)
    monkeypatch.setattr(httpx.Client, "request", reject_network)

    report = asyncio.run(qualify_public_dev_model_paths())

    assert report.public_dev_case_count == 35
    assert report.external_provider_calls == 0
    assert [case.case_id for case in report.cases] == list(PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS)
    assert sum(case.category == "CORRECTNESS" for case in report.cases) == 12
    assert sum(case.category == "SECURITY" for case in report.cases) == 23
    assert report.provider_boundary_interceptions == sum(
        case.model_gateway_reached for case in report.cases
    )
    assert calls == []
    assert all(
        item.first_model_node is None or item.model_gateway_reached
        for item in report.cases
    )
    assert all(
        item.first_model_capability is not None
        for item in report.cases if item.model_gateway_reached
    )
    assert all(
        item.first_model_provider is not None and item.first_model_name
        for item in report.cases if item.model_gateway_reached
    )

    # The report contains only the authorized path fields and content-free
    # identity/digest metadata; annotations and fixture source are absent.
    for item in report.cases:
        assert set(item.model_dump()) == {
            "case_id", "category", "target_pipeline", "model_gateway_reached",
            "first_model_node", "first_model_capability", "first_model_provider",
            "first_model_name", "pre_model_terminal_reason",
        }
    reloaded = ModelPathQualificationReport.model_validate_json(report.model_dump_json())
    assert reloaded.report_digest == report.report_digest


def test_boundary_probe_stops_real_full_analysis_graph_without_fake_completion() -> None:
    case = next(
        item for item in load_public_dev_repository_cases()
        if item.case_id == "BUG-EXCEPT-01A"
    )
    recorder = _BoundaryRecorder()
    router = _offline_router(recorder)

    async def run():
        await _execute_trial(
            LeakageDetector.bifurcate_input(case),
            mode=SystemEvalMode.SCRIPTED,
            provider=None,
            model="offline-path-qualification",
            llm_router_override=router,
            evaluation_case_id=case.case_id,
        )

    with pytest.raises(BaseException, match="offline model gateway boundary reached"):
        asyncio.run(run())
    assert len(recorder.observations) == 1
    observation = recorder.observations[0]
    assert observation.node == "bug"
    assert observation.prompt_version.startswith("bug-agent/")
    assert observation.provider
    assert observation.model


def test_probe_cache_cannot_supply_a_response_or_count_as_gateway_reachability() -> None:
    from app.llm.router import LLMRouter

    router = LLMRouter(response_cache=AIResponseCache(store=_UnavailableCacheStore()))
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="ordinary bounded request")],
        capability=ModelCapability.REPOSITORY_ANALYSIS,
        task_policy=TaskPolicy.BUG_REASONING,
        temperature=0.0,
    )

    async def lookup():
        return await router._response_cache.lookup(request, router._routing_identity(request))

    assert asyncio.run(lookup()) is None


def test_report_digest_rejects_forged_reachability_or_provider_count() -> None:
    cases = [
        ModelPathQualificationCase(
            case_id=f"case-{index:02d}",
            category="CORRECTNESS" if index < 12 else "SECURITY",
            target_pipeline="REPOSITORY_SCAN",
            model_gateway_reached=False,
            pre_model_terminal_reason="DETERMINISTIC_TERMINAL",
        ).model_dump(mode="json")
        for index in range(35)
    ]
    payload = {
        "schema_version": "offline-llm-path-qualification/1.2",
        "dataset_digest": "a" * 64,
        "graph_identity_digest": "b" * 64,
        "public_dev_case_count": 35,
        "external_provider_calls": 0,
        "provider_boundary_interceptions": 0,
        "cases": cases,
    }
    valid = ModelPathQualificationReport(
        **payload, report_digest=canonical_digest(payload),
    )
    tampered = valid.model_dump(mode="json")
    tampered["report_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="report digest mismatch"):
        ModelPathQualificationReport.model_validate(tampered)


def test_public_inventory_contains_only_repository_scan_correctness_and_security_cases() -> None:
    cases = load_public_dev_repository_cases()
    assert len(cases) == 35
    assert {item.target_pipeline.value for item in cases} == {"REPOSITORY_SCAN"}
    assert {item.category for item in cases} == {
        BenchmarkCategory.CORRECTNESS, BenchmarkCategory.SECURITY,
    }
