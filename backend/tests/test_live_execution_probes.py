"""Offline and integrity tests for non-scoring live execution probes."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
import pytest
from pydantic import ValidationError

from app.evaluation.campaign.execution_probes import (
    LiveExecutionProofReport,
    LiveExecutionUnit,
    _validated_proof_report,
    load_live_execution_probe_set,
    qualify_live_execution_probe_set,
    qualify_pinned_model_probe_paths,
    run_live_execution_proof,
)
from app.evaluation.ground_truth.public_dev import (
    PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS,
    load_public_dev_repository_cases,
)
from app.llm.types import LLMProvider


def test_two_execution_probes_are_public_label_free_and_not_benchmark_cases() -> None:
    probes = load_live_execution_probe_set()
    public_cases = load_public_dev_repository_cases()

    assert len(probes.probes) == 2
    assert {item.category for item in probes.probes} == {"CORRECTNESS", "SECURITY"}
    assert {item.probe_id for item in probes.probes}.isdisjoint(PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS)
    assert len(public_cases) == 35
    assert all(not hasattr(item, "annotation") for item in probes.probes)
    assert all(item.analysis_input.case_id == item.probe_id for item in probes.probes)
    assert all(item.fixture_digest for item in probes.probes)


def test_both_execution_probes_naturally_reach_real_graph_model_boundary_without_network(monkeypatch) -> None:
    calls: list[str] = []

    def reject_network(*_args, **_kwargs):
        calls.append("http")
        raise AssertionError("offline execution-probe qualification attempted HTTP")

    monkeypatch.setattr(httpx.AsyncClient, "request", reject_network)
    monkeypatch.setattr(httpx.Client, "request", reject_network)

    report = asyncio.run(qualify_live_execution_probe_set())

    assert report.provider_calls == 0
    assert report.qualified is True
    assert [(item.category, item.observed_model_node) for item in report.probe_results] == [
        ("CORRECTNESS", "bug"),
        ("SECURITY", "security"),
    ]
    assert all(item.model_gateway_reached for item in report.probe_results)
    assert calls == []


def test_exact_pinned_model_routes_are_offline_qualified_before_live_execution(monkeypatch) -> None:
    calls: list[str] = []

    def reject_network(*_args, **_kwargs):
        calls.append("http")
        raise AssertionError("pinned model route qualification must not call providers")

    monkeypatch.setattr(httpx.AsyncClient, "request", reject_network)
    monkeypatch.setattr(httpx.Client, "request", reject_network)
    report = asyncio.run(qualify_pinned_model_probe_paths([
        ("gemini", "gemini", "gemini-3.7-flash"),
        ("groq", "groq", "openai/gpt-oss-120b"),
    ]))

    assert report.provider_calls == 0
    assert len(report.route_results) == 4
    matrix = {
        (item.candidate_id, item.category): item.model_gateway_reached
        for item in report.route_results
    }
    # Current configuration permits Gemini to reach both boundaries. The
    # pinned Groq model does not reach either exact boundary under current
    # route/budget policy, so live execution must fail closed.
    assert matrix == {
        ("gemini", "CORRECTNESS"): True,
        ("gemini", "SECURITY"): True,
        ("groq", "CORRECTNESS"): False,
        ("groq", "SECURITY"): False,
    }
    assert report.qualified is False
    assert calls == []


def test_execution_probe_fixture_digest_rejects_payload_mutation() -> None:
    probe = load_live_execution_probe_set().probes[0]
    payload = probe.model_dump(mode="json")
    payload["analysis_input"]["fixture"]["description"] = "tampered"
    with pytest.raises(ValidationError, match="fixture digest mismatch"):
        type(probe).model_validate(payload)


def test_live_proof_refuses_to_start_without_both_explicit_opt_ins(monkeypatch) -> None:
    def preflight_must_not_run(_models):
        raise AssertionError("preflight must not run before explicit live opt-in")

    monkeypatch.setattr("app.evaluation.campaign.preflight.run_campaign_preflight", preflight_must_not_run)
    models = [
        ("gemini", "gemini", "gemini-3.7-flash"),
        ("groq", "groq", "openai/gpt-oss-120b"),
    ]
    with pytest.raises(ValueError, match="requires --allow-live and --allow-model-campaign"):
        asyncio.run(run_live_execution_proof(models))


def test_live_proof_stops_before_preflight_when_one_pinned_route_is_unqualified(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.evaluation.campaign.execution_probes import load_live_execution_probe_set
    from app.evaluation.system.identity import full_analysis_graph_identity_digest

    public_paths = [
        SimpleNamespace(
            category="CORRECTNESS" if index < 12 else "SECURITY",
            model_gateway_reached=index < 3,
        )
        for index in range(35)
    ]
    probe_set = load_live_execution_probe_set()

    async def public_qualification():
        return SimpleNamespace(
            cases=public_paths,
            report_digest="1" * 64,
            dataset_digest="2" * 64,
            public_dev_case_count=35,
            external_provider_calls=0,
        )

    async def probe_qualification():
        return SimpleNamespace(
            qualified=True,
            probe_set_digest=probe_set.digest,
            graph_identity_digest=full_analysis_graph_identity_digest(),
            qualification_digest="3" * 64,
        )

    async def pinned_routes(_models):
        return SimpleNamespace(
            qualified=False,
            route_results=[
                SimpleNamespace(candidate_id="groq", category="CORRECTNESS", model_gateway_reached=False),
                SimpleNamespace(candidate_id="groq", category="SECURITY", model_gateway_reached=False),
            ],
        )

    monkeypatch.setattr(
        "app.evaluation.campaign.execution_probes.qualify_public_dev_model_paths",
        public_qualification,
    )
    monkeypatch.setattr(
        "app.evaluation.campaign.execution_probes.qualify_live_execution_probe_set",
        probe_qualification,
    )
    monkeypatch.setattr(
        "app.evaluation.campaign.execution_probes.qualify_pinned_model_probe_paths",
        pinned_routes,
    )
    preflight_calls: list[bool] = []

    def fail_if_preflight_runs(_models):
        preflight_calls.append(True)
        raise AssertionError("route failure must stop before preflight/live execution")

    monkeypatch.setattr("app.evaluation.campaign.preflight.run_campaign_preflight", fail_if_preflight_runs)
    models = [
        ("gemini", "gemini", "gemini-3.7-flash"),
        ("groq", "groq", "openai/gpt-oss-120b"),
    ]
    with pytest.raises(ValueError, match="no live provider workflows were started"):
        asyncio.run(run_live_execution_proof(
            models,
            allow_live=True,
            allow_model_campaign=True,
        ))
    assert preflight_calls == []


def _valid_proof_payload() -> dict:
    planned = {
        "gemini": (LLMProvider.GEMINI, "gemini-3.7-flash"),
        "groq": (LLMProvider.GROQ, "openai/gpt-oss-120b"),
    }
    units = []
    for candidate_id, (provider, model) in planned.items():
        for probe_id, category in (
            ("LIVE-EXEC-CORRECTNESS-01", "CORRECTNESS"),
            ("LIVE-EXEC-SECURITY-01", "SECURITY"),
        ):
            units.append(LiveExecutionUnit(
                candidate_id=candidate_id,
                probe_id=probe_id,
                category=category,
                planned_provider=provider,
                planned_model=model,
                status="EXECUTION_PROVEN",
                model_calls=1,
                observed_model_pairs=(f"{provider.value}:{model}",),
                cross_provider_fallback=False,
                duration_ms=1.0,
                safe_failure_code=None,
            ).model_dump(mode="json"))
    return {
        "schema_version": "live-execution-proof/1.1",
        "proof_id": "1" * 32,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_revision": "c" * 40,
        "source_binding_digest": "a" * 64,
        "dirty_worktree": True,
        "probe_set_version": "live-execution-probes/1.0",
        "probe_set_digest": "b" * 64,
        "public_dev_qualification_digest": "d" * 64,
        "public_dev_dataset_digest": "e" * 64,
        "pinned_route_qualification_digest": "8" * 64,
        "public_dev_case_count": 35,
        "public_dev_correctness_model_paths": 3,
        "public_dev_security_model_paths": 0,
        "qualification_digest": "f" * 64,
        "graph_identity_digest": "9" * 64,
        "system_identity_digests": {"gemini": "1" * 64, "groq": "2" * 64},
        "planned_model_pairs": (
            "gemini:gemini-3.7-flash",
            "groq:openai/gpt-oss-120b",
        ),
        "provider_preflight_statuses": {
            "gemini": "READY_WITH_CAPABILITY_WARNINGS",
            "groq": "READY_WITH_CAPABILITY_WARNINGS",
        },
        "mode": "LIVE_EXECUTION_PROOF_ONLY",
        "quality_metrics": "NOT_APPLICABLE",
        "workflow_units": units,
        "status": "LIVE_EXECUTION_PROVEN",
    }


def test_live_proof_report_digest_and_execution_identities_are_validated() -> None:
    payload = _valid_proof_payload()
    report = _validated_proof_report(payload)
    assert len(report.workflow_units) == 4
    assert report.status == "LIVE_EXECUTION_PROVEN"

    tampered = report.model_dump(mode="json")
    tampered["workflow_units"][0]["observed_model_pairs"] = ["groq:openai/gpt-oss-120b"]
    with pytest.raises(ValidationError):
        LiveExecutionProofReport.model_validate(tampered)
