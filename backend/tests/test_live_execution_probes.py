"""Offline and integrity tests for non-scoring live execution probes."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json

import httpx
import pytest
from pydantic import ValidationError

from app.evaluation.campaign.execution_probes import (
    LiveExecutionStageEvent,
    LiveExecutionProofProcessingError,
    LiveExecutionProofReport,
    LiveExecutionUnit,
    _build_live_execution_unit,
    _validate_and_persist_proof,
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
from app.evaluation.system.schemas import SystemEvalMode
from app.evaluation.system.full_analysis import _execute_trial
from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import LLMProviderUnavailableError, ProviderFailureOrigin
from app.llm.execution import (
    ExecutionFailureStage,
    ExecutionProvenanceStage,
    capture_execution_provenance,
    observe_execution_stage,
)
from app.llm.router import LLMRouter
from app.schemas.metadata import ModelExecutionMetadata
from app.llm.types import LLMResponse


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
        ("gemini", "gemini", "gemini-3.8-flash"),
        ("groq", "groq", "openai/gpt-oss-120b"),
    ]))

    assert report.provider_calls == 0
    assert len(report.route_results) == 2
    matrix = {
        (item.candidate_id, item.category): (
            item.model_gateway_reached,
            item.observed_model_node,
            item.observed_capability.value if item.observed_capability else None,
            item.expected_capability.value,
            item.observed_provider.value if item.observed_provider else None,
            item.observed_model,
        )
        for item in report.route_results
    }
    assert matrix == {
        ("gemini", "CORRECTNESS"): (
            True, "bug", "REPOSITORY_ANALYSIS", "REPOSITORY_ANALYSIS", "gemini", "gemini-3.8-flash",
        ),
        ("groq", "SECURITY"): (
            True, "security", "REPOSITORY_ANALYSIS", "REPOSITORY_ANALYSIS", "groq", "openai/gpt-oss-120b",
        ),
    }
    groq_route = next(item for item in report.route_results if item.candidate_id == "groq")
    assert groq_route.failure_code is None
    assert report.qualified is True
    assert report.capability_registry_digest
    assert calls == []


def test_pinned_route_report_rejects_candidate_identity_swaps() -> None:
    from app.evaluation.campaign.contracts import canonical_digest

    report = asyncio.run(qualify_pinned_model_probe_paths([
        ("gemini", "gemini", "gemini-3.8-flash"),
        ("groq", "groq", "openai/gpt-oss-120b"),
    ]))
    payload = report.model_dump(mode="json", exclude={"qualification_digest"})
    rows = payload["route_results"]
    rows[0]["provider"], rows[1]["provider"] = rows[1]["provider"], rows[0]["provider"]
    rows[0]["model"], rows[1]["model"] = rows[1]["model"], rows[0]["model"]
    rows[0]["observed_provider"] = rows[0]["provider"]
    rows[0]["observed_model"] = rows[0]["model"]
    rows[1]["observed_provider"] = rows[1]["provider"]
    rows[1]["observed_model"] = rows[1]["model"]
    payload["qualification_digest"] = canonical_digest(payload)
    with pytest.raises(ValidationError, match="candidate identity"):
        type(report).model_validate(payload)


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
        ("gemini", "gemini", "gemini-3.8-flash"),
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
        ("gemini", "gemini", "gemini-3.8-flash"),
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
        "gemini": (LLMProvider.GEMINI, "gemini-3.8-flash"),
        "groq": (LLMProvider.GROQ, "openai/gpt-oss-120b"),
    }
    units = []
    assignments = {
        "gemini": ("LIVE-EXEC-CORRECTNESS-01", "CORRECTNESS"),
        "groq": ("LIVE-EXEC-SECURITY-01", "SECURITY"),
    }
    for candidate_id, (provider, model) in planned.items():
        probe_id, category = assignments[candidate_id]
        units.append(LiveExecutionUnit(
            candidate_id=candidate_id,
            probe_id=probe_id,
            category=category,
            planned_provider=provider,
            planned_model=model,
            status="EXECUTION_PROVEN",
            provider_execution_status="EXECUTION_PROVEN",
            workflow_status="COMPLETED",
            proof_processing_status="COMPLETED",
            model_calls=1,
            observed_model_pairs=(f"{provider.value}:{model}",),
            cross_provider_fallback=False,
            cache_hit=False,
            provider_call_avoided=False,
            duration_ms=1.0,
            safe_failure_code=None,
            provenance_events=(
                LiveExecutionStageEvent(stage="PROVIDER_ATTEMPT_STARTED", provider=provider, model=model),
                LiveExecutionStageEvent(stage="PROVIDER_ATTEMPT_RETURNED", provider=provider, model=model),
                LiveExecutionStageEvent(
                    stage="PROVIDER_EXECUTION_RECORDED", provider=provider, model=model, success=True,
                ),
                LiveExecutionStageEvent(stage="GRAPH_EXECUTION_STARTED"),
                LiveExecutionStageEvent(stage="GRAPH_RETURNED", success=True),
                LiveExecutionStageEvent(stage="POSTPROCESS_COMPLETED"),
            ),
        ).model_dump(mode="json"))
    return {
        "schema_version": "live-execution-proof/1.4",
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
            "gemini:gemini-3.8-flash",
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
    assert len(report.workflow_units) == 2
    assert report.status == "LIVE_EXECUTION_PROVEN"

    tampered = report.model_dump(mode="json")
    tampered["workflow_units"][0]["observed_model_pairs"] = ["groq:openai/gpt-oss-120b"]
    with pytest.raises(ValidationError):
        LiveExecutionProofReport.model_validate(tampered)


def test_live_execution_summary_cannot_claim_cache_or_provider_avoidance_without_event_consistency() -> None:
    payload = _valid_proof_payload()
    payload["workflow_units"][0]["cache_hit"] = True
    with pytest.raises(ValidationError, match="recomputed from scoped attempt events"):
        _validated_proof_report(payload)


def test_live_stage_event_failure_origin_is_typed_and_content_free() -> None:
    http_event = LiveExecutionStageEvent(
        stage="PROVIDER_ATTEMPT_FAILED",
        provider="gemini",
        model="gemini-3.8-flash",
        failure_origin="HTTP",
        http_status=503,
    )
    transport_event = LiveExecutionStageEvent(
        stage="PROVIDER_ATTEMPT_FAILED",
        provider="groq",
        model="openai/gpt-oss-120b",
        failure_origin="TRANSPORT",
        transport_exception_type="ConnectError",
    )
    assert http_event.http_status == 503
    assert http_event.transport_exception_type is None
    assert transport_event.http_status is None
    assert transport_event.transport_exception_type == "ConnectError"

    with pytest.raises(ValidationError):
        LiveExecutionStageEvent(
            stage="PROVIDER_ATTEMPT_FAILED",
            failure_origin="HTTP",
            transport_exception_type="ProxyError",
        )
    with pytest.raises(ValidationError):
        LiveExecutionStageEvent(
            stage="PROVIDER_ATTEMPT_FAILED",
            failure_origin="TRANSPORT",
            http_status=503,
            transport_exception_type="ConnectError",
        )
    with pytest.raises(ValidationError):
        LiveExecutionStageEvent(
            stage="PROVIDER_ATTEMPT_FAILED",
            failure_origin="TRANSPORT",
            transport_exception_type="C:\\sensitive\\proxy-url",
        )

    payload = _valid_proof_payload()
    payload["workflow_units"][0]["provider_call_avoided"] = True
    with pytest.raises(ValidationError, match="recomputed from scoped attempt events"):
        _validated_proof_report(payload)


def test_live_proof_report_rejects_candidate_provider_swaps() -> None:
    payload = _valid_proof_payload()
    gemini, groq = payload["workflow_units"]
    gemini["planned_provider"], groq["planned_provider"] = (
        groq["planned_provider"], gemini["planned_provider"]
    )
    gemini["planned_model"], groq["planned_model"] = (
        groq["planned_model"], gemini["planned_model"]
    )
    gemini["observed_model_pairs"], groq["observed_model_pairs"] = (
        groq["observed_model_pairs"], gemini["observed_model_pairs"]
    )
    with pytest.raises(ValidationError):
        _validated_proof_report(payload)


def _schema_value(schema: dict) -> object:
    if "const" in schema:
        return schema["const"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = "null" if "null" in kind else kind[0]
    if kind == "object":
        properties = schema.get("properties", {})
        return {
            key: _schema_value(properties[key])
            for key in schema.get("required", [])
            if key in properties
        }
    if kind == "array":
        count = int(schema.get("minItems", 0))
        return [_schema_value(schema.get("items", {})) for _ in range(min(count, 4))]
    if kind == "string":
        return "x" * max(1, int(schema.get("minLength", 1)))
    if kind == "integer":
        return int(schema.get("minimum", 0))
    if kind == "number":
        return float(schema.get("minimum", 1.0))
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    return {}


class _SyntheticSuccessAdapter(BaseLLMAdapter):
    def __init__(self, provider: LLMProvider):
        self._provider = provider
        self.calls = 0

    @property
    def provider(self) -> LLMProvider:
        return self._provider

    async def generate(self, request):
        self.calls += 1
        body = _schema_value(request.output_schema or {"type": "object"})
        return LLMResponse(
            content=json.dumps(body),
            model=request.model or "synthetic-model",
            provider=self.provider,
            metadata=ModelExecutionMetadata(
                model_name=request.model or "synthetic-model",
                provider=self.provider.value,
                prompt_tokens=16,
                completion_tokens=8,
                total_tokens=24,
                execution_time_ms=1.0,
            ),
        )


class _SyntheticFailureAdapter(BaseLLMAdapter):
    def __init__(self, provider: LLMProvider):
        self._provider = provider
        self.calls = 0

    @property
    def provider(self) -> LLMProvider:
        return self._provider

    async def generate(self, request):
        self.calls += 1
        error = LLMProviderUnavailableError(
            "synthetic controlled failure",
            provider=self.provider,
            model=request.model,
        )
        error.failure_origin = ProviderFailureOrigin.TRANSPORT
        error.transport_exception_type = "ConnectError"
        raise error


class _SyntheticInvalidResponseAdapter(_SyntheticSuccessAdapter):
    async def generate(self, request):
        self.calls += 1
        return LLMResponse(
            content="{}",
            model=request.model or "synthetic-model",
            provider=self.provider,
            metadata=ModelExecutionMetadata(
                model_name=request.model or "synthetic-model",
                provider=self.provider.value,
                prompt_tokens=16,
                completion_tokens=2,
                total_tokens=18,
                execution_time_ms=1.0,
            ),
        )


async def _run_synthetic_probe(
    candidate_id: str,
    *,
    failing: bool = False,
    invalid: bool = False,
    recording_failure: bool = False,
):
    probes = load_live_execution_probe_set()
    assignments = {
        "gemini": (LLMProvider.GEMINI, "gemini-3.8-flash", "CORRECTNESS"),
        "groq": (LLMProvider.GROQ, "openai/gpt-oss-120b", "SECURITY"),
    }
    provider, model, category = assignments[candidate_id]
    probe = next(item for item in probes.probes if item.category == category)
    adapter = (
        _SyntheticFailureAdapter(provider) if failing
        else _SyntheticInvalidResponseAdapter(provider) if invalid
        else _SyntheticSuccessAdapter(provider)
    )
    router = LLMRouter(adapters={provider: adapter})
    if recording_failure:
        from app.llm.execution import AIExecutionRecorder

        class FailingStore:
            def append(self, _record):
                raise OSError("synthetic private recording detail")

        router._capability_gateway.recorder = AIExecutionRecorder(FailingStore())
    with capture_execution_provenance() as capture:
        observe_execution_stage(ExecutionProvenanceStage.PROOF_UNIT_STARTED)
        state = None
        error = None
        try:
            state, _, _, _ = await _execute_trial(
                probe.analysis_input,
                mode=SystemEvalMode.LIVE,
                provider=provider,
                model=model,
                evaluation_case_id=probe.probe_id,
                presentation_stage="LIVE_EXECUTION_PROOF_ONLY",
                llm_router_override=router,
            )
        except Exception as exc:  # the production proof normalizes the same boundary
            error = exc
        unit = _build_live_execution_unit(
            candidate_id=candidate_id,
            probe=probe,
            provider=provider,
            model=model,
            capture=capture,
            state=state,
            duration_ms=1.0,
            exception=error,
        )
    return unit, adapter.calls, capture.events, state


@pytest.mark.parametrize("candidate_id", ["gemini", "groq"])
def test_full_graph_synthetic_success_reaches_proof_processing_without_network(candidate_id, monkeypatch) -> None:
    external_calls: list[str] = []

    def reject_network(*_args, **_kwargs):
        external_calls.append("http")
        raise AssertionError("synthetic adapter continuation attempted external HTTP")

    monkeypatch.setattr(httpx.AsyncClient, "request", reject_network)
    monkeypatch.setattr(httpx.Client, "request", reject_network)
    unit, adapter_calls, events, state = asyncio.run(_run_synthetic_probe(candidate_id))

    stages = {event.stage for event in events}
    assert adapter_calls >= 1, (
        unit.safe_failure_code,
        unit.exception_stage,
        unit.exception_type,
        [event.stage.value for event in events],
        state.get("status") if isinstance(state, dict) else None,
    )
    assert {
        ExecutionProvenanceStage.MODEL_GATEWAY_REACHED,
        ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED,
        ExecutionProvenanceStage.PROVIDER_ATTEMPT_RETURNED,
        ExecutionProvenanceStage.PROVIDER_EXECUTION_RECORDED,
        ExecutionProvenanceStage.GRAPH_RETURNED,
        ExecutionProvenanceStage.POSTPROCESS_COMPLETED,
    }.issubset(stages)
    assert unit.provider_execution_status == "EXECUTION_PROVEN"
    assert unit.workflow_status == "COMPLETED"
    assert unit.proof_processing_status == "COMPLETED"
    assert state is not None
    assert external_calls == []

    report_payload = _valid_proof_payload()
    unit_payload = unit.model_dump(mode="json")
    index = 0 if candidate_id == "gemini" else 1
    report_payload["workflow_units"][index] = unit_payload
    validated = _validated_proof_report(report_payload)
    assert validated.workflow_units[index].provider_execution_status == "EXECUTION_PROVEN"


def test_controlled_provider_failure_survives_full_graph_as_attempted_failed(monkeypatch) -> None:
    def reject_network(*_args, **_kwargs):
        raise AssertionError("controlled failure adapter must not call the network")

    monkeypatch.setattr(httpx.AsyncClient, "request", reject_network)
    monkeypatch.setattr(httpx.Client, "request", reject_network)
    unit, adapter_calls, events, state = asyncio.run(_run_synthetic_probe("groq", failing=True))
    stages = {event.stage for event in events}

    assert adapter_calls == unit.model_calls >= 1
    assert ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED in stages
    assert ExecutionProvenanceStage.PROVIDER_ATTEMPT_FAILED in stages
    assert unit.provider_execution_status == "ATTEMPTED_FAILED"
    assert unit.status == "PROVIDER_FAILURE"
    assert unit.safe_failure_code == "UNAVAILABLE"
    failed_attempt = next(
        event for event in unit.provenance_events
        if event.stage == ExecutionProvenanceStage.PROVIDER_ATTEMPT_FAILED
    )
    assert failed_attempt.failure_origin == ProviderFailureOrigin.TRANSPORT
    assert failed_attempt.http_status is None
    assert failed_attempt.transport_exception_type == "ConnectError"
    assert state is not None


def test_proven_provider_call_is_not_erased_by_graph_postprocess_failure(monkeypatch) -> None:
    from app.evaluation.system import full_analysis

    original = full_analysis.run_analysis_workflow

    async def graph_then_fail(**kwargs):
        await original(**kwargs)
        raise RuntimeError("synthetic sensitive text that must not persist")

    monkeypatch.setattr(full_analysis, "run_analysis_workflow", graph_then_fail)

    async def scenario():
        unit, _, events, _state = await _run_synthetic_probe("gemini")
        return unit, events

    unit, events = asyncio.run(scenario())
    assert unit.provider_execution_status == "EXECUTION_PROVEN"
    assert unit.workflow_status == "FAILED"
    assert unit.exception_stage == ExecutionFailureStage.GRAPH_POSTPROCESS
    assert unit.exception_type == "RuntimeError"
    assert "synthetic sensitive text" not in unit.model_dump_json()


def test_fixture_finalization_failure_preserves_provider_execution_facts(monkeypatch) -> None:
    from app.evaluation.system.full_analysis import FullAnalysisFixture

    original = FullAnalysisFixture.close

    def close_then_fail(self):
        original(self)
        raise RuntimeError("synthetic credential-shaped diagnostic that must not persist")

    monkeypatch.setattr(FullAnalysisFixture, "close", close_then_fail)
    unit, _calls, events, _state = asyncio.run(_run_synthetic_probe("groq"))

    assert unit.provider_execution_status == "EXECUTION_PROVEN"
    assert unit.exception_stage == ExecutionFailureStage.FINALIZATION
    assert unit.exception_type == "RuntimeError"
    assert ExecutionProvenanceStage.FIXTURE_CLOSE_FAILED in {event.stage for event in events}
    artifact = unit.model_dump_json()
    assert "synthetic credential-shaped diagnostic" not in artifact


def test_failure_before_provider_attempt_is_attributed_to_graph_initialization(monkeypatch) -> None:
    from app.evaluation.system.full_analysis import FullAnalysisFixture

    async def initialize_fails(_self):
        raise ValueError("private initialization detail")

    monkeypatch.setattr(FullAnalysisFixture, "initialize_runtime", initialize_fails)
    unit, adapter_calls, events, state = asyncio.run(_run_synthetic_probe("gemini"))

    assert adapter_calls == 0
    assert state is None
    assert unit.provider_execution_status == "NOT_ATTEMPTED"
    assert unit.workflow_status == "NOT_STARTED"
    assert unit.exception_stage == ExecutionFailureStage.GRAPH_INITIALIZATION
    assert unit.exception_type == "ValueError"
    assert "private initialization detail" not in unit.model_dump_json()


def test_adapter_return_then_invalid_structured_response_is_separately_proven() -> None:
    unit, adapter_calls, events, _state = asyncio.run(
        _run_synthetic_probe("gemini", invalid=True)
    )
    stages = {event.stage for event in events}

    assert adapter_calls >= 1
    assert ExecutionProvenanceStage.PROVIDER_ATTEMPT_RETURNED in stages
    assert ExecutionProvenanceStage.PROVIDER_ATTEMPT_FAILED in stages
    assert ExecutionProvenanceStage.PROVIDER_EXECUTION_RECORDED in stages
    assert unit.provider_execution_status == "EXECUTION_PROVEN"
    assert unit.safe_failure_code == "STRUCTURED_OUTPUT_INVALID"


def test_execution_recording_failure_does_not_invent_recorded_execution() -> None:
    unit, adapter_calls, events, _state = asyncio.run(
        _run_synthetic_probe("gemini", recording_failure=True)
    )
    stages = {event.stage for event in events}

    assert adapter_calls >= 1
    assert ExecutionProvenanceStage.PROVIDER_ATTEMPT_RETURNED in stages
    assert ExecutionProvenanceStage.PROVIDER_EXECUTION_RECORDED not in stages
    assert unit.provider_execution_status == "ATTEMPTED_FAILED"
    assert unit.exception_stage == ExecutionFailureStage.EXECUTION_RECORDING
    assert unit.exception_type == "OSError"
    assert "synthetic private recording detail" not in unit.model_dump_json()


def test_proof_postprocessing_failure_keeps_existing_provider_events() -> None:
    from app.llm.execution import observe_execution_stage

    with capture_execution_provenance() as capture:
        for stage, kwargs in (
            (ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED, {"provider": LLMProvider.GEMINI, "model": "gemini-3.8-flash"}),
            (ExecutionProvenanceStage.PROVIDER_ATTEMPT_RETURNED, {"provider": LLMProvider.GEMINI, "model": "gemini-3.8-flash"}),
            (ExecutionProvenanceStage.PROVIDER_EXECUTION_RECORDED, {"provider": LLMProvider.GEMINI, "model": "gemini-3.8-flash", "success": True}),
            (ExecutionProvenanceStage.GRAPH_EXECUTION_STARTED, {}),
            (ExecutionProvenanceStage.GRAPH_RETURNED, {"success": True}),
        ):
            observe_execution_stage(stage, **kwargs)
        probe = next(item for item in load_live_execution_probe_set().probes if item.category == "CORRECTNESS")
        unit = _build_live_execution_unit(
            candidate_id="gemini",
            probe=probe,
            provider=LLMProvider.GEMINI,
            model="gemini-3.8-flash",
            capture=capture,
            state=42,
            duration_ms=0.5,
        )

    assert unit.provider_execution_status == "EXECUTION_PROVEN"
    assert unit.workflow_status == "COMPLETED"
    assert unit.proof_processing_status == "FAILED"
    assert unit.exception_stage == ExecutionFailureStage.PROOF_POSTPROCESS
    assert unit.exception_type == "TypeError"


def test_artifact_validation_and_finalization_failures_expose_only_safe_stage_and_type(monkeypatch) -> None:
    invalid = _valid_proof_payload()
    invalid["schema_version"] = "invalid"
    with pytest.raises(LiveExecutionProofProcessingError) as validation_error:
        _validate_and_persist_proof(invalid)
    assert validation_error.value.stage == ExecutionFailureStage.ARTIFACT_VALIDATION
    assert validation_error.value.exception_type == "ValidationError"

    def persistence_fails(_report):
        raise OSError("synthetic secret-like persistence detail")

    monkeypatch.setattr("app.evaluation.campaign.execution_probes._persist_proof", persistence_fails)
    with pytest.raises(LiveExecutionProofProcessingError) as finalization_error:
        _validate_and_persist_proof(_valid_proof_payload())
    assert finalization_error.value.stage == ExecutionFailureStage.FINALIZATION
    assert finalization_error.value.exception_type == "OSError"
    assert "synthetic secret-like persistence detail" not in str(finalization_error.value)


def test_proof_stage_capture_is_context_local_and_restored_after_exception() -> None:
    from app.llm.execution import observe_execution_stage

    async def child(stage):
        with capture_execution_provenance() as local:
            observe_execution_stage(stage)
            return local

    async def scenario():
        first, second = await asyncio.gather(
            child(ExecutionProvenanceStage.PROOF_UNIT_STARTED),
            child(ExecutionProvenanceStage.GRAPH_RETURNED),
        )
        return first, second

    first, second = asyncio.run(scenario())
    assert [item.stage for item in first.events] == [ExecutionProvenanceStage.PROOF_UNIT_STARTED]
    assert [item.stage for item in second.events] == [ExecutionProvenanceStage.GRAPH_RETURNED]
