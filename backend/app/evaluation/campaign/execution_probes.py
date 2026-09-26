"""Separate, non-scoring fixtures for explicit live model-execution proof.

These two fixtures establish that the configured live models can be invoked by
the production full-analysis graph. They are not benchmark cases and carry no
expected findings, labels, grader outcomes, or quality metrics.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import time
from typing import Any, Literal
from uuid import uuid4

from pydantic import ConfigDict, Field, model_validator

from app.evaluation.campaign.contracts import CampaignModel, canonical_digest
from app.evaluation.campaign.path_qualification import (
    ModelPathQualificationReport,
    _qualify_analysis_input,
    qualify_public_dev_model_paths,
)
from app.evaluation.ground_truth.schemas import AnalysisInput, RepositoryFixture, TargetPipeline
from app.evaluation.system.full_analysis import _execute_trial
from app.evaluation.system.identity import build_agent_system_identity, full_analysis_graph_identity_digest
from app.evaluation.system.schemas import SystemEvalMode
from app.evaluation.system.full_analysis import FullAnalysisFixture
from app.evaluation.ground_truth.leakage import LeakageDetector
from app.llm.router import get_llm_router
from app.llm.execution import (
    ExecutionFailureStage,
    ExecutionProvenanceCapture,
    ExecutionProvenanceEvent,
    ExecutionProvenanceStage,
    capture_execution_provenance,
    observe_execution_stage,
    record_execution_exception,
)
from app.llm.exceptions import ProviderFailureOrigin
from app.llm.types import LLMProvider, ModelCapability


LIVE_EXECUTION_PROBE_SET_VERSION = "live-execution-probes/1.0"
LIVE_EXECUTION_PROOF_SCHEMA_VERSION = "live-execution-proof/1.4"
PINNED_ROUTE_QUALIFICATION_SCHEMA_VERSION = "pinned-model-route-qualification/2.0"
_PLANNED_MODELS = {
    "gemini": (LLMProvider.GEMINI, "gemini-3.8-flash"),
    "groq": (LLMProvider.GROQ, "openai/gpt-oss-120b"),
}
_PROBE_CAPABILITIES = {
    # These are the exact capabilities placed on the actual specialist
    # LLMRequest objects; task_policy is separately bound by the graph.
    "CORRECTNESS": ModelCapability.REPOSITORY_ANALYSIS,
    "SECURITY": ModelCapability.REPOSITORY_ANALYSIS,
}


class LiveExecutionProofProcessingError(RuntimeError):
    """Safe artifact-processing failure without an arbitrary exception message."""

    def __init__(self, *, stage: ExecutionFailureStage, exception_type: str) -> None:
        self.stage = stage
        self.exception_type = exception_type[:64] if exception_type.isidentifier() else "Exception"
        super().__init__("Live execution proof artifact processing failed.")


_PROBE_SOURCE_DIRECTORIES = (
    "backend/app/agents",
    "backend/app/agent_runtime",
    "backend/app/agent_tools",
    "backend/app/context",
    "backend/app/llm",
    "backend/app/evaluation/system",
    "backend/app/evaluation/campaign",
)


class LiveExecutionProbe(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(min_length=1, max_length=96)
    category: Literal["CORRECTNESS", "SECURITY"]
    expected_model_node: Literal["bug", "security"]
    analysis_input: AnalysisInput
    fixture_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_fixture(self) -> "LiveExecutionProbe":
        if self.analysis_input.case_id != self.probe_id:
            raise ValueError("execution probe ID must match its label-free analysis input")
        if self.analysis_input.target_pipeline != TargetPipeline.REPOSITORY_SCAN:
            raise ValueError("execution probes must use the production repository-scan pipeline")
        actual = canonical_digest(self.analysis_input.model_dump(mode="json"))
        if actual != self.fixture_digest:
            raise ValueError("execution probe fixture digest mismatch")
        LeakageDetector.check_fixture(self.analysis_input.fixture, case_id=self.probe_id)
        if self.category == "CORRECTNESS" and self.expected_model_node != "bug":
            raise ValueError("correctness execution probe must qualify the bug specialist path")
        if self.category == "SECURITY" and self.expected_model_node != "security":
            raise ValueError("security execution probe must qualify the security specialist path")
        return self


class LiveExecutionProbeSet(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["live-execution-probes/1.0"] = LIVE_EXECUTION_PROBE_SET_VERSION
    probes: tuple[LiveExecutionProbe, LiveExecutionProbe]
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_set(self) -> "LiveExecutionProbeSet":
        if {item.category for item in self.probes} != {"CORRECTNESS", "SECURITY"}:
            raise ValueError("execution probe set must contain one correctness and one security fixture")
        if len({item.probe_id for item in self.probes}) != 2:
            raise ValueError("execution probe IDs must be unique")
        payload = self.model_dump(mode="json", exclude={"digest"})
        if canonical_digest(payload) != self.digest:
            raise ValueError("execution probe set digest mismatch")
        return self


def _build_probe_payload() -> dict[str, Any]:
    raw_inputs = (
        {
            "probe_id": "LIVE-EXEC-CORRECTNESS-01",
            "category": "CORRECTNESS",
            "expected_model_node": "bug",
            "analysis_input": AnalysisInput(
                case_id="LIVE-EXEC-CORRECTNESS-01",
                target_pipeline=TargetPipeline.REPOSITORY_SCAN,
                fixture=RepositoryFixture(files={
                    "worker.py": (
                        "import time\n\n"
                        "async def poll_remote_status():\n"
                        "    time.sleep(0.01)\n"
                    ),
                }),
            ),
        },
        {
            "probe_id": "LIVE-EXEC-SECURITY-01",
            "category": "SECURITY",
            "expected_model_node": "security",
            "analysis_input": AnalysisInput(
                case_id="LIVE-EXEC-SECURITY-01",
                target_pipeline=TargetPipeline.REPOSITORY_SCAN,
                fixture=RepositoryFixture(files={
                    "records.py": (
                        "from fastapi import FastAPI\n\n"
                        "app = FastAPI()\n\n"
                        "@app.get('/records/{owner}')\n"
                        "def load_record(owner: str):\n"
                        "    connection = get_connection()\n"
                        "    return connection.execute(\n"
                        "        f\"SELECT * FROM records WHERE owner = '{owner}'\"\n"
                        "    )\n"
                    ),
                }),
            ),
        },
    )
    probes = []
    for item in raw_inputs:
        analysis_input = item["analysis_input"].model_dump(mode="json")
        input_digest = canonical_digest(analysis_input)
        probes.append({**item, "analysis_input": analysis_input, "fixture_digest": input_digest})
    return {
        "version": LIVE_EXECUTION_PROBE_SET_VERSION,
        "probes": probes,
    }


def load_live_execution_probe_set() -> LiveExecutionProbeSet:
    """Return a fresh validated copy of exactly two public execution fixtures."""
    payload = _build_probe_payload()
    return LiveExecutionProbeSet(**payload, digest=canonical_digest(payload))


class ProbePathQualification(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(min_length=1, max_length=96)
    category: Literal["CORRECTNESS", "SECURITY"]
    expected_model_node: Literal["bug", "security"]
    model_gateway_reached: bool
    observed_model_node: str | None = Field(default=None, max_length=64)
    failure_code: str | None = Field(default=None, max_length=64)


class LiveExecutionProbeQualification(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["live-execution-probe-qualification/1.0"] = "live-execution-probe-qualification/1.0"
    probe_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_calls: Literal[0] = 0
    probe_results: tuple[ProbePathQualification, ProbePathQualification]
    qualified: bool
    qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_qualification(self) -> "LiveExecutionProbeQualification":
        expected = all(
            item.model_gateway_reached and item.observed_model_node == item.expected_model_node
            and item.failure_code is None
            for item in self.probe_results
        )
        if self.qualified != expected:
            raise ValueError("probe qualification status does not match its child results")
        payload = self.model_dump(mode="json", exclude={"qualification_digest"})
        if canonical_digest(payload) != self.qualification_digest:
            raise ValueError("execution probe qualification digest mismatch")
        return self


class PinnedModelProbePath(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1, max_length=64)
    probe_id: str = Field(min_length=1, max_length=96)
    category: Literal["CORRECTNESS", "SECURITY"]
    provider: LLMProvider
    model: str = Field(min_length=1, max_length=256)
    expected_model_node: Literal["bug", "security"]
    expected_capability: ModelCapability
    model_gateway_reached: bool
    observed_model_node: str | None = Field(default=None, max_length=64)
    observed_capability: ModelCapability | None = None
    observed_provider: LLMProvider | None = None
    observed_model: str | None = Field(default=None, max_length=256)
    failure_code: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def validate_route_path(self) -> "PinnedModelProbePath":
        if self.model_gateway_reached:
            if (
                self.observed_model_node != self.expected_model_node
                or self.observed_capability != self.expected_capability
                or self.observed_provider != self.provider
                or self.observed_model != self.model
                or self.failure_code is not None
            ):
                raise ValueError("pinned model path must reach its exact expected production node")
        elif (
            self.observed_model_node is not None
            or self.observed_capability is not None
            or self.observed_provider is not None
            or self.observed_model is not None
            or self.failure_code is None
        ):
            raise ValueError("unreachable pinned model paths require a bounded failure code")
        return self


class PinnedModelRouteQualification(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["pinned-model-route-qualification/2.0"] = PINNED_ROUTE_QUALIFICATION_SCHEMA_VERSION
    probe_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_registry_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    planned_model_pairs: tuple[str, str]
    provider_calls: Literal[0] = 0
    route_results: tuple[PinnedModelProbePath, PinnedModelProbePath]
    qualified: bool
    qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_route_matrix(self) -> "PinnedModelRouteQualification":
        expected_models = {f"{provider.value}:{model}" for provider, model in _PLANNED_MODELS.values()}
        if set(self.planned_model_pairs) != expected_models:
            raise ValueError("pinned route qualification must use the two exact planned models")
        keys = [(item.candidate_id, item.probe_id) for item in self.route_results]
        if len(set(keys)) != 2:
            raise ValueError("pinned route qualification must contain one assignment per candidate")
        if {f"{item.provider.value}:{item.model}" for item in self.route_results} != expected_models:
            raise ValueError("pinned route results do not match the exact model identities")
        assignments = {
            "gemini": ("LIVE-EXEC-CORRECTNESS-01", "bug", ModelCapability.REPOSITORY_ANALYSIS),
            "groq": ("LIVE-EXEC-SECURITY-01", "security", ModelCapability.REPOSITORY_ANALYSIS),
        }
        if {row.candidate_id for row in self.route_results} != set(assignments):
            raise ValueError("pinned route results must contain each planned candidate exactly once")
        for row in self.route_results:
            probe_id, node, capability = assignments[row.candidate_id]
            if (row.probe_id, row.expected_model_node, row.expected_capability) != (probe_id, node, capability):
                raise ValueError("pinned route assignment does not match the compatible capability contract")
            expected_provider, expected_model = _PLANNED_MODELS[row.candidate_id]
            if (row.provider, row.model) != (expected_provider, expected_model):
                raise ValueError("pinned candidate identity is not bound to its planned provider/model")
        expected_qualified = all(
            row.model_gateway_reached
            and row.observed_model_node == row.expected_model_node
            and row.observed_capability == row.expected_capability
            and row.observed_provider == row.provider
            and row.observed_model == row.model
            and row.failure_code is None
            for row in self.route_results
        )
        if self.qualified != expected_qualified:
            raise ValueError("pinned route qualification status does not match the route matrix")
        payload = self.model_dump(mode="json", exclude={"qualification_digest"})
        if canonical_digest(payload) != self.qualification_digest:
            raise ValueError("pinned model route qualification digest mismatch")
        return self


async def qualify_live_execution_probe_set() -> LiveExecutionProbeQualification:
    """Prove both separate fixtures reach their intended nodes, without providers."""
    probes = load_live_execution_probe_set()
    results: list[ProbePathQualification] = []
    for probe in probes.probes:
        path = await _qualify_analysis_input(
            probe.analysis_input,
            case_id=probe.probe_id,
            category=probe.category,
        )
        results.append(ProbePathQualification(
            probe_id=probe.probe_id,
            category=probe.category,
            expected_model_node=probe.expected_model_node,
            model_gateway_reached=path.model_gateway_reached,
            observed_model_node=path.first_model_node,
            failure_code=None if path.model_gateway_reached else path.pre_model_terminal_reason,
        ))
    results.sort(key=lambda item: item.category)
    qualified = all(
        item.model_gateway_reached and item.observed_model_node == item.expected_model_node
        and item.failure_code is None
        for item in results
    )
    payload = {
        "schema_version": "live-execution-probe-qualification/1.0",
        "probe_set_digest": probes.digest,
        "graph_identity_digest": full_analysis_graph_identity_digest(),
        "provider_calls": 0,
        "probe_results": [item.model_dump(mode="json") for item in results],
        "qualified": qualified,
    }
    return LiveExecutionProbeQualification(
        **payload, qualification_digest=canonical_digest(payload),
    )


async def qualify_pinned_model_probe_paths(
    models: list[tuple[str, LLMProvider | str, str]],
) -> PinnedModelRouteQualification:
    """Qualify one capability-compatible production path per pinned model, offline."""
    normalized = [(candidate_id, LLMProvider(provider), model) for candidate_id, provider, model in models]
    expected = {
        (candidate_id, provider, model)
        for candidate_id, (provider, model) in _PLANNED_MODELS.items()
    }
    if len(normalized) != 2 or set(normalized) != expected:
        raise ValueError("pinned route qualification only accepts the exact planned model candidates")

    router = get_llm_router()
    registry = router._capability_gateway.registry
    probes = load_live_execution_probe_set()
    probes_by_category = {probe.category: probe for probe in probes.probes}
    assignments = {"gemini": "CORRECTNESS", "groq": "SECURITY"}
    results: list[PinnedModelProbePath] = []
    for candidate_id, provider, model in sorted(normalized, key=lambda item: item[0]):
        category = assignments[candidate_id]
        probe = probes_by_category[category]
        expected_capability = _PROBE_CAPABILITIES[category]
        spec = registry.get(provider, model)
        if spec is None or not spec.enabled or not spec.supports(expected_capability):
            results.append(PinnedModelProbePath(
                candidate_id=candidate_id,
                probe_id=probe.probe_id,
                category=probe.category,
                provider=provider,
                model=model,
                expected_model_node=probe.expected_model_node,
                expected_capability=expected_capability,
                model_gateway_reached=False,
                failure_code="MODEL_CAPABILITY_NOT_REGISTERED",
            ))
            continue
        path = await _qualify_analysis_input(
            probe.analysis_input,
            case_id=probe.probe_id,
            category=probe.category,
            provider=provider,
            model=model,
        )
        results.append(PinnedModelProbePath(
            candidate_id=candidate_id,
            probe_id=probe.probe_id,
            category=probe.category,
            provider=provider,
            model=model,
            expected_model_node=probe.expected_model_node,
            expected_capability=expected_capability,
            model_gateway_reached=path.model_gateway_reached,
            observed_model_node=path.first_model_node,
            observed_capability=(
                ModelCapability(path.first_model_capability)
                if path.first_model_capability is not None else None
            ),
            observed_provider=path.first_model_provider,
            observed_model=path.first_model_name,
            failure_code=(
                None if path.model_gateway_reached
                else path.pre_model_terminal_reason or "PINNED_MODEL_ROUTE_NOT_REACHABLE"
            ),
        ))
    results.sort(key=lambda item: (item.candidate_id, item.category))
    pairs = tuple(sorted(f"{provider.value}:{model}" for _, provider, model in normalized))
    qualified = all(
        item.model_gateway_reached
        and item.observed_model_node == item.expected_model_node
        and item.observed_capability == item.expected_capability
        and item.observed_provider == item.provider
        and item.observed_model == item.model
        and item.failure_code is None
        for item in results
    )
    payload = {
        "schema_version": PINNED_ROUTE_QUALIFICATION_SCHEMA_VERSION,
        "probe_set_digest": probes.digest,
        "graph_identity_digest": full_analysis_graph_identity_digest(),
        "capability_registry_digest": registry.version,
        "planned_model_pairs": pairs,
        "provider_calls": 0,
        "route_results": [item.model_dump(mode="json") for item in results],
        "qualified": qualified,
    }
    return PinnedModelRouteQualification(
        **payload, qualification_digest=canonical_digest(payload),
    )


class LiveExecutionStageEvent(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: ExecutionProvenanceStage
    provider: LLMProvider | None = None
    model: str | None = Field(default=None, max_length=256)
    capability: ModelCapability | None = None
    success: bool | None = None
    provider_failure_code: str | None = Field(default=None, max_length=32)
    failure_origin: ProviderFailureOrigin | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    transport_exception_type: str | None = Field(
        default=None,
        max_length=64,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )
    attempt_sequence: int | None = Field(default=None, ge=0, le=64)
    latency_ms: float | None = Field(default=None, ge=0.0, le=120_000.0)
    fallback: bool = False
    exception_type: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")

    @model_validator(mode="after")
    def validate_failure_origin(self) -> "LiveExecutionStageEvent":
        if self.failure_origin == ProviderFailureOrigin.HTTP:
            if self.http_status is None or self.transport_exception_type is not None:
                raise ValueError("HTTP failure provenance requires only an HTTP status")
        elif self.failure_origin == ProviderFailureOrigin.TRANSPORT:
            if self.http_status is not None or self.transport_exception_type is None:
                raise ValueError("transport failure provenance requires only an exception class")
        elif self.http_status is not None or self.transport_exception_type is not None:
            raise ValueError("unknown failure provenance cannot carry transport or HTTP details")
        return self

    @classmethod
    def from_observation(cls, event: ExecutionProvenanceEvent) -> "LiveExecutionStageEvent":
        return cls(
            stage=event.stage,
            provider=event.provider,
            model=event.model,
            capability=event.capability,
            success=event.success,
            provider_failure_code=(event.failure_code.value if event.failure_code else None),
            failure_origin=event.failure_origin,
            http_status=event.http_status,
            transport_exception_type=event.transport_exception_type,
            attempt_sequence=event.attempt_sequence,
            latency_ms=event.latency_ms,
            fallback=event.fallback,
            exception_type=event.exception_type,
        )


class LiveExecutionUnit(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1, max_length=64)
    probe_id: str = Field(min_length=1, max_length=96)
    category: Literal["CORRECTNESS", "SECURITY"]
    planned_provider: LLMProvider
    planned_model: str = Field(min_length=1, max_length=256)
    status: Literal[
        "EXECUTION_PROVEN", "PROVIDER_FAILURE", "BUDGET_FAILURE", "IDENTITY_MISMATCH",
        "MODEL_NOT_INVOKED", "HARNESS_FAILURE",
    ]
    provider_execution_status: Literal["NOT_ATTEMPTED", "ATTEMPTED_FAILED", "EXECUTION_PROVEN"]
    workflow_status: Literal["NOT_STARTED", "FAILED", "COMPLETED"]
    proof_processing_status: Literal["NOT_STARTED", "FAILED", "COMPLETED"]
    model_calls: int = Field(ge=0, le=64)
    observed_model_pairs: tuple[str, ...] = Field(max_length=8)
    cross_provider_fallback: bool
    cache_hit: bool = False
    provider_call_avoided: bool = False
    duration_ms: float = Field(ge=0.0, le=120_000.0)
    safe_failure_code: str | None = Field(default=None, max_length=64)
    exception_stage: ExecutionFailureStage | None = None
    exception_type: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    provenance_events: tuple[LiveExecutionStageEvent, ...] = Field(default=(), max_length=256)
    provenance_truncated: bool = False

    @model_validator(mode="after")
    def validate_execution_identity(self) -> "LiveExecutionUnit":
        planned = f"{self.planned_provider.value}:{self.planned_model}"
        attempts = [
            event for event in self.provenance_events
            if event.stage == ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED
        ]
        derived_pairs = tuple(sorted({
            f"{event.provider.value}:{event.model}"
            for event in attempts
            if event.provider is not None and event.model is not None
        }))
        derived_cache_hit = any(
            event.stage == ExecutionProvenanceStage.CACHE_HIT
            for event in self.provenance_events
        )
        derived_call_avoided = any(
            event.stage == ExecutionProvenanceStage.PROVIDER_CALL_AVOIDED
            for event in self.provenance_events
        )
        derived_cross_provider_fallback = any(
            event.provider is not None and event.provider != self.planned_provider
            for event in attempts
        )
        if (
            self.model_calls != min(64, len(attempts))
            or self.observed_model_pairs != derived_pairs
            or self.cache_hit != derived_cache_hit
            or self.provider_call_avoided != derived_call_avoided
            or self.cross_provider_fallback != derived_cross_provider_fallback
        ):
            raise ValueError("provider outcome summary must be recomputed from scoped attempt events")

        exact_events = [
            event for event in self.provenance_events
            if event.provider == self.planned_provider and event.model == self.planned_model
        ]
        exact_stages = {event.stage for event in exact_events}
        identity_execution_proven = (
            not self.provenance_truncated
            and derived_pairs == (planned,)
            and not derived_cross_provider_fallback
            and not derived_cache_hit
            and not derived_call_avoided
            and {
                ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED,
                ExecutionProvenanceStage.PROVIDER_ATTEMPT_RETURNED,
                ExecutionProvenanceStage.PROVIDER_EXECUTION_RECORDED,
            }.issubset(exact_stages)
        )
        derived_provider_status = (
            "EXECUTION_PROVEN" if identity_execution_proven
            else "ATTEMPTED_FAILED" if attempts
            else "NOT_ATTEMPTED"
        )
        if self.provider_execution_status != derived_provider_status:
            raise ValueError("provider execution status must be derived from current-run adapter evidence")

        graph_started = any(
            event.stage == ExecutionProvenanceStage.GRAPH_EXECUTION_STARTED
            for event in self.provenance_events
        )
        graph_failed = any(
            event.stage == ExecutionProvenanceStage.GRAPH_FAILED
            for event in self.provenance_events
        )
        graph_returned = next((
            event for event in reversed(self.provenance_events)
            if event.stage == ExecutionProvenanceStage.GRAPH_RETURNED
        ), None)
        derived_workflow_status = (
            "NOT_STARTED" if not graph_started and graph_returned is None and not graph_failed
            else "COMPLETED" if graph_returned is not None and graph_returned.success is True and not graph_failed
            else "FAILED"
        )
        if self.workflow_status != derived_workflow_status:
            raise ValueError("workflow status must be derived from graph execution events")

        postprocess_started = any(
            event.stage == ExecutionProvenanceStage.POSTPROCESS_STARTED
            for event in self.provenance_events
        )
        postprocess_completed = any(
            event.stage == ExecutionProvenanceStage.POSTPROCESS_COMPLETED
            for event in self.provenance_events
        )
        derived_proof_status = (
            "COMPLETED" if postprocess_completed
            else "FAILED" if postprocess_started
            else "NOT_STARTED"
        )
        if self.proof_processing_status != derived_proof_status:
            raise ValueError("proof processing status must be derived from post-processing events")

        if (self.status == "EXECUTION_PROVEN") != (self.provider_execution_status == "EXECUTION_PROVEN"):
            raise ValueError("legacy unit status must reflect the independent provider execution status")
        if self.provider_execution_status == "EXECUTION_PROVEN":
            if (
                self.model_calls < 1
                or self.observed_model_pairs != (planned,)
                or self.cross_provider_fallback
                or self.cache_hit
                or self.provider_call_avoided
                or self.provenance_truncated
                or not {
                    ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED,
                    ExecutionProvenanceStage.PROVIDER_ATTEMPT_RETURNED,
                    ExecutionProvenanceStage.PROVIDER_EXECUTION_RECORDED,
                }.issubset(exact_stages)
            ):
                raise ValueError("provider execution proof requires exact non-reused adapter and recorder evidence")
        elif self.provider_execution_status == "ATTEMPTED_FAILED" and self.model_calls < 1:
            raise ValueError("attempted failure requires factual provider-attempt evidence")
        if self.provider_execution_status == "NOT_ATTEMPTED" and self.model_calls != 0:
            raise ValueError("not-attempted status cannot include adapter invocation starts")
        if (self.exception_stage is None) != (self.exception_type is None):
            raise ValueError("exception stage and type must be recorded together")
        if self.status != "EXECUTION_PROVEN" and self.safe_failure_code is None:
            raise ValueError("failed execution units require a safe failure code")
        return self


class LiveExecutionProofReport(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["live-execution-proof/1.4"] = LIVE_EXECUTION_PROOF_SCHEMA_VERSION
    proof_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    created_at: datetime
    source_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    source_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    dirty_worktree: bool
    probe_set_version: str = Field(min_length=1, max_length=64)
    probe_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_dev_qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_dev_dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    pinned_route_qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_dev_case_count: Literal[35] = 35
    public_dev_correctness_model_paths: int = Field(ge=1, le=12)
    public_dev_security_model_paths: Literal[0] = 0
    qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    system_identity_digests: dict[str, str] = Field(min_length=2, max_length=2)
    planned_model_pairs: tuple[str, str]
    provider_preflight_statuses: dict[str, str] = Field(min_length=2, max_length=2)
    mode: Literal["LIVE_EXECUTION_PROOF_ONLY"] = "LIVE_EXECUTION_PROOF_ONLY"
    quality_metrics: Literal["NOT_APPLICABLE"] = "NOT_APPLICABLE"
    workflow_units: tuple[LiveExecutionUnit, LiveExecutionUnit]
    status: Literal["LIVE_EXECUTION_PROVEN", "LIVE_EXECUTION_NOT_PROVEN"]
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_proof(self) -> "LiveExecutionProofReport":
        expected_pairs = set(self.planned_model_pairs)
        if len(expected_pairs) != 2:
            raise ValueError("execution proof must bind exactly two distinct model identities")
        expected_assignments = {
            "gemini": ("LIVE-EXEC-CORRECTNESS-01", "CORRECTNESS", *_PLANNED_MODELS["gemini"]),
            "groq": ("LIVE-EXEC-SECURITY-01", "SECURITY", *_PLANNED_MODELS["groq"]),
        }
        if len({unit.candidate_id for unit in self.workflow_units}) != 2:
            raise ValueError("execution proof must contain exactly one workflow per candidate")
        for unit in self.workflow_units:
            expected_assignment = expected_assignments.get(unit.candidate_id)
            if expected_assignment is None or (
                unit.probe_id,
                unit.category,
                unit.planned_provider,
                unit.planned_model,
            ) != expected_assignment:
                raise ValueError("execution proof workflow does not match its capability-compatible assignment")
        if {f"{unit.planned_provider.value}:{unit.planned_model}" for unit in self.workflow_units} != expected_pairs:
            raise ValueError("execution proof workflow identities differ from planned identities")
        fixed_pairs = {
            f"{provider.value}:{model}" for provider, model in _PLANNED_MODELS.values()
        }
        if expected_pairs != fixed_pairs:
            raise ValueError("execution proof must bind the two fixed requested model identities")
        candidate_ids = {unit.candidate_id for unit in self.workflow_units}
        if candidate_ids != set(self.system_identity_digests) or candidate_ids != set(self.provider_preflight_statuses):
            raise ValueError("execution proof candidate metadata must match all workflow units")
        proven = all(unit.provider_execution_status == "EXECUTION_PROVEN" for unit in self.workflow_units)
        if (self.status == "LIVE_EXECUTION_PROVEN") != proven:
            raise ValueError("proof status must be derived from both workflow units")
        payload = self.model_dump(mode="json", exclude={"report_digest"})
        if canonical_digest(payload) != self.report_digest:
            raise ValueError("live execution proof digest mismatch")
        return self


def _validated_proof_report(raw: dict[str, Any]) -> LiveExecutionProofReport:
    """Normalize through the report's JSON contract before digesting it."""
    value = dict(raw)
    if isinstance(value.get("created_at"), str):
        value["created_at"] = datetime.fromisoformat(value["created_at"])
    value["planned_model_pairs"] = tuple(value["planned_model_pairs"])
    value["workflow_units"] = tuple(
        item if isinstance(item, LiveExecutionUnit) else LiveExecutionUnit.model_validate(item)
        for item in value["workflow_units"]
    )
    normalized = LiveExecutionProofReport.model_construct(
        **value, report_digest="0" * 64,
    ).model_dump(mode="json", exclude={"report_digest"})
    return LiveExecutionProofReport(
        **normalized,
        report_digest=canonical_digest(normalized),
    )


def _source_binding_digest() -> str:
    repository = Path(__file__).resolve().parents[4]
    digest = hashlib.sha256()
    root = repository.resolve(strict=True)
    paths: list[tuple[str, Path]] = []
    for relative_dir in _PROBE_SOURCE_DIRECTORIES:
        directory = repository / relative_dir
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("live execution proof source inventory is incomplete")
        for path in directory.rglob("*"):
            if "__pycache__" in path.parts:
                continue
            if path.is_symlink():
                raise ValueError("live execution proof source inventory contains a symlink")
            if not path.is_file() or path.suffix != ".py":
                continue
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise ValueError("live execution proof source inventory escaped the repository") from exc
            paths.append((path.relative_to(repository).as_posix(), resolved))
    for relative, path in sorted(paths):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _safe_failure_code(state: dict[str, Any], *, model_calls: int, identity_ok: bool) -> str | None:
    trace = state.get("workflow_trace", [])
    trace = trace if isinstance(trace, list) else []
    failure_codes = {
        str(code)
        for event in trace if isinstance(event, dict)
        for code in (
            event.get("failure_codes", [])
            if isinstance(event.get("failure_codes", []), list)
            else []
        )
    }
    if "BUDGET_EXHAUSTION" in failure_codes or bool((state.get("ai_cloud_budget") or {}).get("exhausted")):
        return "WORKFLOW_BUDGET_EXHAUSTED"
    if "MODEL_PROVIDER_FAILURE" in failure_codes or "MODEL_PROVIDER_TIMEOUT" in failure_codes:
        return "MODEL_PROVIDER_FAILURE"
    if model_calls == 0:
        return "MODEL_NOT_INVOKED"
    if not identity_ok:
        return "PINNED_MODEL_IDENTITY_MISMATCH"
    if state.get("status") == "FAILED":
        return "WORKFLOW_HARNESS_FAILURE"
    return None


def _exception_stage_for_capture(capture: ExecutionProvenanceCapture) -> ExecutionFailureStage:
    if capture.exception_stage is not None:
        return capture.exception_stage
    stages = {event.stage for event in capture.events}
    if ExecutionProvenanceStage.FIXTURE_CLOSE_FAILED in stages:
        return ExecutionFailureStage.FINALIZATION
    if ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED in stages:
        if ExecutionProvenanceStage.PROVIDER_ATTEMPT_RETURNED in stages:
            return ExecutionFailureStage.EXECUTION_RECORDING
        return ExecutionFailureStage.PROVIDER_CALL
    if ExecutionProvenanceStage.GRAPH_EXECUTION_STARTED in stages:
        return ExecutionFailureStage.GRAPH_POSTPROCESS
    if ExecutionProvenanceStage.GRAPH_INITIALIZATION_STARTED in stages:
        return ExecutionFailureStage.GRAPH_INITIALIZATION
    return ExecutionFailureStage.UNKNOWN


def _build_live_execution_unit(
    *,
    candidate_id: str,
    probe: LiveExecutionProbe,
    provider: LLMProvider,
    model: str,
    capture: ExecutionProvenanceCapture,
    state: dict[str, Any] | None,
    duration_ms: float,
    exception: BaseException | None = None,
) -> LiveExecutionUnit:
    """Derive provider and graph outcomes independently from scoped facts."""

    if state is not None and exception is None:
        observe_execution_stage(ExecutionProvenanceStage.POSTPROCESS_STARTED)
        try:
            normalized_state = dict(state)
        except Exception as exc:
            record_execution_exception(ExecutionFailureStage.PROOF_POSTPROCESS, exc)
            exception = exc
            state = None
            normalized_state = None
        if normalized_state is not None:
            observe_execution_stage(ExecutionProvenanceStage.POSTPROCESS_COMPLETED)
            state = normalized_state

    if exception is not None and capture.exception_stage is None:
        record_execution_exception(_exception_stage_for_capture(capture), exception)

    captured_events = tuple(LiveExecutionStageEvent.from_observation(item) for item in capture.events)
    attempts = [
        item for item in capture.events
        if item.stage == ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED
    ]
    observed_pairs = tuple(sorted({
        f"{item.provider.value}:{item.model}"
        for item in attempts
        if item.provider is not None and item.model is not None
    }))
    expected_pair = f"{provider.value}:{model}"
    exact_events = [
        item for item in capture.events
        if item.provider == provider and item.model == model
    ]
    exact_stages = {item.stage for item in exact_events}
    cache_hit = any(item.stage == ExecutionProvenanceStage.CACHE_HIT for item in capture.events)
    call_avoided = any(
        item.stage == ExecutionProvenanceStage.PROVIDER_CALL_AVOIDED
        for item in capture.events
    )
    # The report field is specifically cross-provider fallback. Same-provider
    # retries/attempt metadata remain visible in provenance but do not satisfy it.
    fallback = any(
        item.provider is not None and item.provider != provider
        for item in attempts
    )
    provider_proven = (
        not capture.truncated
        and observed_pairs == (expected_pair,)
        and not fallback
        and not cache_hit
        and not call_avoided
        and {
            ExecutionProvenanceStage.PROVIDER_ATTEMPT_STARTED,
            ExecutionProvenanceStage.PROVIDER_ATTEMPT_RETURNED,
            ExecutionProvenanceStage.PROVIDER_EXECUTION_RECORDED,
        }.issubset(exact_stages)
    )
    provider_status = (
        "EXECUTION_PROVEN" if provider_proven
        else "ATTEMPTED_FAILED" if attempts
        else "NOT_ATTEMPTED"
    )
    state_workflow_failed = bool(state is not None and state.get("status") == "FAILED")
    graph_returned = any(
        item.stage == ExecutionProvenanceStage.GRAPH_RETURNED
        for item in capture.events
    )
    graph_started = any(
        item.stage == ExecutionProvenanceStage.GRAPH_EXECUTION_STARTED
        for item in capture.events
    )
    workflow_status = (
        "COMPLETED" if graph_returned and not state_workflow_failed
        else "FAILED" if graph_started or state_workflow_failed
        else "NOT_STARTED"
    )
    postprocess_started = any(
        item.stage == ExecutionProvenanceStage.POSTPROCESS_STARTED
        for item in capture.events
    )
    postprocess_completed = any(
        item.stage == ExecutionProvenanceStage.POSTPROCESS_COMPLETED
        for item in capture.events
    )
    proof_processing_status = (
        "COMPLETED" if postprocess_completed
        else "FAILED" if postprocess_started
        else "NOT_STARTED"
    )

    failed_attempt = next((
        item for item in reversed(capture.events)
        if item.stage == ExecutionProvenanceStage.PROVIDER_ATTEMPT_FAILED
    ), None)
    attempt_failure = None
    if failed_attempt is not None and failed_attempt.failure_code is not None:
        attempt_failure = (
            "STRUCTURED_OUTPUT_INVALID"
            if failed_attempt.failure_code.value == "INVALID_OUTPUT"
            else failed_attempt.failure_code.value
        )
    failure: str | None = None
    if fallback:
        failure = "CROSS_PROVIDER_FALLBACK"
    elif observed_pairs and observed_pairs != (expected_pair,):
        failure = "PINNED_MODEL_IDENTITY_MISMATCH"
    elif attempt_failure is not None:
        failure = attempt_failure
    elif exception is not None:
        stage = capture.exception_stage or _exception_stage_for_capture(capture)
        failure = {
            ExecutionFailureStage.GRAPH_INITIALIZATION: "GRAPH_INITIALIZATION_FAILURE",
            ExecutionFailureStage.ROUTING: "ROUTING_FAILURE",
            ExecutionFailureStage.PROVIDER_PRECALL: "PROVIDER_PRECALL_FAILURE",
            ExecutionFailureStage.PROVIDER_CALL: "PROVIDER_CALL_FAILURE",
            ExecutionFailureStage.PROVIDER_RESPONSE_VALIDATION: "PROVIDER_RESPONSE_INVALID",
            ExecutionFailureStage.EXECUTION_RECORDING: "EXECUTION_RECORDING_FAILURE",
            ExecutionFailureStage.SPECIALIST_POSTPROCESS: "SPECIALIST_POSTPROCESS_FAILURE",
            ExecutionFailureStage.GRAPH_POSTPROCESS: "GRAPH_POSTPROCESS_FAILURE",
            ExecutionFailureStage.PROOF_POSTPROCESS: "PROOF_POSTPROCESS_FAILURE",
            ExecutionFailureStage.ARTIFACT_VALIDATION: "ARTIFACT_VALIDATION_FAILURE",
            ExecutionFailureStage.FINALIZATION: "FINALIZATION_FAILURE",
            ExecutionFailureStage.UNKNOWN: "WORKFLOW_HARNESS_FAILURE",
        }[stage]
    elif state is not None:
        failure = _safe_failure_code(
            state,
            model_calls=len(attempts),
            identity_ok=provider_proven or observed_pairs == (expected_pair,),
        )
    if failure is None and not provider_proven:
        failure = "MODEL_NOT_INVOKED" if not attempts else "PROVIDER_EXECUTION_NOT_RECORDED"
    if failure is None and workflow_status != "COMPLETED":
        failure = "WORKFLOW_FAILURE_AFTER_PROVIDER_EXECUTION"

    if provider_proven:
        legacy_status = "EXECUTION_PROVEN"
    elif fallback or (observed_pairs and observed_pairs != (expected_pair,)):
        legacy_status = "IDENTITY_MISMATCH"
    elif failure in {"QUOTA_EXHAUSTED", "WORKFLOW_BUDGET_EXHAUSTED"}:
        legacy_status = "BUDGET_FAILURE"
    elif attempts:
        legacy_status = "PROVIDER_FAILURE"
    elif not attempts:
        legacy_status = "MODEL_NOT_INVOKED"
    else:
        legacy_status = "HARNESS_FAILURE"

    return LiveExecutionUnit(
        candidate_id=candidate_id,
        probe_id=probe.probe_id,
        category=probe.category,
        planned_provider=provider,
        planned_model=model,
        status=legacy_status,
        provider_execution_status=provider_status,
        workflow_status=workflow_status,
        proof_processing_status=proof_processing_status,
        model_calls=min(64, len(attempts)),
        observed_model_pairs=observed_pairs,
        cross_provider_fallback=fallback,
        cache_hit=cache_hit,
        provider_call_avoided=call_avoided,
        duration_ms=min(120_000.0, max(0.0, duration_ms)),
        safe_failure_code=failure,
        exception_stage=capture.exception_stage,
        exception_type=capture.exception_type,
        provenance_events=captured_events,
        provenance_truncated=capture.truncated,
    )


def _persist_proof(report: LiveExecutionProofReport) -> Path:
    repository = Path(__file__).resolve().parents[4]
    directory = repository / "backend" / "output" / "live_execution_proofs"
    if directory.is_symlink():
        raise ValueError("execution proof artifact directory cannot be a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{report.proof_id}.json"
    if path.exists() or path.is_symlink():
        raise ValueError("execution proof artifacts are immutable")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(report.model_dump_json(indent=2) + "\n")
    return path


def _validate_and_persist_proof(raw: dict[str, Any]) -> tuple[LiveExecutionProofReport, Path]:
    """Expose artifact-validation and finalization failures as safe stage/type pairs."""

    try:
        report = _validated_proof_report(raw)
    except Exception as exc:
        raise LiveExecutionProofProcessingError(
            stage=ExecutionFailureStage.ARTIFACT_VALIDATION,
            exception_type=type(exc).__name__,
        ) from None
    try:
        artifact = _persist_proof(report)
    except Exception as exc:
        raise LiveExecutionProofProcessingError(
            stage=ExecutionFailureStage.FINALIZATION,
            exception_type=type(exc).__name__,
        ) from None
    return report, artifact


async def run_live_execution_proof(
    models: list[tuple[str, LLMProvider | str, str]],
    *,
    allow_live: bool = False,
    allow_model_campaign: bool = False,
) -> tuple[LiveExecutionProofReport, Path]:
    """Make exactly two capability-compatible execution-only full-graph runs."""
    if not (allow_live and allow_model_campaign):
        raise ValueError("live execution proof requires --allow-live and --allow-model-campaign")
    if len(models) != 2 or len({str(item[0]) for item in models}) != 2:
        raise ValueError("execution proof requires exactly two distinct candidate IDs")
    expected_candidates = {
        (candidate_id, provider, model)
        for candidate_id, (provider, model) in _PLANNED_MODELS.items()
    }
    normalized = [(cid, LLMProvider(provider), model) for cid, provider, model in models]
    if len(normalized) != 2 or set(normalized) != expected_candidates:
        raise ValueError("execution proof only accepts the two explicitly planned Gemini/Groq model identities")
    # Re-run both no-provider qualifications inside the proof command. A
    # caller-supplied, re-digested JSON artifact is not treated as evidence
    # that the current graph naturally reaches these boundaries.
    public_qualification: ModelPathQualificationReport = await qualify_public_dev_model_paths()
    public_security_paths = [
        item.case_id for item in public_qualification.cases
        if item.category == "SECURITY" and item.model_gateway_reached
    ]
    if public_security_paths:
        raise ValueError(
            "canonical public DEV security paths are now model-reachable; use the versioned benchmark smoke path instead"
        )
    if not any(
        item.category == "CORRECTNESS" and item.model_gateway_reached
        for item in public_qualification.cases
    ):
        raise ValueError("canonical public DEV correctness has no model-reaching path")
    probes_qualification = await qualify_live_execution_probe_set()
    probes = load_live_execution_probe_set()
    if not probes_qualification.qualified or probes_qualification.probe_set_digest != probes.digest:
        raise ValueError("both separate execution probes must pass offline path qualification before live calls")
    if probes_qualification.graph_identity_digest != full_analysis_graph_identity_digest():
        raise ValueError("offline probe qualification is stale for the current production graph")
    pinned_route_qualification = await qualify_pinned_model_probe_paths(normalized)
    if not pinned_route_qualification.qualified:
        blocked = [
            f"{item.candidate_id}/{item.category}"
            for item in pinned_route_qualification.route_results
            if not item.model_gateway_reached
        ]
        raise ValueError(
            "pinned candidate routes failed offline model-boundary qualification for: "
            + ", ".join(blocked)
            + "; no live provider workflows were started"
        )

    from app.evaluation.campaign.preflight import run_campaign_preflight

    preflight = run_campaign_preflight(normalized)
    accepted_statuses = {"READY", "READY_WITH_CAPABILITY_WARNINGS"}
    if any(item.status not in accepted_statuses or not item.credential_configured for item in preflight.candidate_readiness):
        raise ValueError("a pinned model is not technically ready; no live execution was attempted")

    system_digests: dict[str, str] = {}
    identity_fixture = FullAnalysisFixture(probes.probes[0].analysis_input)
    try:
        await identity_fixture.initialize_runtime()
        for candidate_id, provider, model in normalized:
            identity = build_agent_system_identity(
                provider=provider,
                model=model,
                registry=identity_fixture.registry,
                scope="FULL_ANALYSIS_GRAPH",
            )
            system_digests[candidate_id] = identity.system_digest
    finally:
        identity_fixture.close()

    from app.evaluation.campaign.plan import _git_head
    from app.evaluation.campaign.runner import _git_state

    source_revision, dirty = _git_state()
    if source_revision != _git_head():
        raise ValueError("source revision changed while freezing execution proof identity")
    source_digest = _source_binding_digest()
    units: list[LiveExecutionUnit] = []
    probes_by_id = {probe.probe_id: probe for probe in probes.probes}
    routes_by_candidate = {row.candidate_id: row for row in pinned_route_qualification.route_results}
    for candidate_id, provider, model in sorted(normalized, key=lambda item: item[0]):
        route = routes_by_candidate[candidate_id]
        probe = probes_by_id[route.probe_id]
        started = time.perf_counter()
        with capture_execution_provenance() as capture:
            observe_execution_stage(ExecutionProvenanceStage.PROOF_UNIT_STARTED)
            state: dict[str, Any] | None = None
            exception: BaseException | None = None
            try:
                state, _, _, _ = await asyncio.wait_for(
                    _execute_trial(
                        probe.analysis_input,
                        mode=SystemEvalMode.LIVE,
                        provider=provider,
                        model=model,
                        evaluation_case_id=probe.probe_id,
                        presentation_stage="LIVE_EXECUTION_PROOF_ONLY",
                    ),
                    timeout=120.0,
                )
            except TimeoutError as exc:
                exception = exc
                record_execution_exception(_exception_stage_for_capture(capture), exc)
            except Exception as exc:
                exception = exc
                record_execution_exception(_exception_stage_for_capture(capture), exc)
            try:
                unit = _build_live_execution_unit(
                    candidate_id=candidate_id,
                    probe=probe,
                    provider=provider,
                    model=model,
                    capture=capture,
                    state=state,
                    duration_ms=(time.perf_counter() - started) * 1000.0,
                    exception=exception,
                )
            except Exception as exc:
                # Preserve already observed provider facts even if proof-unit
                # post-processing itself fails. Never serialize exception text.
                record_execution_exception(ExecutionFailureStage.PROOF_POSTPROCESS, exc, replace=True)
                unit = _build_live_execution_unit(
                    candidate_id=candidate_id,
                    probe=probe,
                    provider=provider,
                    model=model,
                    capture=capture,
                    state=None,
                    duration_ms=(time.perf_counter() - started) * 1000.0,
                    exception=exc,
                )
            units.append(unit)

    pairs = tuple(sorted(f"{provider.value}:{model}" for _, provider, model in normalized))
    results = tuple(units)
    proven = all(unit.status == "EXECUTION_PROVEN" for unit in results)
    raw = {
        "schema_version": LIVE_EXECUTION_PROOF_SCHEMA_VERSION,
        "proof_id": uuid4().hex,
        "created_at": datetime.now(timezone.utc),
        "source_revision": source_revision,
        "source_binding_digest": source_digest,
        "dirty_worktree": dirty,
        "probe_set_version": probes.version,
        "probe_set_digest": probes.digest,
        "public_dev_qualification_digest": public_qualification.report_digest,
        "public_dev_dataset_digest": public_qualification.dataset_digest,
        "pinned_route_qualification_digest": pinned_route_qualification.qualification_digest,
        "public_dev_case_count": public_qualification.public_dev_case_count,
        "public_dev_correctness_model_paths": sum(
            item.category == "CORRECTNESS" and item.model_gateway_reached
            for item in public_qualification.cases
        ),
        "public_dev_security_model_paths": 0,
        "qualification_digest": probes_qualification.qualification_digest,
        "graph_identity_digest": full_analysis_graph_identity_digest(),
        "system_identity_digests": dict(sorted(system_digests.items())),
        "planned_model_pairs": pairs,
        "provider_preflight_statuses": {
            item.candidate_id: item.status for item in sorted(preflight.candidate_readiness, key=lambda item: item.candidate_id)
        },
        "mode": "LIVE_EXECUTION_PROOF_ONLY",
        "quality_metrics": "NOT_APPLICABLE",
        "workflow_units": results,
        "status": "LIVE_EXECUTION_PROVEN" if proven else "LIVE_EXECUTION_NOT_PROVEN",
    }
    return _validate_and_persist_proof(raw)


__all__ = [
    "LIVE_EXECUTION_PROOF_SCHEMA_VERSION",
    "LIVE_EXECUTION_PROBE_SET_VERSION",
    "LiveExecutionProbe",
    "LiveExecutionProbeSet",
    "LiveExecutionProbeQualification",
    "PinnedModelProbePath",
    "PinnedModelRouteQualification",
    "LiveExecutionProofReport",
    "load_live_execution_probe_set",
    "qualify_live_execution_probe_set",
    "qualify_pinned_model_probe_paths",
    "run_live_execution_proof",
]
