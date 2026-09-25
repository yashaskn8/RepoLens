"""Offline qualification of natural model reachability in the production graph.

This is execution-path evidence only. It neither scores findings nor supplies a
model response, and its public-DEV inventory is the same closed inventory used
by the full-analysis evaluator.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from app.evaluation.campaign.contracts import CampaignModel, canonical_digest
from app.evaluation.ground_truth.loader import compute_canonical_benchmark_hash
from app.evaluation.ground_truth.leakage import LeakageDetector
from app.evaluation.ground_truth.public_dev import load_public_dev_repository_cases
from app.evaluation.system.full_analysis import _execute_trial
from app.evaluation.system.identity import full_analysis_graph_identity_digest
from app.evaluation.system.schemas import SystemEvalMode
from app.llm.cache import AIResponseCache
from app.llm.execution import AIExecutionRecorder
from app.llm.gateway import CapabilityAIGateway
from app.llm.health import ProviderHealthRegistry
from app.llm.quota import LocalProviderQuotaLedger
from app.llm.router import LLMRouter, get_llm_router
from app.llm.types import LLMProvider, LLMRequest
from app.schemas.metadata import ModelExecutionMetadata


PATH_QUALIFICATION_SCHEMA_VERSION = "offline-llm-path-qualification/1.0"
_PUBLIC_DEV_CASE_COUNT = 35
_QUALIFICATION_TIMEOUT_SECONDS = 90.0


class GatewayBoundaryReached(BaseException):
    """Sentinel raised immediately before a provider adapter could perform I/O."""

    def __init__(self, observation: "ModelBoundaryObservation") -> None:
        super().__init__("offline model gateway boundary reached")
        self.observation = observation


@dataclass(frozen=True, slots=True)
class ModelBoundaryObservation:
    provider: str
    model: str
    capability: str | None
    task_policy: str | None
    prompt_version: str
    node: str | None


class ModelPathQualificationCase(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=128)
    category: Literal["CORRECTNESS", "SECURITY"]
    target_pipeline: Literal["REPOSITORY_SCAN"]
    model_gateway_reached: bool
    first_model_node: str | None = Field(default=None, max_length=64)
    pre_model_terminal_reason: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def validate_reachability(self) -> "ModelPathQualificationCase":
        if self.model_gateway_reached:
            if self.pre_model_terminal_reason is not None:
                raise ValueError("reached cases cannot have a pre-model terminal reason")
        elif self.first_model_node is not None or self.pre_model_terminal_reason is None:
            raise ValueError("unreached cases require a terminal reason and no model node")
        return self


class ModelPathQualificationReport(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["offline-llm-path-qualification/1.0"] = PATH_QUALIFICATION_SCHEMA_VERSION
    dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_dev_case_count: int = Field(ge=35, le=35)
    external_provider_calls: Literal[0] = 0
    provider_boundary_interceptions: int = Field(ge=0, le=35)
    cases: tuple[ModelPathQualificationCase, ...] = Field(min_length=35, max_length=35)
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_report(self) -> "ModelPathQualificationReport":
        ids = [item.case_id for item in self.cases]
        if len(ids) != len(set(ids)) or ids != sorted(ids):
            raise ValueError("qualification cases must be unique and in canonical order")
        if sum(item.model_gateway_reached for item in self.cases) != self.provider_boundary_interceptions:
            raise ValueError("gateway interception count does not match qualified cases")
        payload = self.model_dump(mode="json", exclude={"report_digest"})
        if canonical_digest(payload) != self.report_digest:
            raise ValueError("offline path qualification report digest mismatch")
        return self


class _UnavailableCacheStore:
    """Cache store that cannot return or persist any value during qualification."""

    @property
    def is_available(self) -> bool:
        return False

    async def get(self, key: str, namespace: str = "cache") -> None:
        del key, namespace
        return None

    async def set(self, key: str, value: Any, ttl: int | None = None, namespace: str = "cache") -> bool:
        del key, value, ttl, namespace
        return False


class _OfflineBoundaryAdapter:
    """Preserves adapter identity while making provider I/O impossible."""

    def __init__(self, provider: LLMProvider, recorder: "_BoundaryRecorder") -> None:
        self._provider = provider
        self._recorder = recorder

    @property
    def provider(self) -> LLMProvider:
        return self._provider

    async def generate(self, request: LLMRequest) -> Any:
        observation = ModelBoundaryObservation(
            provider=self._provider.value,
            model=request.model or "",
            capability=request.capability.value if request.capability else None,
            task_policy=request.task_policy.value if request.task_policy else None,
            prompt_version=request.lineage.prompt_template_version,
            node=_node_for_prompt_version(request.lineage.prompt_template_version),
        )
        self._recorder.record(observation)
        raise GatewayBoundaryReached(observation)


class _BoundaryRecorder:
    def __init__(self) -> None:
        self.observations: list[ModelBoundaryObservation] = []

    def record(self, observation: ModelBoundaryObservation) -> None:
        self.observations.append(observation)


def _node_for_prompt_version(version: str) -> str | None:
    prefixes = (
        ("architecture-agent/", "architecture"),
        ("integration-agent/", "integration"),
        ("security-agent/", "security"),
        ("bug-agent/", "bug"),
        ("finding-verifier/", "verifier"),
        ("evidence-investigator/", "investigator_decide"),
        ("revision-agent/", "revise"),
    )
    return next((node for prefix, node in prefixes if version.startswith(prefix)), None)


def _offline_router(recorder: _BoundaryRecorder) -> LLMRouter:
    """Create the canonical router/gateway with zero-I/O adapter sentinels.

    Registry, routing policy, provider-health behavior, and candidate adapters
    come from the current canonical router. Cache and quota state are isolated
    so a qualification cannot reuse prior answers or consume persisted quota.
    """
    canonical = get_llm_router()
    source_gateway = canonical._capability_gateway
    adapters = {
        provider: _OfflineBoundaryAdapter(provider, recorder)
        for provider in canonical._adapters
    }
    gateway = CapabilityAIGateway(
        adapters,
        registry=source_gateway.registry,
        routing_policy=source_gateway.routing_policy,
        health=ProviderHealthRegistry(),
        quota=LocalProviderQuotaLedger(),
        recorder=AIExecutionRecorder(),
        context_estimator=source_gateway.context_estimator,
        structured_gateway=source_gateway.structured_gateway,
        policy_resolver=source_gateway.policy_resolver,
        max_retries=0,
    )
    return LLMRouter(
        adapters=adapters,
        capability_gateway=gateway,
        response_cache=AIResponseCache(store=_UnavailableCacheStore()),
    )


def _sentinel_from(error: BaseException) -> GatewayBoundaryReached | None:
    if isinstance(error, GatewayBoundaryReached):
        return error
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            found = _sentinel_from(nested)
            if found is not None:
                return found
    return None


def _pre_model_terminal_reason(state: dict[str, Any]) -> str:
    budget = state.get("ai_cloud_budget")
    if isinstance(budget, dict) and budget.get("exhausted") is True:
        return "BUDGET_EXHAUSTED"
    if state.get("status") == "FAILED":
        trace = state.get("workflow_trace", [])
        trace = trace if isinstance(trace, list) else []
        failure_codes = [
            str(code)
            for event in trace if isinstance(event, dict)
            for code in event.get("failure_codes", [])[:4]
        ]
        if "BUDGET_EXHAUSTION" in failure_codes:
            return "BUDGET_EXHAUSTED"
        return "WORKFLOW_FAILED"
    return "DETERMINISTIC_TERMINAL"


async def _qualify_analysis_input(
    analysis_input: Any,
    *,
    case_id: str,
    category: Literal["CORRECTNESS", "SECURITY"],
    target_pipeline: str = "REPOSITORY_SCAN",
    provider: LLMProvider | None = None,
    model: str = "offline-path-qualification",
) -> ModelPathQualificationCase:
    recorder = _BoundaryRecorder()
    router = _offline_router(recorder)
    try:
        state, _, _, _ = await asyncio.wait_for(
            _execute_trial(
                analysis_input,
                mode=SystemEvalMode.LIVE if provider is not None else SystemEvalMode.SCRIPTED,
                provider=provider,
                model=model,
                llm_router_override=router,
                evaluation_case_id=case_id,
            ),
            timeout=_QUALIFICATION_TIMEOUT_SECONDS,
        )
    except BaseException as exc:
        reached = _sentinel_from(exc)
        if reached is None:
            raise
        node = reached.observation.node
        result = ModelPathQualificationCase(
            case_id=case_id,
            category=category,
            target_pipeline=target_pipeline,
            model_gateway_reached=True,
            first_model_node=node,
        )
        return result

    if recorder.observations:
        raise RuntimeError("a model gateway interception was swallowed by the production graph")
    result = ModelPathQualificationCase(
        case_id=case_id,
        category=category,
        target_pipeline=target_pipeline,
        model_gateway_reached=False,
        pre_model_terminal_reason=_pre_model_terminal_reason(state),
    )
    return result


async def _qualify_case(case: Any) -> tuple[ModelPathQualificationCase, int]:
    from app.evaluation.ground_truth.schemas import BenchmarkCategory

    if case.category not in {BenchmarkCategory.CORRECTNESS, BenchmarkCategory.SECURITY}:
        raise ValueError("the fixed public DEV inventory contains an unsupported qualification category")
    result = await _qualify_analysis_input(
        LeakageDetector.bifurcate_input(case),
        case_id=case.case_id,
        category="SECURITY" if case.category == BenchmarkCategory.SECURITY else "CORRECTNESS",
        target_pipeline=case.target_pipeline.value,
    )
    return result, int(result.model_gateway_reached)


async def qualify_public_dev_model_paths() -> ModelPathQualificationReport:
    """Run the actual FULL_ANALYSIS_GRAPH over all fixed public DEV cases.

    The evaluator annotations are stripped before fixture construction. A
    sentinel at the selected adapter boundary raises without supplying a fake
    response, which prevents downstream routing from depending on a mock.
    """
    cases = load_public_dev_repository_cases()
    if len(cases) != _PUBLIC_DEV_CASE_COUNT:
        raise ValueError("offline qualification requires the exact fixed 35-case public DEV inventory")
    if any(case.target_pipeline.value != "REPOSITORY_SCAN" for case in cases):
        raise ValueError("offline qualification only supports the fixed repository-scan pipeline")

    results: list[ModelPathQualificationCase] = []
    interceptions = 0
    for case in cases:
        result, count = await _qualify_case(case)
        results.append(result)
        interceptions += count

    results.sort(key=lambda item: item.case_id)
    payload = {
        "schema_version": PATH_QUALIFICATION_SCHEMA_VERSION,
        "dataset_digest": compute_canonical_benchmark_hash(cases),
        "graph_identity_digest": full_analysis_graph_identity_digest(),
        "public_dev_case_count": len(cases),
        "external_provider_calls": 0,
        "provider_boundary_interceptions": sum(item.model_gateway_reached for item in results),
        "cases": [item.model_dump(mode="json") for item in results],
    }
    if interceptions != payload["provider_boundary_interceptions"]:
        raise RuntimeError("gateway intercept accounting differs from case-level reachability")
    return ModelPathQualificationReport(**payload, report_digest=canonical_digest(payload))


__all__ = [
    "GatewayBoundaryReached",
    "ModelBoundaryObservation",
    "ModelPathQualificationCase",
    "ModelPathQualificationReport",
    "PATH_QUALIFICATION_SCHEMA_VERSION",
    "_qualify_analysis_input",
    "qualify_public_dev_model_paths",
]
