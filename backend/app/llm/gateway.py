"""Capability-driven, budget-first AI Gateway with sequential escalation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
import time
from typing import Callable, Mapping
from uuid import uuid4

from app.llm.base import BaseLLMAdapter
from app.llm.capabilities import ModelCapabilityRegistry, RoutingPolicy
from app.llm.context import ContextEstimator
from app.llm.exceptions import (
    LLMAllFallbacksFailedError,
    LLMContextLimitError,
    LLMError,
    LLMProviderUnavailableError,
    LLMQuotaExhaustedError,
    LLMResponseValidationError,
    ProviderFailureCode,
)
from app.llm.economy import current_workflow_cloud_budget
from app.llm.execution import AIExecutionRecorder
from app.llm.health import ProviderHealth, ProviderHealthRegistry
from app.llm.quota import LocalProviderQuotaLedger, ProviderQuotaLedger
from app.llm.structured import StructuredOutputGateway
from app.llm.types import (
    AIValidationResult,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
    ModelCostTier,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AIRoutingLimits:
    max_cost_tier: ModelCostTier
    disabled_providers: frozenset[LLMProvider] = frozenset()
    disabled_models: frozenset[str] = frozenset()


class CapabilityAIGateway:
    """One bounded sequential model chain; no voting and no parallel provider fan-out."""

    def __init__(
        self,
        adapters: Mapping[LLMProvider, BaseLLMAdapter],
        *,
        registry: ModelCapabilityRegistry | None = None,
        routing_policy: RoutingPolicy | None = None,
        health: ProviderHealth | None = None,
        quota: ProviderQuotaLedger | None = None,
        recorder: AIExecutionRecorder | None = None,
        context_estimator: ContextEstimator | None = None,
        structured_gateway: StructuredOutputGateway | None = None,
        policy_resolver: Callable[[str | None], AIRoutingLimits] | None = None,
        max_retries: int = 2,
    ) -> None:
        self.adapters = adapters
        self.registry = registry or ModelCapabilityRegistry.from_settings()
        self.routing_policy = routing_policy or RoutingPolicy(self.registry)
        self.health = health or ProviderHealthRegistry()
        self.quota = quota or LocalProviderQuotaLedger()
        self.recorder = recorder or AIExecutionRecorder()
        self.context_estimator = context_estimator or ContextEstimator()
        self.structured_gateway = structured_gateway or StructuredOutputGateway()
        self.policy_resolver = policy_resolver
        self.max_retries = max(0, max_retries)
        # Public free inference endpoints commonly enforce very small burst
        # limits.  Keep unrelated endpoints concurrent while ensuring one
        # process never fans out simultaneous calls to the same free endpoint.
        self._free_endpoint_locks: dict[tuple[LLMProvider, str], asyncio.Lock] = {}

    def reconcile_expired_quota(self, *, limit: int = 500) -> int:
        """Release durable provider reservations abandoned by crashed workers."""
        return self.quota.reconcile_expired(limit=limit)

    async def generate(self, request: LLMRequest) -> LLMResponse:
        if request.capability is None:
            raise ValueError("CapabilityAIGateway requires request.capability")
        estimate = self.context_estimator.estimate(request)
        if estimate.input_tokens > request.budget.max_input_tokens:
            raise LLMContextLimitError("Estimated input exceeds the request input-token budget.")
        if estimate.total_tokens > request.budget.max_context_tokens:
            raise LLMContextLimitError("Estimated request exceeds the configured context budget.")

        runtime_limits = (
            await asyncio.to_thread(self.policy_resolver, request.lineage.policy_snapshot_id)
            if self.policy_resolver is not None
            else AIRoutingLimits(max_cost_tier=request.budget.max_escalation_tier)
        )
        effective_tier = ModelCostTier(
            min(request.budget.max_escalation_tier.value, runtime_limits.max_cost_tier.value)
        )
        candidates = self.routing_policy.candidates(
            request.capability,
            max_cost_tier=effective_tier,
            required_context_tokens=estimate.total_tokens,
            structured_output=request.json_mode or request.output_schema is not None,
        )
        candidates = tuple(
            item
            for item in candidates
            if item.provider not in set(request.excluded_providers)
            and item.provider not in runtime_limits.disabled_providers
            and item.model not in set(request.excluded_models)
            and item.model not in runtime_limits.disabled_models
        )
        if request.provider is not None:
            candidates = tuple(
                item for item in candidates
                if item.provider == request.provider and (request.model is None or item.model == request.model)
            )
        elif request.model is not None:
            candidates = tuple(item for item in candidates if item.model == request.model)
        if not candidates:
            raise LLMContextLimitError(
                f"No enabled model satisfies capability {request.capability.value} within the request budget."
            )

        attempted: list[LLMError] = []
        call_count = 0
        parent_execution_id = request.lineage.parent_execution_id
        best_uncertain_response: LLMResponse | None = None
        best_uncertain_confidence = -1.0
        cloud_budget_exhausted = False
        workflow_budget = current_workflow_cloud_budget()
        effective_retries = 0 if workflow_budget is not None and workflow_budget.strict else self.max_retries
        for candidate_index, candidate in enumerate(candidates):
            if not self.health.allow_request(candidate.provider, candidate.model):
                attempted.append(LLMProviderUnavailableError(
                    "Provider/model circuit is open.", provider=candidate.provider, model=candidate.model
                ))
                continue
            adapter = self.adapters.get(candidate.provider)
            if adapter is None:
                attempted.append(LLMProviderUnavailableError(
                    "No configured adapter is available.", provider=candidate.provider, model=candidate.model
                ))
                continue

            for retry_number in range(effective_retries + 1):
                if call_count >= request.budget.max_ai_calls:
                    attempted.append(LLMQuotaExhaustedError("The request AI-call budget was exhausted."))
                    break
                call_count += 1
                from app.execution.context import consume_current_budget
                from app.execution.types import BudgetConsumption

                reserved_output_tokens = min(
                    estimate.requested_output_tokens,
                    candidate.max_output_tokens,
                    request.budget.max_output_tokens,
                )
                allowed = await asyncio.to_thread(
                    consume_current_budget,
                    BudgetConsumption(
                        ai_calls=1,
                        input_tokens=estimate.input_tokens,
                        output_tokens=reserved_output_tokens,
                        escalation_tier=candidate.cost_tier.value,
                    ),
                    coverage_explanation=(
                        "AI reasoning stopped at its explicit request budget; deterministic results remain available."
                    ),
                )
                if not allowed:
                    budget_error = LLMQuotaExhaustedError(
                        "The durable work-item AI budget was exhausted.",
                        provider=candidate.provider,
                        model=candidate.model,
                    )
                    if best_uncertain_response is not None:
                        attempted.append(budget_error)
                        return self._retained_uncertain_response(
                            best_uncertain_response,
                            attempted=attempted,
                            reason="escalation_budget_exhausted",
                        )
                    raise budget_error
                execution_id = str(uuid4())
                reservation = self.quota.reserve(
                    execution_id=execution_id,
                    provider=candidate.provider,
                    model=candidate.model,
                    request_id=request.lineage.request_id,
                    tenant_id=request.lineage.tenant_id,
                    estimated_input_tokens=estimate.input_tokens,
                    estimated_output_tokens=reserved_output_tokens,
                )
                if reservation is None:
                    attempted.append(LLMQuotaExhaustedError(
                        "Provider/model quota could not reserve this attempt.",
                        provider=candidate.provider,
                        model=candidate.model,
                    ))
                    break

                if workflow_budget is not None and not workflow_budget.reserve(
                    candidate.provider,
                    input_tokens=estimate.input_tokens,
                    output_tokens=reserved_output_tokens,
                ):
                    self.quota.settle(
                        reservation,
                        consume=False,
                        actual_input_tokens=None,
                        actual_output_tokens=None,
                    )
                    attempted.append(LLMQuotaExhaustedError(
                        "The workflow cloud-use budget was exhausted; deterministic results remain available.",
                        provider=candidate.provider,
                        model=candidate.model,
                    ))
                    cloud_budget_exhausted = True
                    break

                attempt_request = request.model_copy(update={
                    "provider": candidate.provider,
                    "model": candidate.model,
                    "max_tokens": min(
                        request.max_tokens or estimate.requested_output_tokens,
                        candidate.max_output_tokens,
                        request.budget.max_output_tokens,
                    ),
                    "lineage": request.lineage.model_copy(update={"parent_execution_id": parent_execution_id}),
                })
                started = time.monotonic()
                try:
                    if candidate.cost_tier == ModelCostTier.FREE:
                        endpoint_lock = self._free_endpoint_locks.setdefault(
                            (candidate.provider, candidate.model),
                            asyncio.Lock(),
                        )
                        async with endpoint_lock:
                            started = time.monotonic()
                            response = await adapter.generate(attempt_request)
                    else:
                        started = time.monotonic()
                        response = await adapter.generate(attempt_request)
                    latency_ms = max(0.0, (time.monotonic() - started) * 1000.0)
                    validation = AIValidationResult.NOT_REQUESTED
                    uncertain = False
                    confidence: float | None = None
                    if attempt_request.json_mode or attempt_request.output_schema is not None:
                        structured = self.structured_gateway.validate(
                            response.content,
                            schema=attempt_request.output_schema,
                            confidence_threshold=attempt_request.confidence_threshold,
                            provider=candidate.provider,
                            model=candidate.model,
                        )
                        validation = structured.result
                        uncertain = structured.result == AIValidationResult.UNCERTAIN
                        confidence = structured.confidence

                    input_tokens = response.metadata.prompt_tokens
                    output_tokens = response.metadata.completion_tokens
                    self.quota.settle(
                        reservation,
                        consume=True,
                        actual_input_tokens=input_tokens,
                        actual_output_tokens=output_tokens,
                    )
                    self.health.record_success(candidate.provider, candidate.model)
                    can_escalate = (
                        uncertain
                        and request.allow_escalation
                        and candidate_index + 1 < len(candidates)
                        and call_count < request.budget.max_ai_calls
                    )
                    record = self.recorder.record(
                        execution_id=execution_id,
                        sequence=call_count,
                        request=attempt_request,
                        capability=request.capability,
                        provider=candidate.provider,
                        model=candidate.model,
                        model_revision=candidate.model_revision,
                        estimated_input_tokens=estimate.input_tokens,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        latency_ms=latency_ms,
                        validation_result=validation,
                        success=True,
                        failure_code=None,
                        fallback_reason="prior_candidate_failed" if attempted else None,
                        escalation_reason="confidence_below_threshold" if can_escalate else None,
                        quota_reservation_id=reservation.reservation_id,
                        output=response.content,
                        routing_policy_version=self.routing_policy.version,
                        model_registry_version=self.registry.version,
                    )
                    parent_execution_id = record.execution_id
                    extra = dict(response.metadata.extra_metadata or {})
                    extra.update({
                        "ai_execution_id": record.execution_id,
                        "capability": request.capability.value,
                        "cost_tier": candidate.cost_tier.name,
                        "model_registry_version": self.registry.version,
                        "routing_policy_version": self.routing_policy.version,
                        "retry_count": retry_number,
                        "fallbacks_attempted": [
                            {
                                "provider": error.provider.value if error.provider else "gateway",
                                "model": error.model,
                                "failure_code": error.failure_code.value,
                            }
                            for error in attempted
                        ],
                    })
                    response.metadata.extra_metadata = extra
                    if uncertain:
                        confidence_score = confidence if confidence is not None else -1.0
                        if (
                            best_uncertain_response is None
                            or confidence_score > best_uncertain_confidence
                        ):
                            best_uncertain_response = response
                            best_uncertain_confidence = confidence_score
                    if can_escalate:
                        break
                    if uncertain and best_uncertain_response is not None:
                        return self._retained_uncertain_response(
                            best_uncertain_response,
                            attempted=attempted,
                            reason=(
                                "escalation_not_allowed"
                                if not request.allow_escalation
                                else (
                                    "escalation_candidates_exhausted"
                                    if candidate_index + 1 >= len(candidates)
                                    else "escalation_budget_exhausted"
                                )
                            ),
                        )
                    return response
                except LLMError as exc:
                    latency_ms = max(0.0, (time.monotonic() - started) * 1000.0)
                    self.quota.settle(
                        reservation,
                        consume=True,
                        actual_input_tokens=None,
                        actual_output_tokens=None,
                    )
                    self.health.record_failure(
                        candidate.provider,
                        candidate.model,
                        exc.failure_code,
                        retry_after_seconds=getattr(exc, "retry_after_seconds", None),
                    )
                    self.recorder.record(
                        execution_id=execution_id,
                        sequence=call_count,
                        request=attempt_request,
                        capability=request.capability,
                        provider=candidate.provider,
                        model=candidate.model,
                        model_revision=candidate.model_revision,
                        estimated_input_tokens=estimate.input_tokens,
                        input_tokens=None,
                        output_tokens=None,
                        latency_ms=latency_ms,
                        validation_result=(
                            AIValidationResult.INVALID
                            if isinstance(exc, LLMResponseValidationError)
                            else AIValidationResult.NOT_REQUESTED
                        ),
                        success=False,
                        failure_code=exc.failure_code,
                        fallback_reason="prior_candidate_failed" if attempted else None,
                        escalation_reason=None,
                        quota_reservation_id=reservation.reservation_id,
                        output=None,
                        routing_policy_version=self.routing_policy.version,
                        model_registry_version=self.registry.version,
                    )
                    attempted.append(exc)
                    reserve_escalation_slot = (
                        request.allow_escalation and candidate_index + 1 < len(candidates)
                    )
                    retry_call_limit = request.budget.max_ai_calls - int(reserve_escalation_slot)
                    if (
                        exc.retryable
                        and retry_number < effective_retries
                        and call_count < retry_call_limit
                    ):
                        await asyncio.sleep(min(2.0, 0.2 * (2 ** retry_number)))
                        continue
                    break
                except Exception as exc:
                    latency_ms = max(0.0, (time.monotonic() - started) * 1000.0)
                    self.quota.settle(
                        reservation,
                        consume=True,
                        actual_input_tokens=None,
                        actual_output_tokens=None,
                    )
                    normalized = LLMError(
                        "Unexpected provider execution failure.",
                        provider=candidate.provider,
                        model=candidate.model,
                        retryable=False,
                        failure_code=ProviderFailureCode.UNKNOWN,
                    )
                    self.health.record_failure(
                        candidate.provider,
                        candidate.model,
                        normalized.failure_code,
                    )
                    self.recorder.record(
                        execution_id=execution_id,
                        sequence=call_count,
                        request=attempt_request,
                        capability=request.capability,
                        provider=candidate.provider,
                        model=candidate.model,
                        model_revision=candidate.model_revision,
                        estimated_input_tokens=estimate.input_tokens,
                        input_tokens=None,
                        output_tokens=None,
                        latency_ms=latency_ms,
                        validation_result=AIValidationResult.NOT_REQUESTED,
                        success=False,
                        failure_code=normalized.failure_code,
                        fallback_reason="prior_candidate_failed" if attempted else None,
                        escalation_reason=None,
                        quota_reservation_id=reservation.reservation_id,
                        output=None,
                        routing_policy_version=self.routing_policy.version,
                        model_registry_version=self.registry.version,
                    )
                    attempted.append(normalized)
                    logger.exception("Unexpected AI gateway error: %s", type(exc).__name__)
                    break

            if cloud_budget_exhausted:
                break

        if best_uncertain_response is not None:
            return self._retained_uncertain_response(
                best_uncertain_response,
                attempted=attempted,
                reason="stronger_escalation_failed",
            )

        summary = "; ".join(
            f"{error.provider.value if error.provider else 'gateway'}:{error.failure_code.value}"
            for error in attempted
        )
        raise LLMAllFallbacksFailedError(
            f"All sequential candidates for capability {request.capability.value} failed ({summary}).",
            attempted_errors=attempted,
        )

    @staticmethod
    def _retained_uncertain_response(
        response: LLMResponse,
        *,
        attempted: list[LLMError],
        reason: str,
    ) -> LLMResponse:
        """Return schema-valid evidence when optional escalation cannot improve it."""
        extra = dict(response.metadata.extra_metadata or {})
        extra.update(
            {
                "uncertain_response_retained": True,
                "escalation_outcome": reason,
                "fallbacks_attempted": [
                    {
                        "provider": error.provider.value if error.provider else "gateway",
                        "model": error.model,
                        "failure_code": error.failure_code.value,
                    }
                    for error in attempted
                ],
            }
        )
        response.metadata.extra_metadata = extra
        return response
