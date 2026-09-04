"""Canonical LLMRouter orchestrating task policy dispatch, provider adapters, and fallback execution."""

import logging
import random
from typing import Callable, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.llm.adapters import (
    CloudflareAdapter,
    GeminiAdapter,
    GroqAdapter,
    HuggingFaceAdapter,
    MistralAdapter,
    NvidiaAdapter,
    OllamaAdapter,
    OpenRouterAdapter,
)
from app.llm.base import BaseLLMAdapter
from app.llm.cache import AIResponseCache, SingleFlight
from app.llm.classifier import TaskCategory, TaskClassifier
from app.llm.exceptions import (
    LLMAllFallbacksFailedError,
    LLMError,
    LLMRateLimitError,
    ProviderFailureCode,
)
from app.llm.gateway import CapabilityAIGateway
from app.llm.health import ProviderHealthRegistry
from app.llm.types import LLMProvider, LLMRequest, LLMResponse, ModelCapability, TaskPolicy

logger = logging.getLogger(__name__)


def _calculate_retry_delay(
    attempt: int,
    exc: Optional[LLMError] = None,
    max_delay: float = 2.0,
) -> float:
    """Calculate bounded exponential backoff delay with random jitter.

    If exc is LLMRateLimitError with retry_after_seconds, uses that as base delay.
    Otherwise uses exponential backoff: min(0.2 * (2 ** attempt), max_delay).
    Applies bounded jitter up to min(base_delay * 0.25, 0.25) while strictly capping total delay at max_delay.
    """
    if isinstance(exc, LLMRateLimitError) and exc.retry_after_seconds is not None and exc.retry_after_seconds > 0:
        base_delay = min(exc.retry_after_seconds, max_delay)
    else:
        base_delay = min(0.2 * (2 ** attempt), max_delay)

    max_jitter = min(base_delay * 0.25, 0.25)
    jitter = random.uniform(0.0, max_jitter) if max_jitter > 0 else 0.0
    return min(base_delay + jitter, max_delay)


class LLMRouter:
    """Canonical LLM Gateway Router.
    
    Dispatches LLM requests based on task classification and policies to designated primary models and
    automatically executes fallback routes on provider failures or timeouts without model voting.
    """

    def __init__(
        self,
        adapters: Optional[Dict[LLMProvider, BaseLLMAdapter]] = None,
        capability_gateway: Optional[CapabilityAIGateway] = None,
        health: Optional[ProviderHealthRegistry] = None,
        response_cache: Optional[AIResponseCache] = None,
        singleflight: Optional[SingleFlight[LLMResponse]] = None,
    ):
        self._health = health or ProviderHealthRegistry()
        self._adapters: Dict[LLMProvider, BaseLLMAdapter] = adapters or {
            LLMProvider.GEMINI: GeminiAdapter(),
            LLMProvider.GROQ: GroqAdapter(),
            LLMProvider.NVIDIA: NvidiaAdapter(),
            LLMProvider.HUGGINGFACE: HuggingFaceAdapter(),
            LLMProvider.CLOUDFLARE: CloudflareAdapter(),
            LLMProvider.MISTRAL: MistralAdapter(),
            LLMProvider.OPENROUTER: OpenRouterAdapter(),
            LLMProvider.OLLAMA: OllamaAdapter(),
        }
        self._capability_gateway = capability_gateway or CapabilityAIGateway(
            self._adapters,
            max_retries=max(0, get_settings().LLM_MAX_RETRIES),
            health=self._health,
        )
        self._response_cache = response_cache or AIResponseCache()
        self._singleflight = singleflight or SingleFlight[LLMResponse](
            max_entries=get_settings().AI_SINGLEFLIGHT_MAX_ENTRIES
        )

    def get_adapter(self, provider: LLMProvider) -> BaseLLMAdapter:
        """Retrieve registered adapter for a given provider."""
        if provider not in self._adapters:
            raise ValueError(f"No adapter registered for provider: {provider}")
        return self._adapters[provider]

    def register_adapter(self, provider: LLMProvider, adapter: BaseLLMAdapter) -> None:
        """Register or override an adapter (useful for testing and mocks)."""
        self._adapters[provider] = adapter

    def reconcile_expired_quota(self, *, limit: int = 500) -> int:
        """Reclaim provider allowance reserved by attempts that never settled."""
        return self._capability_gateway.reconcile_expired_quota(limit=limit)

    def get_policy_routes(self, policy: TaskPolicy) -> Tuple[Tuple[LLMProvider, str], List[Tuple[LLMProvider, str]]]:
        """Return the primary (provider, model) and ordered list of fallback (provider, model) pairs."""
        settings = get_settings()

        routes: Dict[TaskPolicy, Tuple[Tuple[LLMProvider, str], List[Tuple[LLMProvider, str]]]] = {
            TaskPolicy.ARCHITECTURE: (
                (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                [
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                ],
            ),
            TaskPolicy.INTEGRATION_CODE: (
                (LLMProvider.HUGGINGFACE, settings.MODEL_INTEGRATION_CODE),
                [
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                ],
            ),
            TaskPolicy.BUG_REASONING: (
                (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                [
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                ],
            ),
            TaskPolicy.SECURITY_REASONING: (
                (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                [
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                ],
            ),
            TaskPolicy.LIGHTWEIGHT_CLASSIFICATION: (
                (
                    (LLMProvider.OLLAMA, settings.OLLAMA_MODEL)
                    if settings.LOCAL_LLM_ENABLED
                    else (LLMProvider.GROQ, settings.MODEL_LIGHTWEIGHT_CLASSIFICATION)
                ),
                (
                    [
                        (LLMProvider.GROQ, settings.MODEL_LIGHTWEIGHT_CLASSIFICATION),
                        (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                    ]
                    if settings.LOCAL_LLM_ENABLED
                    else [(LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE)]
                ),
            ),
            TaskPolicy.VERIFICATION: (
                (LLMProvider.NVIDIA, settings.MODEL_VERIFICATION),
                [
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                ],
            ),
            TaskPolicy.RESEARCH: (
                (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                [
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                ],
            ),
            TaskPolicy.FIX_PLANNING: (
                (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                [
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                ],
            ),
            TaskPolicy.PATCH_GENERATION: (
                (LLMProvider.HUGGINGFACE, settings.MODEL_INTEGRATION_CODE),
                [
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                ],
            ),
            TaskPolicy.PATCH_CRITIC: (
                (LLMProvider.NVIDIA, settings.MODEL_VERIFICATION),
                [
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                ],
            ),
            TaskPolicy.CHANGE_REVIEW: (
                (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                [
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                ],
            ),
        }


        return routes.get(
            policy,
            (
                (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                [(LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING)],
            ),
        )

    def get_task_aware_routes(
        self,
        request: LLMRequest,
        category: Optional[TaskCategory] = None,
    ) -> Tuple[Tuple[LLMProvider, str], List[Tuple[LLMProvider, str]]]:
        """Determine primary provider and fallback chain based on deterministic task classification."""
        settings = get_settings()
        cat = category or TaskClassifier.classify(request)

        if cat == TaskCategory.COMPLEX_REASONING:
            # Mistral primary for complex reasoning / structured generation
            primary = (LLMProvider.MISTRAL, settings.MISTRAL_DEFAULT_MODEL)
            fallbacks = [
                (LLMProvider.CLOUDFLARE, settings.CLOUDFLARE_DEFAULT_MODEL),
                (LLMProvider.OPENROUTER, settings.OPENROUTER_DEFAULT_MODEL),
            ]
            return primary, fallbacks

        elif cat == TaskCategory.RETRIEVAL:
            raise ValueError(
                "Embedding and reranking requests must use the canonical EmbeddingProvider/retrieval boundary."
            )

        else:  # SIMPLE_GENERATION (Default general-purpose)
            if settings.LOCAL_LLM_ENABLED and TaskClassifier.local_model_eligible(request):
                primary = (LLMProvider.OLLAMA, settings.OLLAMA_MODEL)
                fallbacks = [
                    (LLMProvider.CLOUDFLARE, settings.CLOUDFLARE_DEFAULT_MODEL),
                    (LLMProvider.MISTRAL, settings.MISTRAL_DEFAULT_MODEL),
                ]
            else:
                primary = (LLMProvider.CLOUDFLARE, settings.CLOUDFLARE_DEFAULT_MODEL)
                fallbacks = [
                    (LLMProvider.MISTRAL, settings.MISTRAL_DEFAULT_MODEL),
                    (LLMProvider.OPENROUTER, settings.OPENROUTER_DEFAULT_MODEL),
                ]
            return primary, fallbacks

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Run one evidence-scoped request through cache, single-flight, then routing."""
        # Explicit local-provider overrides must retain the same low-risk
        # boundary as capability/task-policy routing.  Keep this check before
        # cache lookup so a previously cached local response can never bypass
        # the safety policy for a newly submitted request.
        if request.provider == LLMProvider.OLLAMA and not TaskClassifier.local_model_eligible(request):
            raise ValueError(
                "Ollama is restricted to low-risk classification/extraction requests."
            )
        if request.capability in {ModelCapability.EMBEDDING, ModelCapability.RERANKING}:
            raise ValueError(
                "Embedding and reranking requests must use the canonical EmbeddingProvider/retrieval boundary."
            )
        routing_identity = self._routing_identity(request)
        cached = await self._response_cache.lookup(request, routing_identity)
        if cached is not None:
            return cached.response.model_copy(deep=True)

        async def execute() -> LLMResponse:
            response = await self._generate_uncached(request)
            await self._response_cache.store_response(request, routing_identity, response)
            return response

        if not self._response_cache.can_coalesce(request):
            return await execute()
        try:
            singleflight_key = self._response_cache.request_key(
                request, routing_identity
            )
        except Exception:
            # Non-canonical provider parameters make reuse unsafe, but never
            # make execution unavailable.
            return await execute()
        response, coalesced = await self._singleflight.run(
            singleflight_key, execute
        )
        result = response.model_copy(deep=True)
        if coalesced:
            extra = dict(result.metadata.extra_metadata or {})
            extra.update({"singleflight_coalesced": True, "provider_call_avoided": True})
            result.metadata.extra_metadata = extra
            await self._response_cache.record_event("singleflight_coalesced", request)
        return result

    def _routing_identity(self, request: LLMRequest) -> str:
        """Version cache/coalescing identity by the selected router policy."""
        if request.capability is not None:
            return (
                f"capability:{self._capability_gateway.routing_policy.version}:"
                f"{self._capability_gateway.registry.version}"
            )
        if request.provider is not None:
            return f"explicit:{request.provider.value}:{request.model or 'provider-default'}"
        if request.task_policy is not None:
            primary, fallbacks = self.get_policy_routes(request.task_policy)
        else:
            primary, fallbacks = self.get_task_aware_routes(
                request, category=TaskClassifier.classify(request)
            )
        chain = [primary, *fallbacks]
        return "router/2.0:" + ",".join(
            f"{provider.value}/{model}" for provider, model in chain
        )

    async def _generate_uncached(self, request: LLMRequest) -> LLMResponse:
        """Route request according to task classification/policy/overrides with circuit breaking and fallback."""
        import asyncio
        settings = get_settings()
        max_retries = max(0, settings.LLM_MAX_RETRIES)

        # Capability requests use the governed cheap-first control plane.
        if request.capability is not None:
            return await self._capability_gateway.generate(request)

        # 1. Direct explicit provider override
        if request.provider is not None:
            adapter = self.get_adapter(request.provider)
            model_target = request.model or ""
            for attempt in range(max_retries + 1):
                try:
                    response = await adapter.generate(request)
                    if model_target:
                        self._health.record_success(request.provider, model_target)
                    if attempt > 0:
                        if response.metadata.extra_metadata is None:
                            response.metadata.extra_metadata = {}
                        response.metadata.extra_metadata["retry_count"] = attempt
                    return response
                except LLMError as exc:
                    if model_target:
                        code = getattr(exc, "failure_code", ProviderFailureCode.UNAVAILABLE)
                        self._health.record_failure(request.provider, model_target, code, retry_after_seconds=getattr(exc, "retry_after_seconds", None))
                    if not exc.retryable or attempt >= max_retries:
                        raise
                    delay = _calculate_retry_delay(attempt, exc)
                    logger.warning(
                        f"Transient LLM failure on explicit provider {request.provider.value} ({exc.message}). "
                        f"Retrying in {delay:.2f}s (attempt {attempt + 1}/{max_retries})..."
                    )
                    await asyncio.sleep(delay)

        # 2. Determine execution chain via task classification or explicit task policy
        if request.task_policy is not None:
            primary, fallbacks = self.get_policy_routes(request.task_policy)
            routing_target = f"policy '{request.task_policy.value}'"
        else:
            category = TaskClassifier.classify(request)
            primary, fallbacks = self.get_task_aware_routes(request, category=category)
            routing_target = f"task '{category.value}'"

        execution_chain = [primary] + fallbacks
        attempted_errors: List[LLMError] = []

        for provider, model in execution_chain:
            # Check circuit breaker health state
            if not self._health.allow_request(provider, model):
                logger.warning(f"Circuit breaker is OPEN or in cooldown for {provider.value} ({model}). Skipping...")
                continue

            adapter = self.get_adapter(provider)
            attempt_request = request.model_copy(update={"provider": provider, "model": model})

            # OpenRouter constraint: single attempt only, never retry OpenRouter repeatedly
            route_max_retries = 0 if provider == LLMProvider.OPENROUTER else max_retries

            for attempt in range(route_max_retries + 1):
                try:
                    response = await adapter.generate(attempt_request)
                    self._health.record_success(provider, model)
                    if attempt > 0 or attempted_errors:
                        if response.metadata.extra_metadata is None:
                            response.metadata.extra_metadata = {}
                        response.metadata.extra_metadata["retry_count"] = attempt
                        response.metadata.extra_metadata["fallback_used"] = bool(attempted_errors)
                        if attempted_errors:
                            response.metadata.extra_metadata["fallbacks_attempted"] = [
                                {
                                    "provider": err.provider.value if err.provider else "unknown",
                                    "model": err.model,
                                    "error": err.message,
                                }
                                for err in attempted_errors
                            ]
                    return response
                except LLMError as exc:
                    code = getattr(exc, "failure_code", ProviderFailureCode.UNAVAILABLE)
                    self._health.record_failure(
                        provider,
                        model,
                        code,
                        retry_after_seconds=getattr(exc, "retry_after_seconds", None),
                    )

                    if not exc.retryable or attempt >= route_max_retries:
                        logger.warning(
                            f"LLM execution exhausted/permanent failure for route target '{routing_target}' on {provider.value} ({model}): {exc.message}. "
                            f"Attempting fallback..."
                        )
                        attempted_errors.append(exc)
                        break

                    delay = _calculate_retry_delay(attempt, exc)
                    logger.warning(
                        f"Transient LLM error on {provider.value} ({model}): {exc.message}. "
                        f"Retrying in {delay:.2f}s (attempt {attempt + 1}/{route_max_retries})..."
                    )
                    await asyncio.sleep(delay)

                except Exception as exc:
                    logger.error(f"Unexpected error executing {provider.value} ({model}): {str(exc)}")
                    self._health.record_failure(provider, model, ProviderFailureCode.UNKNOWN)
                    attempted_errors.append(
                        LLMError(f"Unexpected execution failure: {str(exc)}", provider=provider, model=model, retryable=False)
                    )
                    break

        # If all routes in the execution chain failed
        error_summary = "; ".join([f"[{err.provider.value if err.provider else 'unknown'}]: {err.message}" for err in attempted_errors])
        raise LLMAllFallbacksFailedError(
            f"All LLM candidate models for {routing_target} failed: {error_summary}",
            attempted_errors=attempted_errors,
        )


# Global default router instance
_default_router: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Return singleton LLMRouter instance."""
    global _default_router
    if _default_router is None:
        _default_router = LLMRouter()
    return _default_router


def configure_persistent_llm_router(
    session_factory: Callable[[], Session],
    *,
    database_authoritative: bool,
) -> LLMRouter:
    """Install the runtime gateway with immutable execution records.

    PostgreSQL owns shared circuit/quota state. SQLite intentionally keeps those
    two fast-changing ledgers process-local because local mode permits one worker,
    while AI execution lineage remains durable in both profiles.
    """
    from app.governance.policies import OperationalPolicy, OperationalPolicyService
    from app.governance.telemetry import TelemetryRecorder
    from app.llm.cache import AIResponseCache
    from app.llm.execution import AIExecutionRecorder, CanonicalSQLAlchemyAIExecutionStore
    from app.llm.gateway import AIRoutingLimits
    from app.llm.health import ProviderHealthRegistry, SQLAlchemyProviderHealthRegistry
    from app.llm.quota import LocalProviderQuotaLedger, SQLAlchemyProviderQuotaLedger
    from app.llm.types import ModelCostTier

    def resolve_policy(policy_snapshot_id: str | None) -> AIRoutingLimits:
        from app.models.platform import OperationalPolicyModel

        with session_factory() as db:
            model = (
                db.query(OperationalPolicyModel)
                .filter(OperationalPolicyModel.id == policy_snapshot_id)
                .first()
                if policy_snapshot_id
                else OperationalPolicyService.active(db)
            )
            policy = (
                OperationalPolicy.model_validate(model.policy_payload)
                if model is not None
                else OperationalPolicy.from_settings()
            )
        provider_values = {
            str(value).lower() for value in policy.disabled_providers
        }
        return AIRoutingLimits(
            max_cost_tier=ModelCostTier[policy.max_model_cost_tier],
            disabled_providers=frozenset(
                provider for provider in LLMProvider if provider.value in provider_values
            ),
            disabled_models=frozenset(policy.disabled_models),
        )

    def record_cache_event(event: str, request: LLMRequest) -> None:
        """Persist bounded cache/coalescing counters without provider-call inflation."""
        with session_factory() as db, db.begin():
            TelemetryRecorder.record(
                db,
                metric_name=f"ai.cache.{event}",
                value=1,
                unit="count",
                tenant_id=request.lineage.tenant_id,
                request_id=request.lineage.request_id,
                work_item_id=request.lineage.work_item_id,
                dimensions={
                    "capability": request.capability.value if request.capability else None,
                    "task_policy": request.task_policy.value if request.task_policy else None,
                    "cache_task": request.cache_task,
                },
            )

    global _default_router
    router = LLMRouter(response_cache=AIResponseCache(event_sink=record_cache_event))
    health = (
        SQLAlchemyProviderHealthRegistry(session_factory)
        if database_authoritative
        else ProviderHealthRegistry()
    )
    quota = (
        SQLAlchemyProviderQuotaLedger(session_factory)
        if database_authoritative
        else LocalProviderQuotaLedger()
    )
    router._capability_gateway = CapabilityAIGateway(
        router._adapters,
        health=health,
        quota=quota,
        recorder=AIExecutionRecorder(CanonicalSQLAlchemyAIExecutionStore(session_factory)),
        policy_resolver=resolve_policy,
        max_retries=max(0, get_settings().LLM_MAX_RETRIES),
    )
    _default_router = router
    return router
