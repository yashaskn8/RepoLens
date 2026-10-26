"""Regression tests for evidence-scoped AI reuse and in-process coalescing."""

from __future__ import annotations

import asyncio

import pytest

from app.indexing.embeddings import EmbeddingProvider
from app.indexing.schemas import EmbeddingRequest, EmbeddingResponse, EmbeddingResult
from app.llm.base import BaseLLMAdapter
from app.llm.cache import AIResponseCache, SingleFlight
from app.llm.classifier import TaskCategory, TaskClassifier
from app.llm.capabilities import ModelCapabilityRegistry, ModelCapabilitySpec, RoutingPolicy
from app.llm.gateway import AIRoutingLimits, CapabilityAIGateway
from app.llm.quota import LocalProviderQuotaLedger
from app.llm.exceptions import LLMContextLimitError
from app.llm.router import LLMRouter
from app.llm.types import (
    AIExecutionLineage,
    AIRequestBudget,
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
    ModelCostTier,
    TaskPolicy,
)
from app.schemas.metadata import ModelExecutionMetadata


class MemoryCacheStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.values: dict[str, object] = {}
        self.fail = fail

    @property
    def is_available(self) -> bool:
        return True

    async def get(self, key: str, namespace: str = "cache"):
        if self.fail:
            raise RuntimeError("cache unavailable")
        return self.values.get(f"{namespace}:{key}")

    async def set(
        self,
        key: str,
        value,
        ttl: int | None = None,
        namespace: str = "cache",
    ) -> bool:
        if self.fail:
            raise RuntimeError("cache unavailable")
        self.values[f"{namespace}:{key}"] = value
        return True


class CountingAdapter(BaseLLMAdapter):
    def __init__(self, *, delay: float = 0.0) -> None:
        self.calls = 0
        self.delay = delay

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.GROQ

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        model = request.model or "test-model"
        return LLMResponse(
            content="grounded result",
            model=model,
            provider=LLMProvider.GROQ,
            metadata=ModelExecutionMetadata(
                model_name=model,
                provider=LLMProvider.GROQ.value,
                total_tokens=12,
            ),
        )


class StableEmbeddingProvider(EmbeddingProvider):
    @property
    def provider_name(self) -> str:
        return "test-local"

    @property
    def default_model(self) -> str:
        return "stable-test-embedding"

    @property
    def dimensions(self) -> int:
        return 3

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        return EmbeddingResponse(
            embeddings=[EmbeddingResult(index=0, vector=[1.0, 0.0, 0.0], dimensions=3)],
            model=self.default_model,
            provider=self.provider_name,
            dimensions=3,
        )


def _request(content: str = "classify this") -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role="user", content=content)],
        provider=LLMProvider.GROQ,
        model="test-model",
        lineage=AIExecutionLineage(
            tenant_id="11111111-1111-1111-1111-111111111111",
            prompt_template_version="test-prompt/v1",
            evidence_digest="a" * 64,
        ),
    )


def _capability_gateway(
    adapter: CountingAdapter,
    *,
    policy_resolver=None,
    quota: LocalProviderQuotaLedger | None = None,
) -> CapabilityAIGateway:
    registry = ModelCapabilityRegistry(
        [
            ModelCapabilitySpec(
                provider=LLMProvider.GROQ,
                model="test-model",
                capabilities=frozenset(
                    {
                        ModelCapability.REPOSITORY_ANALYSIS,
                        ModelCapability.STRUCTURED_EXTRACTION,
                    }
                ),
                cost_tier=ModelCostTier.FREE,
                quality_rank=1,
                context_window_tokens=32_768,
                max_output_tokens=8_192,
            )
        ]
    )
    return CapabilityAIGateway(
        {LLMProvider.GROQ: adapter},
        registry=registry,
        routing_policy=RoutingPolicy(registry),
        policy_resolver=policy_resolver,
        quota=quota,
    )


@pytest.mark.asyncio
async def test_exact_cache_avoids_duplicate_provider_call() -> None:
    store = MemoryCacheStore()
    adapter = CountingAdapter()
    router = LLMRouter(
        adapters={LLMProvider.GROQ: adapter},
        response_cache=AIResponseCache(store=store),
    )

    first = await router.generate(_request())
    second = await router.generate(_request())

    assert first.content == second.content == "grounded result"
    assert adapter.calls == 1
    assert second.metadata.extra_metadata["cache_hit"] is True
    assert second.metadata.extra_metadata["provider_call_avoided"] is True


@pytest.mark.asyncio
async def test_cache_failure_is_fail_open() -> None:
    adapter = CountingAdapter()
    router = LLMRouter(
        adapters={LLMProvider.GROQ: adapter},
        response_cache=AIResponseCache(store=MemoryCacheStore(fail=True)),
    )

    response = await router.generate(_request())

    assert response.content == "grounded result"
    assert adapter.calls == 1


@pytest.mark.asyncio
async def test_singleflight_coalesces_concurrent_identical_requests() -> None:
    adapter = CountingAdapter(delay=0.03)
    router = LLMRouter(
        adapters={LLMProvider.GROQ: adapter},
        response_cache=AIResponseCache(store=MemoryCacheStore()),
    )

    responses = await asyncio.gather(*(router.generate(_request()) for _ in range(5)))

    assert adapter.calls == 1
    assert sum(
        bool(item.metadata.extra_metadata.get("singleflight_coalesced"))
        for item in responses
    ) == 4


@pytest.mark.asyncio
async def test_singleflight_cleans_up_failed_task() -> None:
    flight: SingleFlight[str] = SingleFlight()

    async def fail() -> str:
        raise RuntimeError("provider failed")

    with pytest.raises(RuntimeError, match="provider failed"):
        await flight.run("same", fail)
    await asyncio.sleep(0)
    assert flight.active_count == 0


@pytest.mark.asyncio
async def test_singleflight_cleans_up_after_waiter_cancellation() -> None:
    flight: SingleFlight[str] = SingleFlight()
    started = asyncio.Event()
    release = asyncio.Event()

    async def finish_later() -> str:
        started.set()
        await release.wait()
        return "done"

    waiter = asyncio.create_task(flight.run("same", finish_later))
    await started.wait()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert flight.active_count == 1

    release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert flight.active_count == 0


@pytest.mark.asyncio
async def test_semantic_cache_is_explicit_and_non_authoritative() -> None:
    store = MemoryCacheStore()
    cache = AIResponseCache(
        store=store,
        embedding_provider=StableEmbeddingProvider(),
    )
    first = _request("summarize the module")
    first.cache_mode = "semantic"
    first.cache_task = "summary"
    response = LLMResponse(
        content="module summary",
        model="test-model",
        provider=LLMProvider.GROQ,
        metadata=ModelExecutionMetadata(model_name="test-model", provider="groq"),
    )
    await cache.store_response(first, "route/v1", response)

    equivalent = _request("give me a summary of the module")
    equivalent.cache_mode = "semantic"
    equivalent.cache_task = "summary"
    hit = await cache.lookup(equivalent, "route/v1")

    assert hit is not None
    assert hit.kind == "semantic"
    assert hit.response.metadata.extra_metadata["authoritative_cache_result"] is False


def test_cache_identity_is_tenant_evidence_and_version_scoped() -> None:
    cache = AIResponseCache(store=MemoryCacheStore())
    baseline = _request()
    other_tenant = baseline.model_copy(
        update={
            "lineage": baseline.lineage.model_copy(
                update={"tenant_id": "22222222-2222-2222-2222-222222222222"}
            )
        }
    )
    other_evidence = baseline.model_copy(
        update={
            "lineage": baseline.lineage.model_copy(update={"evidence_digest": "b" * 64})
        }
    )
    other_prompt = baseline.model_copy(
        update={
            "lineage": baseline.lineage.model_copy(
                update={"prompt_template_version": "test-prompt/v2"}
            )
        }
    )

    keys = {
        cache.request_key(request, "route/v1")
        for request in (baseline, other_tenant, other_evidence, other_prompt)
    }
    assert len(keys) == 4


def test_exact_cache_identity_preserves_semantic_message_whitespace() -> None:
    cache = AIResponseCache(store=MemoryCacheStore())
    baseline = _request("if cond:\n    work()\n    deny()")
    different_scope = baseline.model_copy(deep=True)
    different_scope.messages[0].content = "if cond:\n    work()\ndeny()"

    assert cache.exact_cache_allowed(baseline)
    assert cache.exact_cache_allowed(different_scope)
    assert cache.request_key(baseline, "route/v1") != cache.request_key(
        different_scope,
        "route/v1",
    )
    assert cache.VERSION == "ai-response-cache/1.2"


def test_semantic_cache_denies_security_reasoning() -> None:
    cache = AIResponseCache(
        store=MemoryCacheStore(), embedding_provider=StableEmbeddingProvider()
    )
    request = _request("summarize security evidence")
    request.capability = ModelCapability.SECURITY_REASONING
    request.cache_mode = "semantic"
    request.cache_task = "summary"

    assert cache.semantic_cache_allowed(request) is False


def test_cache_identity_includes_request_budget() -> None:
    cache = AIResponseCache(store=MemoryCacheStore())
    baseline = _request()
    baseline.capability = ModelCapability.STRUCTURED_EXTRACTION
    baseline.budget = AIRequestBudget(max_output_tokens=500, max_context_tokens=2_000)
    stricter = baseline.model_copy(deep=True)
    stricter.budget = AIRequestBudget(max_output_tokens=100, max_context_tokens=2_000)

    assert cache.request_key(baseline, "route/v1") != cache.request_key(stricter, "route/v1")


@pytest.mark.parametrize(
    "capability",
    [ModelCapability.STRUCTURED_EXTRACTION, None],
)
@pytest.mark.asyncio
async def test_cache_hit_cannot_bypass_current_context_budget(capability) -> None:
    store = MemoryCacheStore()
    cache = AIResponseCache(store=store)
    router = LLMRouter(
        adapters={LLMProvider.GROQ: CountingAdapter()}, response_cache=cache
    )
    request = _request("A detailed repository analysis request that exceeds a tiny input budget.")
    request.capability = capability
    request.budget = AIRequestBudget(max_input_tokens=10, max_context_tokens=2_000)
    await cache.store_response(
        request,
        router._routing_identity(request),
        LLMResponse(
            content="cached response",
            model="test-model",
            provider=LLMProvider.GROQ,
            metadata=ModelExecutionMetadata(model_name="test-model", provider="groq"),
        ),
    )

    with pytest.raises(LLMContextLimitError, match="input-token budget"):
        await router.generate(request)


@pytest.mark.asyncio
async def test_capability_cache_hit_revalidates_active_provider_policy_without_snapshot(
    monkeypatch,
) -> None:
    import asyncio

    store = MemoryCacheStore()
    cache = AIResponseCache(store=store)
    adapter = CountingAdapter()
    resolved_policy_ids: list[str | None] = []

    def resolve_active_policy(policy_snapshot_id: str | None) -> AIRoutingLimits:
        resolved_policy_ids.append(policy_snapshot_id)
        return AIRoutingLimits(
            max_cost_tier=ModelCostTier.FREE,
            disabled_providers=frozenset({LLMProvider.GROQ}),
        )

    async def direct_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", direct_to_thread)
    gateway = _capability_gateway(adapter, policy_resolver=resolve_active_policy)
    router = LLMRouter(
        adapters={LLMProvider.GROQ: adapter},
        capability_gateway=gateway,
        response_cache=cache,
    )
    request = _request("analyze this evidence")
    request.capability = ModelCapability.REPOSITORY_ANALYSIS
    request.task_policy = TaskPolicy.ARCHITECTURE
    request.provider = None
    request.model = None
    request.lineage = request.lineage.model_copy(
        update={"policy_snapshot_id": None}
    )
    await cache.store_response(
        request,
        router._routing_identity(request),
        LLMResponse(
            content="stale cached response",
            model="test-model",
            provider=LLMProvider.GROQ,
            metadata=ModelExecutionMetadata(model_name="test-model", provider="groq"),
        ),
    )

    with pytest.raises(LLMContextLimitError, match="No enabled model"):
        await router.generate(request)

    assert resolved_policy_ids == [None, None]
    assert adapter.calls == 0


@pytest.mark.asyncio
async def test_eligible_capability_cache_hit_does_not_consume_provider_quota() -> None:
    store = MemoryCacheStore()
    cache = AIResponseCache(store=store)
    adapter = CountingAdapter()
    quota = LocalProviderQuotaLedger()
    gateway = _capability_gateway(adapter, quota=quota)
    router = LLMRouter(
        adapters={LLMProvider.GROQ: adapter},
        capability_gateway=gateway,
        response_cache=cache,
    )
    request = _request("analyze this evidence")
    request.capability = ModelCapability.REPOSITORY_ANALYSIS
    request.task_policy = TaskPolicy.ARCHITECTURE
    request.provider = None
    request.model = None
    await cache.store_response(
        request,
        router._routing_identity(request),
        LLMResponse(
            content="eligible cached response",
            model="test-model",
            provider=LLMProvider.GROQ,
            metadata=ModelExecutionMetadata(model_name="test-model", provider="groq"),
        ),
    )

    response = await router.generate(request)

    assert response.content == "eligible cached response"
    assert response.metadata.extra_metadata["cache_hit"] is True
    assert adapter.calls == 0
    assert quota.usage(LLMProvider.GROQ, "test-model")["consumed_calls"] == 0
    assert quota.usage(LLMProvider.GROQ, "test-model")["reserved_calls"] == 0


@pytest.mark.asyncio
async def test_generation_router_rejects_embedding_capabilities() -> None:
    adapter = CountingAdapter()
    router = LLMRouter(adapters={LLMProvider.GROQ: adapter})
    request = _request("embed this source")
    request.capability = ModelCapability.EMBEDDING

    with pytest.raises(ValueError, match="canonical EmbeddingProvider"):
        await router.generate(request)
    assert adapter.calls == 0


def test_search_language_does_not_misroute_generation_to_embedding_provider() -> None:
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Find the risks and explain them")]
    )

    assert TaskClassifier.classify(request) == TaskCategory.SIMPLE_GENERATION


@pytest.mark.asyncio
async def test_cache_serialization_failure_never_breaks_successful_model_call() -> None:
    """Metadata outside the cache JSON contract cannot fail model execution."""
    cache = AIResponseCache(store=MemoryCacheStore())
    response = LLMResponse(
        content="valid provider result",
        model="test-model",
        provider=LLMProvider.GROQ,
        metadata=ModelExecutionMetadata(model_name="test-model", provider="groq"),
    )
    # The metadata field supports arbitrary diagnostic values, but Redis
    # cache entries require JSON-serializable values.
    response.metadata.extra_metadata["unserializable"] = object()
    await cache.store_response(_request(), "route/v1", response)
    assert response.content == "valid provider result"



@pytest.mark.asyncio
async def test_semantic_cache_ignores_corrupt_vectors_without_losing_valid_hits() -> None:
    """A malformed Redis bucket entry cannot poison an otherwise valid cache hit."""
    store = MemoryCacheStore()
    cache = AIResponseCache(
        store=store,
        embedding_provider=StableEmbeddingProvider(),
    )
    request = _request("summarize the repository")
    request.cache_mode = "semantic"
    request.cache_task = "summary"
    response = LLMResponse(
        content="repository summary",
        model="test-model",
        provider=LLMProvider.GROQ,
        metadata=ModelExecutionMetadata(model_name="test-model", provider="groq"),
    )
    await cache.store_response(request, "route/v1", response)
    other = _request("summarize the whole repository")
    other.cache_mode = "semantic"
    other.cache_task = "summary"
    bucket = f"cache:{cache.semantic_bucket_key(other, 'route/v1')}"
    assert isinstance(store.values[bucket], list)
    store.values[bucket].insert(0, {
        "vector": ["bad-value", 0.0, 0.0],
        "response": {"content": "forged-cache-result"},
    })
    hit = await cache.lookup(other, "route/v1")
    assert hit is not None
    assert hit.kind == "semantic"
    assert hit.response.content == "repository summary"


@pytest.mark.parametrize("vector", [
    [], [True, 0.0], ["0.1", 1.0], [float("nan")],
    [float("inf")], [1e308, 1e308],
])
def test_semantic_cache_rejects_invalid_vectors(vector) -> None:
    assert AIResponseCache._valid_embedding_vector(vector) is False


@pytest.mark.asyncio
async def test_singleflight_timed_out_provider_does_not_poison_key() -> None:
    flight: SingleFlight[str] = SingleFlight(task_timeout_seconds=0.02)
    started = asyncio.Event()

    async def never_finish() -> str:
        started.set()
        await asyncio.Event().wait()
        return "not-reached"

    first = asyncio.create_task(flight.run("same-key", never_finish))
    await started.wait()
    second = asyncio.create_task(flight.run("same-key", never_finish))
    with pytest.raises(asyncio.TimeoutError):
        await first
    with pytest.raises(asyncio.TimeoutError):
        await second
    await asyncio.sleep(0)
    assert flight.active_count == 0

    result, shared = await flight.run("same-key", lambda: asyncio.sleep(0, result="recovered"))
    assert result == "recovered"
    assert shared is False


def test_singleflight_rejects_invalid_timeout() -> None:
    for invalid in [0, -1, float("inf"), float("nan")]:
        with pytest.raises(ValueError, match="finite and positive"):
            SingleFlight(task_timeout_seconds=invalid)


@pytest.mark.asyncio
async def test_singleflight_capacity_bypass_is_also_time_bounded() -> None:
    flight: SingleFlight[str] = SingleFlight(max_entries=1, task_timeout_seconds=0.02)
    started = asyncio.Event()

    async def hanging() -> str:
        started.set()
        await asyncio.Event().wait()
        return "unreachable"

    first = asyncio.create_task(flight.run("occupied", hanging))
    await started.wait()
    with pytest.raises(asyncio.TimeoutError):
        await flight.run("different", hanging)
    with pytest.raises(asyncio.TimeoutError):
        await first
    await asyncio.sleep(0)
    assert flight.active_count == 0
