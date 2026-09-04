"""Regression tests for evidence-scoped AI reuse and in-process coalescing."""

from __future__ import annotations

import asyncio

import pytest

from app.indexing.embeddings import EmbeddingProvider
from app.indexing.schemas import EmbeddingRequest, EmbeddingResponse, EmbeddingResult
from app.llm.base import BaseLLMAdapter
from app.llm.cache import AIResponseCache, SingleFlight
from app.llm.classifier import TaskCategory, TaskClassifier
from app.llm.router import LLMRouter
from app.llm.types import (
    AIExecutionLineage,
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
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


def test_semantic_cache_denies_security_reasoning() -> None:
    cache = AIResponseCache(
        store=MemoryCacheStore(), embedding_provider=StableEmbeddingProvider()
    )
    request = _request("summarize security evidence")
    request.capability = ModelCapability.SECURITY_REASONING
    request.cache_mode = "semantic"
    request.cache_task = "summary"

    assert cache.semantic_cache_allowed(request) is False


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
