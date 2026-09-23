"""Security tests for async-scoped system-evaluation candidate routing."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.llm.base import BaseLLMAdapter
from app.llm.capabilities import ModelCapabilityRegistry, ModelCapabilitySpec
from app.llm.evaluation_route import (
    apply_evaluation_model_route,
    current_evaluation_model_route,
    evaluation_model_route,
)
from app.llm.exceptions import LLMAllFallbacksFailedError, LLMAuthenticationError
from app.llm.gateway import CapabilityAIGateway
from app.llm.router import LLMRouter
from app.llm.types import (
    AIRequestBudget,
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
    ModelCostTier,
)
from app.schemas.metadata import ModelExecutionMetadata


class _NoReuseCache:
    def __init__(self) -> None:
        self.requests: list[LLMRequest] = []

    async def lookup(self, request: LLMRequest, routing_identity: str):
        self.requests.append(request)
        return None

    async def store_response(self, request: LLMRequest, routing_identity: str, response: LLMResponse) -> None:
        self.requests.append(request)

    def can_coalesce(self, request: LLMRequest) -> bool:
        return request.cache_mode != "disabled"

    async def record_event(self, event: str, request: LLMRequest) -> None:
        return None


def _spec(provider: LLMProvider, model: str) -> ModelCapabilitySpec:
    return ModelCapabilitySpec(
        provider=provider,
        model=model,
        capabilities=frozenset({ModelCapability.CODE_REASONING}),
        cost_tier=ModelCostTier.CHEAP,
        quality_rank=10,
        context_window_tokens=32_768,
        max_output_tokens=4_096,
    )


def _request() -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role="user", content="bounded context")],
        capability=ModelCapability.CODE_REASONING,
        output_schema={"type": "object", "properties": {"result": {"type": "string"}}},
        budget=AIRequestBudget(max_ai_calls=1, max_context_tokens=8_000),
    )


def _response(provider: LLMProvider, model: str) -> LLMResponse:
    return LLMResponse(
        content='{"result":"ok"}',
        provider=provider,
        model=model,
        metadata=ModelExecutionMetadata(model_name=model, provider=provider.value),
    )


@pytest.mark.asyncio
async def test_evaluation_route_is_task_local_and_restored_after_exception():
    request = _request()
    barrier = asyncio.Event()

    async def scoped(provider: LLMProvider, model: str) -> tuple[str, str, str]:
        with evaluation_model_route(provider, model):
            await barrier.wait()
            routed = apply_evaluation_model_route(request)
            return routed.provider.value, routed.model, routed.cache_mode

    first = asyncio.create_task(scoped(LLMProvider.GEMINI, "candidate-a"))
    second = asyncio.create_task(scoped(LLMProvider.GROQ, "candidate-b"))
    barrier.set()
    assert await asyncio.gather(first, second) == [
        ("gemini", "candidate-a", "disabled"),
        ("groq", "candidate-b", "disabled"),
    ]
    assert current_evaluation_model_route() is None
    with pytest.raises(RuntimeError):
        with evaluation_model_route(LLMProvider.GEMINI, "candidate-a"):
            raise RuntimeError("test failure")
    assert current_evaluation_model_route() is None


@pytest.mark.asyncio
async def test_candidate_route_stays_in_gateway_and_never_falls_back_to_baseline():
    candidate = MagicMock(spec=BaseLLMAdapter)
    candidate.generate = AsyncMock(
        side_effect=LLMAuthenticationError(
            "candidate rejected",
            provider=LLMProvider.GEMINI,
            model="candidate-model",
        )
    )
    baseline = MagicMock(spec=BaseLLMAdapter)
    baseline.generate = AsyncMock(return_value=_response(LLMProvider.GROQ, "baseline-model"))
    adapters = {LLMProvider.GEMINI: candidate, LLMProvider.GROQ: baseline}
    registry = ModelCapabilityRegistry((
        _spec(LLMProvider.GEMINI, "candidate-model"),
        _spec(LLMProvider.GROQ, "baseline-model"),
    ))
    gateway = CapabilityAIGateway(adapters, registry=registry, max_retries=4)
    cache = _NoReuseCache()
    router = LLMRouter(
        adapters=adapters,
        capability_gateway=gateway,
        response_cache=cache,  # type: ignore[arg-type]
    )

    with evaluation_model_route(LLMProvider.GEMINI, "candidate-model"):
        with pytest.raises(LLMAllFallbacksFailedError):
            await router.generate(_request())

    assert candidate.generate.await_count == 1
    assert baseline.generate.await_count == 0
    assert cache.requests
    assert all(item.provider == LLMProvider.GEMINI for item in cache.requests)
    assert all(item.model == "candidate-model" for item in cache.requests)
    assert all(item.cache_mode == "disabled" for item in cache.requests)
    assert current_evaluation_model_route() is None
