"""Focused tests for budget-first repository-analysis model routing."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import get_settings
from app.llm.base import BaseLLMAdapter
from app.llm.capabilities import ModelCapabilityRegistry, ModelCapabilitySpec, RoutingPolicy
from app.llm.exceptions import LLMAuthenticationError, LLMRateLimitError
from app.llm.gateway import CapabilityAIGateway
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


def _response(provider: LLMProvider, model: str, content: str = "ok") -> LLMResponse:
    return LLMResponse(
        content=content,
        model=model,
        provider=provider,
        metadata=ModelExecutionMetadata(
            model_name=model,
            provider=provider.value,
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15,
            execution_time_ms=1.0,
        ),
    )


def _spec(
    provider: LLMProvider,
    model: str,
    cost_tier: ModelCostTier,
    quality_rank: int,
) -> ModelCapabilitySpec:
    return ModelCapabilitySpec(
        provider=provider,
        model=model,
        capabilities=frozenset({ModelCapability.REPOSITORY_ANALYSIS}),
        cost_tier=cost_tier,
        quality_rank=quality_rank,
        context_window_tokens=32_768,
        max_output_tokens=4_096,
    )


def _request(*, max_ai_calls: int = 2, structured: bool = False) -> LLMRequest:
    schema = None
    if structured:
        schema = {
            "type": "object",
            "required": ["summary", "confidence"],
            "properties": {
                "summary": {"type": "string"},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "additionalProperties": False,
        }
    return LLMRequest(
        messages=[LLMMessage(role="user", content="Analyze these extracted repository facts")],
        capability=ModelCapability.REPOSITORY_ANALYSIS,
        output_schema=schema,
        confidence_threshold=0.8 if structured else None,
        budget=AIRequestBudget(
            max_ai_calls=max_ai_calls,
            max_escalation_tier=ModelCostTier.CHEAP,
        ),
    )


def test_repository_analysis_routes_free_code_model_before_stronger_models():
    settings = get_settings()
    registry = ModelCapabilityRegistry.from_settings(settings)
    policy = RoutingPolicy(registry)

    candidates = policy.candidates(
        ModelCapability.REPOSITORY_ANALYSIS,
        max_cost_tier=ModelCostTier.STANDARD,
        required_context_tokens=1,
        structured_output=True,
    )

    assert candidates[0].provider == LLMProvider.HUGGINGFACE
    assert candidates[0].model == settings.MODEL_INTEGRATION_CODE
    assert candidates[0].cost_tier == ModelCostTier.FREE
    assert ModelCapability.VERIFICATION in candidates[0].capabilities
    assert [candidate.cost_tier for candidate in candidates[1:3]] == [
        ModelCostTier.CHEAP,
        ModelCostTier.CHEAP,
    ]
    assert RoutingPolicy.version == "capability-routing/1.1"


@pytest.mark.asyncio
async def test_retry_preserves_last_call_for_stronger_escalation():
    registry = ModelCapabilityRegistry(
        (
            _spec(LLMProvider.HUGGINGFACE, "free-code", ModelCostTier.FREE, 10),
            _spec(LLMProvider.GEMINI, "strong-code", ModelCostTier.CHEAP, 10),
        )
    )
    free_adapter = MagicMock(spec=BaseLLMAdapter)
    free_adapter.generate = AsyncMock(
        side_effect=LLMRateLimitError(
            "free endpoint is busy",
            provider=LLMProvider.HUGGINGFACE,
            model="free-code",
        )
    )
    strong_adapter = MagicMock(spec=BaseLLMAdapter)
    strong_adapter.generate = AsyncMock(
        return_value=_response(LLMProvider.GEMINI, "strong-code", "strong result")
    )
    gateway = CapabilityAIGateway(
        {
            LLMProvider.HUGGINGFACE: free_adapter,
            LLMProvider.GEMINI: strong_adapter,
        },
        registry=registry,
        max_retries=5,
    )

    result = await gateway.generate(_request(max_ai_calls=2))

    assert result.content == "strong result"
    assert free_adapter.generate.call_count == 1
    assert strong_adapter.generate.call_count == 1


@pytest.mark.asyncio
async def test_failed_escalation_returns_best_schema_valid_uncertain_response():
    registry = ModelCapabilityRegistry(
        (
            _spec(LLMProvider.HUGGINGFACE, "free-code", ModelCostTier.FREE, 10),
            _spec(LLMProvider.GEMINI, "strong-code", ModelCostTier.CHEAP, 10),
        )
    )
    free_adapter = MagicMock(spec=BaseLLMAdapter)
    free_adapter.generate = AsyncMock(
        return_value=_response(
            LLMProvider.HUGGINGFACE,
            "free-code",
            '{"summary":"supported but incomplete","confidence":0.55}',
        )
    )
    strong_adapter = MagicMock(spec=BaseLLMAdapter)
    strong_adapter.generate = AsyncMock(
        side_effect=LLMAuthenticationError(
            "strong endpoint unavailable",
            provider=LLMProvider.GEMINI,
            model="strong-code",
        )
    )
    gateway = CapabilityAIGateway(
        {
            LLMProvider.HUGGINGFACE: free_adapter,
            LLMProvider.GEMINI: strong_adapter,
        },
        registry=registry,
        max_retries=3,
    )

    result = await gateway.generate(_request(max_ai_calls=2, structured=True))

    assert result.provider == LLMProvider.HUGGINGFACE
    assert result.metadata.extra_metadata["uncertain_response_retained"] is True
    assert result.metadata.extra_metadata["escalation_outcome"] == "stronger_escalation_failed"
    assert result.metadata.extra_metadata["fallbacks_attempted"] == [
        {
            "provider": "gemini",
            "model": "strong-code",
            "failure_code": "AUTH_FAILURE",
        }
    ]


@pytest.mark.asyncio
async def test_concurrent_free_requests_are_serialized_per_endpoint():
    registry = ModelCapabilityRegistry(
        (_spec(LLMProvider.HUGGINGFACE, "free-code", ModelCostTier.FREE, 10),)
    )
    active_calls = 0
    max_active_calls = 0

    async def generate(request: LLMRequest) -> LLMResponse:
        nonlocal active_calls, max_active_calls
        active_calls += 1
        max_active_calls = max(max_active_calls, active_calls)
        await asyncio.sleep(0.02)
        active_calls -= 1
        return _response(LLMProvider.HUGGINGFACE, request.model or "free-code")

    free_adapter = MagicMock(spec=BaseLLMAdapter)
    free_adapter.generate = AsyncMock(side_effect=generate)
    gateway = CapabilityAIGateway(
        {LLMProvider.HUGGINGFACE: free_adapter},
        registry=registry,
        max_retries=0,
    )

    await asyncio.gather(
        gateway.generate(_request(max_ai_calls=1)),
        gateway.generate(_request(max_ai_calls=1)),
    )

    assert free_adapter.generate.call_count == 2
    assert max_active_calls == 1
