"""Security-specialist tier authorization remains request- and operator-bounded."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import get_settings
from app.llm.base import BaseLLMAdapter
from app.llm.budgets import REPOSITORY_ANALYSIS_BUDGET, SECURITY_ANALYSIS_BUDGET
from app.llm.capabilities import ModelCapabilityRegistry
from app.llm.exceptions import LLMContextLimitError
from app.llm.gateway import AIRoutingLimits, CapabilityAIGateway
from app.llm.router import LLMRouter
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
    ModelCostTier,
    TaskPolicy,
)
from app.llm.evaluation_route import evaluation_model_route
from app.schemas.metadata import ModelExecutionMetadata


def _request(budget=SECURITY_ANALYSIS_BUDGET) -> LLMRequest:
    settings = get_settings()
    return LLMRequest(
        messages=[LLMMessage(role="user", content="Evaluate bounded security evidence.")],
        task_policy=TaskPolicy.SECURITY_REASONING,
        capability=ModelCapability.REPOSITORY_ANALYSIS,
        budget=budget,
        max_tokens=512,
        provider=LLMProvider.GROQ,
        model=settings.MODEL_SECURITY_REASONING,
    )


def _response() -> LLMResponse:
    settings = get_settings()
    return LLMResponse(
        content="{}",
        model=settings.MODEL_SECURITY_REASONING,
        provider=LLMProvider.GROQ,
        metadata=ModelExecutionMetadata(
            model_name=settings.MODEL_SECURITY_REASONING,
            provider=LLMProvider.GROQ.value,
            prompt_tokens=10,
            completion_tokens=2,
            total_tokens=12,
            execution_time_ms=1.0,
        ),
    )


def test_security_budget_changes_only_request_tier_ceiling() -> None:
    assert SECURITY_ANALYSIS_BUDGET.max_escalation_tier == ModelCostTier.STANDARD
    assert REPOSITORY_ANALYSIS_BUDGET.max_escalation_tier == ModelCostTier.CHEAP
    assert SECURITY_ANALYSIS_BUDGET.model_copy(update={
        "max_escalation_tier": ModelCostTier.CHEAP,
    }) == REPOSITORY_ANALYSIS_BUDGET
    assert SECURITY_ANALYSIS_BUDGET.max_ai_calls == REPOSITORY_ANALYSIS_BUDGET.max_ai_calls
    assert SECURITY_ANALYSIS_BUDGET.max_input_tokens == REPOSITORY_ANALYSIS_BUDGET.max_input_tokens
    assert SECURITY_ANALYSIS_BUDGET.max_output_tokens == REPOSITORY_ANALYSIS_BUDGET.max_output_tokens
    assert SECURITY_ANALYSIS_BUDGET.max_context_tokens == REPOSITORY_ANALYSIS_BUDGET.max_context_tokens


@pytest.mark.asyncio
async def test_security_standard_model_is_reachable_when_operator_allows_standard() -> None:
    settings = get_settings()
    registry = ModelCapabilityRegistry.from_settings(settings)
    adapter = MagicMock(spec=BaseLLMAdapter)
    adapter.generate = AsyncMock(return_value=_response())
    gateway = CapabilityAIGateway(
        {LLMProvider.GROQ: adapter},
        registry=registry,
        policy_resolver=lambda _snapshot: AIRoutingLimits(max_cost_tier=ModelCostTier.STANDARD),
        max_retries=0,
    )

    result = await gateway.generate(_request())

    assert result.provider == LLMProvider.GROQ
    assert result.model == settings.MODEL_SECURITY_REASONING
    adapter.generate.assert_awaited_once()


@pytest.mark.asyncio
async def test_operator_cheap_ceiling_blocks_standard_security_model_before_adapter() -> None:
    adapter = MagicMock(spec=BaseLLMAdapter)
    adapter.generate = AsyncMock(return_value=_response())
    gateway = CapabilityAIGateway(
        {LLMProvider.GROQ: adapter},
        registry=ModelCapabilityRegistry.from_settings(),
        policy_resolver=lambda _snapshot: AIRoutingLimits(max_cost_tier=ModelCostTier.CHEAP),
        max_retries=0,
    )

    with pytest.raises(LLMContextLimitError, match="within the request budget"):
        await gateway.generate(_request())

    adapter.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_pinned_evaluation_route_cannot_bypass_cheap_request_or_operator_ceiling() -> None:
    settings = get_settings()
    adapter = MagicMock(spec=BaseLLMAdapter)
    adapter.generate = AsyncMock(return_value=_response())
    gateway = CapabilityAIGateway(
        {LLMProvider.GROQ: adapter},
        registry=ModelCapabilityRegistry.from_settings(settings),
        policy_resolver=lambda _snapshot: AIRoutingLimits(max_cost_tier=ModelCostTier.STANDARD),
        max_retries=0,
    )
    router = LLMRouter(
        adapters={LLMProvider.GROQ: adapter},
        capability_gateway=gateway,
    )

    with evaluation_model_route(LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING):
        with pytest.raises(LLMContextLimitError, match="within the request budget"):
            await router.generate(_request(REPOSITORY_ANALYSIS_BUDGET))

    adapter.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_standard_does_not_raise_cheap_request_budget() -> None:
    settings = get_settings()
    adapter = MagicMock(spec=BaseLLMAdapter)
    adapter.generate = AsyncMock(return_value=_response())
    gateway = CapabilityAIGateway(
        {LLMProvider.GROQ: adapter},
        registry=ModelCapabilityRegistry.from_settings(settings),
        policy_resolver=lambda _snapshot: AIRoutingLimits(max_cost_tier=ModelCostTier.STANDARD),
        max_retries=0,
    )

    with pytest.raises(LLMContextLimitError, match="within the request budget"):
        await gateway.generate(_request(REPOSITORY_ANALYSIS_BUDGET))

    adapter.generate.assert_not_awaited()


def test_provider_credentials_do_not_change_registered_model_tier() -> None:
    settings = get_settings()
    without_credentials = settings.model_copy(update={
        "GROQ_API_KEY": "",
        "GEMINI_API_KEY": "",
    })
    configured_registry = ModelCapabilityRegistry.from_settings(settings)
    empty_registry = ModelCapabilityRegistry.from_settings(without_credentials)
    groq_model = settings.MODEL_SECURITY_REASONING

    assert configured_registry.version == empty_registry.version
    assert configured_registry.get(LLMProvider.GROQ, groq_model).cost_tier == ModelCostTier.STANDARD
    assert empty_registry.get(LLMProvider.GROQ, groq_model).cost_tier == ModelCostTier.STANDARD


@pytest.mark.asyncio
async def test_missing_pinned_security_candidate_fails_closed() -> None:
    settings = get_settings()
    full_registry = ModelCapabilityRegistry.from_settings(settings)
    registry = ModelCapabilityRegistry(
        spec for spec in full_registry.specifications
        if not (spec.provider == LLMProvider.GROQ and spec.model == settings.MODEL_SECURITY_REASONING)
    )
    adapter = MagicMock(spec=BaseLLMAdapter)
    adapter.generate = AsyncMock(return_value=_response())
    gateway = CapabilityAIGateway(
        {LLMProvider.GROQ: adapter},
        registry=registry,
        policy_resolver=lambda _snapshot: AIRoutingLimits(max_cost_tier=ModelCostTier.STANDARD),
        max_retries=0,
    )

    with pytest.raises(LLMContextLimitError, match="No enabled model satisfies capability"):
        await gateway.generate(_request())

    adapter.generate.assert_not_awaited()
