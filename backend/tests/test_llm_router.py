"""Unit tests for LLMRouter policy dispatch, adapter orchestration, and fallback execution."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import (
    LLMAllFallbacksFailedError,
    LLMAuthenticationError,
    LLMRateLimitError,
)
from app.llm.router import LLMRouter
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    TaskPolicy,
)
from app.schemas.metadata import ModelExecutionMetadata


def _create_mock_response(provider: LLMProvider, model: str, content: str = "ok") -> LLMResponse:
    return LLMResponse(
        content=content,
        model=model,
        provider=provider,
        metadata=ModelExecutionMetadata(
            model_name=model,
            provider=provider.value,
            prompt_tokens=10,
            completion_tokens=10,
            total_tokens=20,
            execution_time_ms=100.0,
        ),
    )


@pytest.mark.asyncio
async def test_router_policy_mappings():
    """Verify router maps policies to the canonical primary models and providers."""
    router = LLMRouter()

    arch_primary, _ = router.get_policy_routes(TaskPolicy.ARCHITECTURE)
    assert arch_primary == (LLMProvider.GEMINI, "gemini-3.7-flash")

    code_primary, _ = router.get_policy_routes(TaskPolicy.INTEGRATION_CODE)
    assert code_primary == (LLMProvider.HUGGINGFACE, "Qwen/Qwen3-Coder-Next")

    bug_primary, _ = router.get_policy_routes(TaskPolicy.BUG_REASONING)
    assert bug_primary == (LLMProvider.NVIDIA, "poolside/laguna-xs-2.1")

    sec_primary, _ = router.get_policy_routes(TaskPolicy.SECURITY_REASONING)
    assert sec_primary == (LLMProvider.GROQ, "openai/gpt-oss-120b")

    class_primary, _ = router.get_policy_routes(TaskPolicy.LIGHTWEIGHT_CLASSIFICATION)
    assert class_primary == (LLMProvider.GROQ, "openai/gpt-oss-20b")

    verif_primary, _ = router.get_policy_routes(TaskPolicy.VERIFICATION)
    assert verif_primary == (LLMProvider.NVIDIA, "nvidia/nemotron-3-ultra-550b-a55b")


@pytest.mark.asyncio
async def test_router_dispatches_to_primary():
    """Verify router calls primary provider adapter when successful."""
    mock_gemini = MagicMock(spec=BaseLLMAdapter)
    mock_gemini.generate = AsyncMock(
        return_value=_create_mock_response(LLMProvider.GEMINI, "gemini-3.7-flash", "Architectural overview")
    )

    router = LLMRouter(adapters={LLMProvider.GEMINI: mock_gemini})
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Describe structure")],
        task_policy=TaskPolicy.ARCHITECTURE,
    )

    response = await router.generate(request)
    assert response.provider == LLMProvider.GEMINI
    assert response.model == "gemini-3.7-flash"
    assert response.content == "Architectural overview"
    mock_gemini.generate.assert_called_once()


@pytest.mark.asyncio
async def test_router_fallback_on_primary_failure():
    """Verify router seamlessly executes fallback adapter when primary fails."""
    # Primary (HF) fails with rate limit error
    mock_hf = MagicMock(spec=BaseLLMAdapter)
    mock_hf.generate = AsyncMock(
        side_effect=LLMRateLimitError("HF rate limit exceeded", provider=LLMProvider.HUGGINGFACE, model="Qwen/Qwen3-Coder-Next")
    )

    # First fallback (Gemini) succeeds
    mock_gemini = MagicMock(spec=BaseLLMAdapter)
    mock_gemini.generate = AsyncMock(
        return_value=_create_mock_response(LLMProvider.GEMINI, "gemini-3.7-flash", "Fallback code analysis")
    )

    router = LLMRouter(adapters={
        LLMProvider.HUGGINGFACE: mock_hf,
        LLMProvider.GEMINI: mock_gemini,
        LLMProvider.GROQ: MagicMock(spec=BaseLLMAdapter),
    })

    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Fix function")],
        task_policy=TaskPolicy.INTEGRATION_CODE,
    )

    response = await router.generate(request)
    assert response.provider == LLMProvider.GEMINI
    assert response.model == "gemini-3.7-flash"
    assert response.content == "Fallback code analysis"
    # HF fails transiently with RateLimitError -> retried 2 times (total 3 attempts)
    assert mock_hf.generate.call_count == 3
    mock_gemini.generate.assert_called_once()


@pytest.mark.asyncio
async def test_router_all_fallbacks_failed():
    """Verify router raises LLMAllFallbacksFailedError when primary and all fallbacks fail."""
    mock_groq = MagicMock(spec=BaseLLMAdapter)
    mock_groq.generate = AsyncMock(
        side_effect=LLMAuthenticationError("Groq key invalid", provider=LLMProvider.GROQ, model="openai/gpt-oss-120b")
    )

    mock_nvidia = MagicMock(spec=BaseLLMAdapter)
    mock_nvidia.generate = AsyncMock(
        side_effect=LLMRateLimitError("NVIDIA rate limit", provider=LLMProvider.NVIDIA, model="poolside/laguna-xs-2.1")
    )

    mock_gemini = MagicMock(spec=BaseLLMAdapter)
    mock_gemini.generate = AsyncMock(
        side_effect=LLMAuthenticationError("Gemini key missing", provider=LLMProvider.GEMINI, model="gemini-3.7-flash")
    )

    router = LLMRouter(adapters={
        LLMProvider.GROQ: mock_groq,
        LLMProvider.NVIDIA: mock_nvidia,
        LLMProvider.GEMINI: mock_gemini,
    })

    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Check security")],
        task_policy=TaskPolicy.SECURITY_REASONING,
    )

    with pytest.raises(LLMAllFallbacksFailedError) as exc_info:
        await router.generate(request)

    assert len(exc_info.value.attempted_errors) == 3
    assert "All LLM candidate models for policy 'security_reasoning' failed" in str(exc_info.value)
    # Groq (auth error) called once without retrying permanent error
    assert mock_groq.generate.call_count == 1
    # Nvidia (rate limit error) retried 2 times (3 calls total)
    assert mock_nvidia.generate.call_count == 3
    # Gemini (auth error) called once
    assert mock_gemini.generate.call_count == 1
