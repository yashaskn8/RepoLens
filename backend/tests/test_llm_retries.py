"""Tests for LLM retry behavior, exponential backoff, jitter calculation, non-retryable error handling, and telemetry metadata."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import (
    LLMAllFallbacksFailedError,
    LLMAuthenticationError,
    LLMError,
    LLMRateLimitError,
    LLMResponseValidationError,
    LLMTimeoutError,
)
from app.llm.router import LLMRouter, _calculate_retry_delay
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    TaskPolicy,
)
from app.schemas.metadata import ModelExecutionMetadata


def _make_response(provider: LLMProvider, model: str, content: str = "success") -> LLMResponse:
    return LLMResponse(
        content=content,
        model=model,
        provider=provider,
        metadata=ModelExecutionMetadata(
            model_name=model,
            provider=provider.value,
            prompt_tokens=15,
            completion_tokens=25,
            total_tokens=40,
            execution_time_ms=120.0,
            extra_metadata={},
        ),
    )


def test_calculate_retry_delay_exponential_with_jitter_range():
    """Verify _calculate_retry_delay calculates base exponential delay with bounded jitter."""
    # attempt 0: base = 0.2, max_jitter = min(0.05, 0.25) = 0.05
    with patch("random.uniform", return_value=0.03):
        delay = _calculate_retry_delay(attempt=0)
        assert delay == pytest.approx(0.23)

    # attempt 1: base = 0.4, max_jitter = min(0.10, 0.25) = 0.10
    with patch("random.uniform", return_value=0.08):
        delay = _calculate_retry_delay(attempt=1)
        assert delay == pytest.approx(0.48)


def test_calculate_retry_delay_never_exceeds_maximum_cap():
    """Verify _calculate_retry_delay strictly caps total delay at max_delay even with large attempts or jitter."""
    # attempt 5: base = 6.4 -> capped at 2.0. max_jitter = 0.25. If random returns 0.25, total capped at 2.0
    with patch("random.uniform", return_value=0.25):
        delay = _calculate_retry_delay(attempt=5, max_delay=2.0)
        assert delay <= 2.0
        assert delay == 2.0


def test_calculate_retry_delay_respects_retry_after_header():
    """Verify Retry-After is respected as the authoritative base delay with bounded jitter."""
    exc = LLMRateLimitError("Rate limit", retry_after_seconds=1.2)
    # base = 1.2, max_jitter = min(0.30, 0.25) = 0.25
    with patch("random.uniform", return_value=0.15):
        delay = _calculate_retry_delay(attempt=0, exc=exc, max_delay=2.0)
        assert delay == pytest.approx(1.35)

    # Large Retry-After should be capped at max_delay
    large_exc = LLMRateLimitError("Rate limit", retry_after_seconds=10.0)
    delay_large = _calculate_retry_delay(attempt=0, exc=large_exc, max_delay=2.0)
    assert delay_large <= 2.0


@pytest.mark.asyncio
async def test_transient_error_retries_and_succeeds_with_metadata():
    """Verify that a transient error (e.g. RateLimit) retries and succeeds, recording retry_count."""
    mock_gemini = MagicMock(spec=BaseLLMAdapter)
    mock_gemini.generate = AsyncMock(
        side_effect=[
            LLMRateLimitError("Rate limit exceeded", provider=LLMProvider.GEMINI, model="gemini-3.7-flash"),
            _make_response(LLMProvider.GEMINI, "gemini-3.7-flash", "Retried success"),
        ]
    )

    router = LLMRouter(adapters={LLMProvider.GEMINI: mock_gemini})
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Hello")],
        task_policy=TaskPolicy.ARCHITECTURE,
    )

    with patch("asyncio.sleep", AsyncMock()) as mock_sleep, \
         patch("random.uniform", return_value=0.02):
        response = await router.generate(request)

    assert response.content == "Retried success"
    assert response.provider == LLMProvider.GEMINI
    assert mock_gemini.generate.call_count == 2
    mock_sleep.assert_called_once()
    assert response.metadata.extra_metadata.get("retry_count") == 1


@pytest.mark.asyncio
async def test_non_retryable_error_does_not_retry_and_triggers_fallback():
    """Verify that a non-retryable error (e.g. 401 Auth) does NOT retry and immediately falls back."""
    mock_hf = MagicMock(spec=BaseLLMAdapter)
    mock_hf.generate = AsyncMock(
        side_effect=LLMAuthenticationError("Invalid HF token", provider=LLMProvider.HUGGINGFACE, model="Qwen/Qwen3-Coder-Next")
    )

    mock_gemini = MagicMock(spec=BaseLLMAdapter)
    mock_gemini.generate = AsyncMock(
        return_value=_make_response(LLMProvider.GEMINI, "gemini-3.7-flash", "Fallback from auth error")
    )

    router = LLMRouter(adapters={
        LLMProvider.HUGGINGFACE: mock_hf,
        LLMProvider.GEMINI: mock_gemini,
        LLMProvider.GROQ: MagicMock(spec=BaseLLMAdapter),
    })

    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Generate patch")],
        task_policy=TaskPolicy.INTEGRATION_CODE,
    )

    with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
        response = await router.generate(request)

    assert response.content == "Fallback from auth error"
    assert response.provider == LLMProvider.GEMINI
    # HF should be called exactly ONCE because auth error is not retryable
    assert mock_hf.generate.call_count == 1
    mock_sleep.assert_not_called()
    assert mock_gemini.generate.call_count == 1
    assert "fallbacks_attempted" in response.metadata.extra_metadata
    assert len(response.metadata.extra_metadata["fallbacks_attempted"]) == 1
    assert response.metadata.extra_metadata["fallbacks_attempted"][0]["provider"] == "huggingface"


@pytest.mark.asyncio
async def test_explicit_provider_transient_retry_and_metadata():
    """Verify explicit provider override retries transient failures with metadata tracking."""
    mock_groq = MagicMock(spec=BaseLLMAdapter)
    mock_groq.generate = AsyncMock(
        side_effect=[
            LLMTimeoutError("Groq timeout", provider=LLMProvider.GROQ, model="openai/gpt-oss-120b"),
            _make_response(LLMProvider.GROQ, "openai/gpt-oss-120b", "Direct retry success"),
        ]
    )

    router = LLMRouter(adapters={LLMProvider.GROQ: mock_groq})
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Security check")],
        provider=LLMProvider.GROQ,
    )

    with patch("asyncio.sleep", AsyncMock()) as mock_sleep, \
         patch("random.uniform", return_value=0.01):
        response = await router.generate(request)

    assert response.content == "Direct retry success"
    assert mock_groq.generate.call_count == 2
    mock_sleep.assert_called_once()
    assert response.metadata.extra_metadata.get("retry_count") == 1


@pytest.mark.asyncio
async def test_max_retries_caps_transient_retry_attempts():
    """Verify settings.LLM_MAX_RETRIES strictly caps the number of retry attempts."""
    mock_gemini = MagicMock(spec=BaseLLMAdapter)
    mock_gemini.generate = AsyncMock(
        side_effect=LLMRateLimitError("Gemini 429", provider=LLMProvider.GEMINI, model="gemini-3.7-flash")
    )

    router = LLMRouter(adapters={LLMProvider.GEMINI: mock_gemini})
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Hello")],
        provider=LLMProvider.GEMINI,
    )

    with patch("asyncio.sleep", AsyncMock()) as mock_sleep, \
         patch("random.uniform", return_value=0.01):
        with pytest.raises(LLMRateLimitError):
            await router.generate(request)

    # Initial attempt (1) + 2 retries (LLM_MAX_RETRIES=2) = 3 calls
    assert mock_gemini.generate.call_count == 3
    assert mock_sleep.call_count == 2


@pytest.mark.asyncio
async def test_all_retries_and_fallbacks_exhausted():
    """Verify LLMAllFallbacksFailedError is raised with complete error history when all candidates fail."""
    mock_gemini = MagicMock(spec=BaseLLMAdapter)
    mock_gemini.generate = AsyncMock(
        side_effect=LLMRateLimitError("Gemini 429", provider=LLMProvider.GEMINI, model="gemini-3.7-flash")
    )

    mock_groq = MagicMock(spec=BaseLLMAdapter)
    mock_groq.generate = AsyncMock(
        side_effect=LLMAuthenticationError("Groq 401", provider=LLMProvider.GROQ, model="openai/gpt-oss-120b")
    )

    mock_nvidia = MagicMock(spec=BaseLLMAdapter)
    mock_nvidia.generate = AsyncMock(
        side_effect=LLMResponseValidationError("Nvidia bad JSON", provider=LLMProvider.NVIDIA, model="poolside/laguna-xs-2.1")
    )

    router = LLMRouter(adapters={
        LLMProvider.GEMINI: mock_gemini,
        LLMProvider.GROQ: mock_groq,
        LLMProvider.NVIDIA: mock_nvidia,
    })

    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Architecture query")],
        task_policy=TaskPolicy.ARCHITECTURE,
    )

    with patch("asyncio.sleep", AsyncMock()), \
         patch("random.uniform", return_value=0.01):
        with pytest.raises(LLMAllFallbacksFailedError) as exc_info:
            await router.generate(request)

    assert len(exc_info.value.attempted_errors) == 3
    assert "All LLM candidate models for policy 'architecture' failed" in str(exc_info.value)
