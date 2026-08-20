"""Unit tests for LLM error normalization, timeouts, and authentication validation."""

import pytest
import httpx
from unittest.mock import patch, MagicMock

from app.llm.adapters import GeminiAdapter, GroqAdapter
from app.llm.exceptions import (
    LLMAuthenticationError,
    LLMError,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMResponseValidationError,
    LLMTimeoutError,
)
from app.llm.types import LLMMessage, LLMRequest


@pytest.mark.asyncio
async def test_missing_api_key_raises_auth_error():
    """Verify adapter raises LLMAuthenticationError immediately if API key is empty."""
    adapter = GroqAdapter(api_key="")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="openai/gpt-oss-120b",
    )
    with pytest.raises(LLMAuthenticationError) as exc_info:
        await adapter.generate(request)
    assert "Groq API key is not configured" in str(exc_info.value)


@pytest.mark.asyncio
async def test_http_401_raises_auth_error():
    """Verify HTTP 401 response is normalized into LLMAuthenticationError."""
    mock_client = MagicMock()
    mock_post_res = MagicMock(status_code=401, text="Unauthorized token")
    mock_post_res.json.return_value = {"error": {"message": "Invalid API key"}}

    async def mock_post(*args, **kwargs):
        return mock_post_res

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = GroqAdapter(api_key="invalid_key")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="openai/gpt-oss-120b",
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(LLMAuthenticationError) as exc_info:
            await adapter.generate(request)
        assert exc_info.value.status_code == 401
        assert exc_info.value.retryable is False


@pytest.mark.asyncio
async def test_http_429_raises_rate_limit_error():
    """Verify HTTP 429 response is normalized into LLMRateLimitError."""
    mock_client = MagicMock()
    mock_post_res = MagicMock(
        status_code=429,
        text="Rate limit exceeded",
        headers={"retry-after": "5"},
    )
    mock_post_res.json.return_value = {"error": {"message": "Quota exceeded"}}

    async def mock_post(*args, **kwargs):
        return mock_post_res

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = GroqAdapter(api_key="valid_key")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="openai/gpt-oss-120b",
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(LLMRateLimitError) as exc_info:
            await adapter.generate(request)
        assert exc_info.value.status_code == 429
        assert exc_info.value.retryable is True
        assert exc_info.value.retry_after_seconds == 5.0


@pytest.mark.asyncio
async def test_http_503_raises_provider_unavailable_error():
    """Verify HTTP 503 response is normalized into LLMProviderUnavailableError."""
    mock_client = MagicMock()
    mock_post_res = MagicMock(status_code=503, text="Service Unavailable")
    mock_post_res.json.side_effect = Exception("Not JSON")

    async def mock_post(*args, **kwargs):
        return mock_post_res

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = GeminiAdapter(api_key="valid_key")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="gemini-3.7-flash",
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(LLMProviderUnavailableError) as exc_info:
            await adapter.generate(request)
        assert exc_info.value.status_code == 503
        assert exc_info.value.retryable is True


@pytest.mark.asyncio
async def test_transport_timeout_raises_llm_timeout_error():
    """Verify httpx.TimeoutException is normalized into LLMTimeoutError."""
    mock_client = MagicMock()

    async def mock_post(*args, **kwargs):
        raise httpx.ReadTimeout("Read timed out")

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = GeminiAdapter(api_key="valid_key")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="gemini-3.7-flash",
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(LLMTimeoutError) as exc_info:
            await adapter.generate(request)
        assert exc_info.value.retryable is True


@pytest.mark.asyncio
async def test_empty_candidates_raises_validation_error():
    """Verify empty candidates/choices payload raises LLMResponseValidationError."""
    mock_client = MagicMock()
    mock_post_res = MagicMock(status_code=200)
    mock_post_res.json.return_value = {"candidates": []}

    async def mock_post(*args, **kwargs):
        return mock_post_res

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = GeminiAdapter(api_key="valid_key")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="gemini-3.7-flash",
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(LLMResponseValidationError) as exc_info:
            await adapter.generate(request)
        assert "empty candidates" in str(exc_info.value)
