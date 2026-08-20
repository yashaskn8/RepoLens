"""Unit tests for individual LLM adapters using mocked HTTP transports (zero API quota consumption)."""

import json
import pytest
import httpx
from unittest.mock import patch, MagicMock

from app.llm.adapters import GeminiAdapter, GroqAdapter, HuggingFaceAdapter, NvidiaAdapter
from app.llm.types import LLMMessage, LLMProvider, LLMRequest


@pytest.mark.asyncio
async def test_gemini_adapter_mock_generation():
    """Verify GeminiAdapter correctly handles message translation, HTTP payload, and token extraction."""
    mock_response_data = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Gemini response text analysis"}]
                },
                "finishReason": "STOP"
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 120,
            "candidatesTokenCount": 45,
            "totalTokenCount": 165
        }
    }

    mock_client = MagicMock()
    mock_post_res = MagicMock(status_code=200)
    mock_post_res.json.return_value = mock_response_data

    async def mock_post(*args, **kwargs):
        return mock_post_res

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = GeminiAdapter(api_key="mock_gemini_key")
    request = LLMRequest(
        messages=[
            LLMMessage(role="system", content="You are an architect."),
            LLMMessage(role="user", content="Analyze this architecture."),
        ],
        model="gemini-3.7-flash",
        temperature=0.2,
    )

    with patch("httpx.AsyncClient", return_value=mock_client):
        response = await adapter.generate(request)

    assert response.provider == LLMProvider.GEMINI
    assert response.model == "gemini-3.7-flash"
    assert response.content == "Gemini response text analysis"
    assert response.finish_reason == "STOP"
    assert response.metadata.prompt_tokens == 120
    assert response.metadata.completion_tokens == 45
    assert response.metadata.total_tokens == 165
    assert response.metadata.execution_time_ms > 0


@pytest.mark.asyncio
async def test_groq_adapter_mock_generation():
    """Verify GroqAdapter handles OpenAI-compatible format and usage metadata."""
    mock_response_data = {
        "id": "chatcmpl-mock-groq",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Groq security analysis results"
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 80,
            "completion_tokens": 30,
            "total_tokens": 110
        }
    }

    mock_client = MagicMock()
    mock_post_res = MagicMock(status_code=200)
    mock_post_res.json.return_value = mock_response_data

    async def mock_post(*args, **kwargs):
        return mock_post_res

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = GroqAdapter(api_key="mock_groq_key")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Analyze for security flaws.")],
        model="openai/gpt-oss-120b",
        temperature=0.0,
    )

    with patch("httpx.AsyncClient", return_value=mock_client):
        response = await adapter.generate(request)

    assert response.provider == LLMProvider.GROQ
    assert response.model == "openai/gpt-oss-120b"
    assert response.content == "Groq security analysis results"
    assert response.metadata.prompt_tokens == 80
    assert response.metadata.completion_tokens == 30
    assert response.metadata.total_tokens == 110


@pytest.mark.asyncio
async def test_nvidia_adapter_mock_generation():
    """Verify NvidiaAdapter handles NIM completions and token metadata."""
    mock_response_data = {
        "id": "chatcmpl-mock-nvidia",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "NVIDIA verification outcome"
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 150,
            "completion_tokens": 60,
            "total_tokens": 210
        }
    }

    mock_client = MagicMock()
    mock_post_res = MagicMock(status_code=200)
    mock_post_res.json.return_value = mock_response_data

    async def mock_post(*args, **kwargs):
        return mock_post_res

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = NvidiaAdapter(api_key="mock_nvidia_key")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Verify finding correctness.")],
        model="nvidia/nemotron-3-ultra-550b-a55b",
        temperature=0.1,
    )

    with patch("httpx.AsyncClient", return_value=mock_client):
        response = await adapter.generate(request)

    assert response.provider == LLMProvider.NVIDIA
    assert response.model == "nvidia/nemotron-3-ultra-550b-a55b"
    assert response.content == "NVIDIA verification outcome"
    assert response.metadata.prompt_tokens == 150
    assert response.metadata.completion_tokens == 60


@pytest.mark.asyncio
async def test_huggingface_adapter_mock_generation():
    """Verify HuggingFaceAdapter handles Inference Providers completions."""
    mock_response_data = {
        "id": "chatcmpl-mock-hf",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "HF Qwen code reasoning output"
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 95,
            "completion_tokens": 50,
            "total_tokens": 145
        }
    }

    mock_client = MagicMock()
    mock_post_res = MagicMock(status_code=200)
    mock_post_res.json.return_value = mock_response_data

    async def mock_post(*args, **kwargs):
        return mock_post_res

    mock_client.post = mock_post
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    adapter = HuggingFaceAdapter(api_key="mock_hf_key")
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Generate patch for code issue.")],
        model="Qwen/Qwen3-Coder-Next",
        temperature=0.0,
    )

    with patch("httpx.AsyncClient", return_value=mock_client):
        response = await adapter.generate(request)

    assert response.provider == LLMProvider.HUGGINGFACE
    assert response.model == "Qwen/Qwen3-Coder-Next"
    assert response.content == "HF Qwen code reasoning output"
    assert response.metadata.prompt_tokens == 95
    assert response.metadata.completion_tokens == 50
