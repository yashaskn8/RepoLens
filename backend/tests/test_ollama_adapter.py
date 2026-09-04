"""Offline tests for opt-in, low-risk Ollama execution and fallback."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.config import Settings
from app.llm.adapters.ollama import OllamaAdapter
from app.llm.base import BaseLLMAdapter
from app.llm.capabilities import ModelCapabilityRegistry
from app.llm.exceptions import LLMError
from app.llm.router import LLMRouter
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
    TaskPolicy,
)
from app.schemas.metadata import ModelExecutionMetadata


def _response(provider: LLMProvider, model: str) -> LLMResponse:
    return LLMResponse(
        content="cloud fallback",
        provider=provider,
        model=model,
        metadata=ModelExecutionMetadata(model_name=model, provider=provider.value),
    )


@pytest.mark.asyncio
async def test_ollama_normalizes_chat_response_without_live_server() -> None:
    adapter = OllamaAdapter(enabled=True, model="local-test", timeout=1)
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "model": "local-test@sha256:abc",
        "message": {"role": "assistant", "content": '{"kind":"summary"}'},
        "done": True,
        "done_reason": "stop",
        "prompt_eval_count": 8,
        "eval_count": 4,
    }
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Summarize facts")],
        json_mode=True,
        max_tokens=64,
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=response)) as post:
        result = await adapter.generate(request)

    assert result.provider == LLMProvider.OLLAMA
    assert result.model == "local-test@sha256:abc"
    assert result.metadata.total_tokens == 12
    assert result.metadata.extra_metadata == {
        "local_execution": True,
        "cloud_execution": False,
    }
    payload = post.await_args.kwargs["json"]
    assert payload["stream"] is False
    assert payload["format"] == "json"
    assert payload["options"]["num_predict"] == 64


@pytest.mark.asyncio
async def test_ollama_disabled_fails_before_network() -> None:
    adapter = OllamaAdapter(enabled=False)
    with patch("httpx.AsyncClient.post", new=AsyncMock()) as post:
        with pytest.raises(LLMError, match="disabled") as error:
            await adapter.generate(
                LLMRequest(messages=[LLMMessage(role="user", content="classify")])
            )
    assert error.value.retryable is False
    post.assert_not_awaited()


@pytest.mark.asyncio
async def test_ollama_transport_failure_enters_fast_cooldown() -> None:
    adapter = OllamaAdapter(
        enabled=True,
        timeout=0.1,
        failure_cooldown_seconds=30,
    )
    request = LLMRequest(messages=[LLMMessage(role="user", content="classify")])
    transport = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

    with patch("httpx.AsyncClient.post", new=transport):
        with pytest.raises(LLMError, match="Network connection failure"):
            await adapter.generate(request)
        with pytest.raises(LLMError, match="failure cooldown"):
            await adapter.generate(request)

    assert transport.await_count == 1
    assert adapter.cooldown_remaining_seconds > 0


def test_ollama_rejects_non_loopback_transport() -> None:
    with pytest.raises(ValueError, match="loopback"):
        OllamaAdapter(enabled=True, base_url="https://example.com")


def test_ollama_registry_is_low_risk_and_opt_in() -> None:
    enabled = Settings(_env_file=None, LOCAL_LLM_ENABLED=True)
    registry = ModelCapabilityRegistry.from_settings(enabled)

    assert registry.candidates(ModelCapability.CLASSIFICATION)[0].provider == LLMProvider.OLLAMA
    assert all(
        item.provider != LLMProvider.OLLAMA
        for capability in (
            ModelCapability.SECURITY_REASONING,
            ModelCapability.VERIFICATION,
            ModelCapability.PATCH_GENERATION,
            ModelCapability.REPOSITORY_ANALYSIS,
        )
        for item in registry.candidates(capability)
    )


@pytest.mark.asyncio
async def test_ollama_failure_falls_back_once_to_existing_cloud_route(monkeypatch) -> None:
    settings = Settings(_env_file=None, LOCAL_LLM_ENABLED=True, LLM_MAX_RETRIES=2)
    monkeypatch.setattr("app.llm.router.get_settings", lambda: settings)
    local = OllamaAdapter(enabled=True, failure_cooldown_seconds=30)
    cloud = MagicMock(spec=BaseLLMAdapter)
    cloud.generate = AsyncMock(
        return_value=_response(LLMProvider.CLOUDFLARE, settings.CLOUDFLARE_DEFAULT_MODEL)
    )
    fallback = MagicMock(spec=BaseLLMAdapter)
    router = LLMRouter(
        adapters={
            LLMProvider.OLLAMA: local,
            LLMProvider.CLOUDFLARE: cloud,
            LLMProvider.MISTRAL: fallback,
        }
    )
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Briefly summarize these facts")]
    )

    with patch(
        "httpx.AsyncClient.post",
        new=AsyncMock(side_effect=httpx.ConnectError("connection refused")),
    ) as local_post:
        result = await router.generate(request)

    assert result.provider == LLMProvider.CLOUDFLARE
    assert local_post.await_count == 1
    cloud.generate.assert_awaited_once()
    fallback.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_explicit_ollama_rejects_risky_policy_before_cache_or_network() -> None:
    local = OllamaAdapter(enabled=True)
    router = LLMRouter(adapters={LLMProvider.OLLAMA: local})
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="classify these facts")],
        provider=LLMProvider.OLLAMA,
        task_policy=TaskPolicy.SECURITY_REASONING,
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock()) as local_post:
        with pytest.raises(ValueError, match="low-risk"):
            await router.generate(request)

    local_post.assert_not_awaited()


def test_sensitive_simple_prompt_is_not_local_model_eligible() -> None:
    request = LLMRequest(
        messages=[
            LLMMessage(
                role="user",
                content="Briefly classify this GitHub write authorization decision",
            )
        ]
    )

    from app.llm.classifier import TaskClassifier

    assert TaskClassifier.local_model_eligible(request) is False
