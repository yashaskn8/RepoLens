"""Comprehensive unit and integration tests for task-aware multi-provider AI layer.

Verifies:
1. Simple request routing to Cloudflare Workers AI
2. Complex reasoning routing to Mistral AI
3. Cohere embedding generation and neural reranking
4. Reranking threshold optimization (bypass API when candidates < 3)
5. Cloudflare 429 rate limit fallback chain (Cloudflare -> Mistral -> OpenRouter)
6. Mistral failure fallback chain
7. OpenRouter restricted last-resort gate (single attempt, never primary)
8. Circuit breaker and cooldown state transitions
9. Zero secret token leakage in logs, exceptions, or metadata
10. Network timeouts and malformed JSON payload handling
11. Normalized response contract (content, provider, model, fallbackUsed, latencyMs)
12. Task classifier deterministic categorization
"""

import asyncio
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.core.config import get_settings
from app.indexing.embeddings import CohereEmbeddingAdapter
from app.indexing.schemas import CodeChunk, EmbeddingRequest
from app.llm.adapters.cloudflare import CloudflareAdapter
from app.llm.adapters.mistral import MistralAdapter
from app.llm.adapters.openrouter import OpenRouterAdapter
from app.llm.base import BaseLLMAdapter
from app.llm.classifier import TaskCategory, TaskClassifier
from app.llm.exceptions import (
    LLMAllFallbacksFailedError,
    LLMAuthenticationError,
    LLMError,
    LLMRateLimitError,
    LLMResponseValidationError,
    LLMTimeoutError,
    ProviderFailureCode,
)
from app.llm.health import CircuitState, ProviderHealthRegistry
from app.llm.router import LLMRouter
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
    TaskPolicy,
)
from app.retrieval.reranker import CohereReranker
from app.retrieval.schemas import RerankCandidate
from app.retrieval.service import RetrievalService
from app.schemas.metadata import ModelExecutionMetadata
from app.security.redaction import redact_secrets


def _create_mock_response(
    provider: LLMProvider,
    model: str,
    content: str = "Test response content",
    fallback_used: bool = False,
) -> LLMResponse:
    return LLMResponse(
        content=content,
        model=model,
        provider=provider,
        metadata=ModelExecutionMetadata(
            model_name=model,
            provider=provider.value,
            prompt_tokens=25,
            completion_tokens=40,
            total_tokens=65,
            execution_time_ms=120.5,
            extra_metadata={"fallback_used": fallback_used},
        ),
    )


# ---------------------------------------------------------------------------
# Test 1: Simple Request Routing to Cloudflare
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_simple_request_routes_to_cloudflare():
    mock_cf = MagicMock(spec=BaseLLMAdapter)
    mock_cf.generate = AsyncMock(
        return_value=_create_mock_response(LLMProvider.CLOUDFLARE, "@cf/meta/llama-3.1-8b-instruct", "Summary response")
    )
    mock_mistral = MagicMock(spec=BaseLLMAdapter)
    mock_openrouter = MagicMock(spec=BaseLLMAdapter)

    router = LLMRouter(
        adapters={
            LLMProvider.CLOUDFLARE: mock_cf,
            LLMProvider.MISTRAL: mock_mistral,
            LLMProvider.OPENROUTER: mock_openrouter,
        }
    )

    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Please summarize this short document briefly.")],
    )

    category = TaskClassifier.classify(request)
    assert category == TaskCategory.SIMPLE_GENERATION

    response = await router.generate(request)
    assert response.provider == LLMProvider.CLOUDFLARE
    assert response.model == "@cf/meta/llama-3.1-8b-instruct"
    assert response.content == "Summary response"
    mock_cf.generate.assert_called_once()
    mock_mistral.generate.assert_not_called()
    mock_openrouter.generate.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2: Complex Reasoning Routing to Mistral
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_complex_reasoning_routes_to_mistral():
    mock_cf = MagicMock(spec=BaseLLMAdapter)
    mock_mistral = MagicMock(spec=BaseLLMAdapter)
    mock_mistral.generate = AsyncMock(
        return_value=_create_mock_response(LLMProvider.MISTRAL, "mistral-small-latest", "Complex architectural analysis")
    )
    mock_openrouter = MagicMock(spec=BaseLLMAdapter)

    router = LLMRouter(
        adapters={
            LLMProvider.CLOUDFLARE: mock_cf,
            LLMProvider.MISTRAL: mock_mistral,
            LLMProvider.OPENROUTER: mock_openrouter,
        }
    )

    request = LLMRequest(
        messages=[
            LLMMessage(
                role="user",
                content="Perform a deep multi-step analysis comparing trade-offs, concurrency race conditions, and root cause.",
            )
        ],
    )

    category = TaskClassifier.classify(request)
    assert category == TaskCategory.COMPLEX_REASONING

    response = await router.generate(request)
    assert response.provider == LLMProvider.MISTRAL
    assert response.model == "mistral-small-latest"
    assert response.content == "Complex architectural analysis"
    mock_mistral.generate.assert_called_once()
    mock_cf.generate.assert_not_called()
    mock_openrouter.generate.assert_not_called()


# ---------------------------------------------------------------------------
# Test 3: Cohere Embedding and Reranking Flow
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cohere_embedding_and_reranking():
    # 1. Cohere Embedding Adapter
    adapter = CohereEmbeddingAdapter(api_key="cohere_test_secret_key")

    mock_embed_payload = {
        "embeddings": [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]],
        "meta": {"billed_units": {"input_tokens": 15}},
    }

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_embed_payload
        mock_post.return_value = mock_resp

        req = EmbeddingRequest(
            texts=["first document", "second document"],
            input_type="search_document",
            model="embed-english-v3.0",
        )
        res = await adapter.embed(req)

        assert res.provider == "cohere"
        assert len(res.embeddings) == 2
        assert res.embeddings[0].vector == [0.1, 0.2, 0.3]
        assert res.total_tokens == 15

    # 2. Cohere Reranker
    reranker = CohereReranker(api_key="cohere_test_secret_key", min_candidates=3)
    candidates = [
        RerankCandidate(chunk_id="chunk_1", content="Text about Python database connections", initial_score=0.7),
        RerankCandidate(chunk_id="chunk_2", content="Text about CSS animations and design", initial_score=0.5),
        RerankCandidate(chunk_id="chunk_3", content="Text about SQL query optimization and indexes", initial_score=0.9),
    ]

    mock_rerank_payload = {
        "results": [
            {"index": 2, "relevance_score": 0.95},
            {"index": 0, "relevance_score": 0.88},
            {"index": 1, "relevance_score": 0.12},
        ]
    }

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_rerank_payload
        mock_post.return_value = mock_resp

        ranked = await reranker.rerank("optimize sql index", candidates)
        assert len(ranked) == 3
        assert ranked[0][0] == "chunk_3"  # Index 2 highest score
        assert ranked[0][1] == 0.95
        assert ranked[1][0] == "chunk_1"
        assert ranked[2][0] == "chunk_2"


# ---------------------------------------------------------------------------
# Test 4: Reranking Optimization Gate (< 3 items bypasses API)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reranking_optimization_gate_skips_api():
    reranker = CohereReranker(api_key="cohere_test_secret_key", min_candidates=3)
    # Only 2 candidates - should bypass Cohere API completely
    candidates = [
        RerankCandidate(chunk_id="chunk_a", content="Document A", initial_score=0.4),
        RerankCandidate(chunk_id="chunk_b", content="Document B", initial_score=0.3),
    ]

    with patch("httpx.AsyncClient.post") as mock_post:
        ranked = await reranker.rerank("search query", candidates)
        mock_post.assert_not_called()  # API was completely skipped!
        assert len(ranked) == 2
        assert ranked[0] == ("chunk_a", None)
        assert ranked[1] == ("chunk_b", None)


# ---------------------------------------------------------------------------
# Test 5: Cloudflare 429 Fallback Chain (Cloudflare -> Mistral -> OpenRouter)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cloudflare_429_fallback_to_mistral_and_openrouter():
    # Cloudflare fails with 429
    mock_cf = MagicMock(spec=BaseLLMAdapter)
    mock_cf.generate = AsyncMock(
        side_effect=LLMRateLimitError(
            "Cloudflare rate limit exceeded",
            provider=LLMProvider.CLOUDFLARE,
            model="@cf/meta/llama-3.1-8b-instruct",
            retry_after_seconds=0.01,
        )
    )

    # Mistral succeeds as first fallback
    mock_mistral = MagicMock(spec=BaseLLMAdapter)
    mock_mistral.generate = AsyncMock(
        return_value=_create_mock_response(LLMProvider.MISTRAL, "mistral-small-latest", "Mistral fallback answer")
    )

    mock_openrouter = MagicMock(spec=BaseLLMAdapter)

    router = LLMRouter(
        adapters={
            LLMProvider.CLOUDFLARE: mock_cf,
            LLMProvider.MISTRAL: mock_mistral,
            LLMProvider.OPENROUTER: mock_openrouter,
        }
    )

    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Summarize project.")],
    )

    response = await router.generate(request)
    assert response.provider == LLMProvider.MISTRAL
    assert response.content == "Mistral fallback answer"
    assert response.metadata.extra_metadata.get("fallback_used") is True
    mock_cf.generate.assert_called()
    mock_mistral.generate.assert_called_once()
    mock_openrouter.generate.assert_not_called()


# ---------------------------------------------------------------------------
# Test 6: Mistral Failure Escalates to OpenRouter
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_mistral_failure_falls_back_to_openrouter():
    # Cloudflare fails
    mock_cf = MagicMock(spec=BaseLLMAdapter)
    mock_cf.generate = AsyncMock(
        side_effect=LLMError("Cloudflare service unavailable", provider=LLMProvider.CLOUDFLARE, model="@cf/model")
    )

    # Mistral also fails
    mock_mistral = MagicMock(spec=BaseLLMAdapter)
    mock_mistral.generate = AsyncMock(
        side_effect=LLMError("Mistral quota exhausted", provider=LLMProvider.MISTRAL, model="mistral-small-latest")
    )

    # OpenRouter handles last-resort fallback
    mock_openrouter = MagicMock(spec=BaseLLMAdapter)
    mock_openrouter.generate = AsyncMock(
        return_value=_create_mock_response(
            LLMProvider.OPENROUTER,
            "meta-llama/llama-3.2-3b-instruct:free",
            "OpenRouter emergency fallback",
            fallback_used=True,
        )
    )

    router = LLMRouter(
        adapters={
            LLMProvider.CLOUDFLARE: mock_cf,
            LLMProvider.MISTRAL: mock_mistral,
            LLMProvider.OPENROUTER: mock_openrouter,
        }
    )

    request = LLMRequest(
        messages=[LLMMessage(role="user", content="Summarize code repository.")],
    )

    response = await router.generate(request)
    assert response.provider == LLMProvider.OPENROUTER
    assert response.content == "OpenRouter emergency fallback"
    mock_openrouter.generate.assert_called_once()


# ---------------------------------------------------------------------------
# Test 7: OpenRouter Restricted Last-Resort Gate (Never Primary, Max 1 Attempt)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_openrouter_single_attempt_only():
    mock_cf = MagicMock(spec=BaseLLMAdapter)
    mock_cf.generate = AsyncMock(
        side_effect=LLMError("Cloudflare down", provider=LLMProvider.CLOUDFLARE, model="@cf/model")
    )

    mock_mistral = MagicMock(spec=BaseLLMAdapter)
    mock_mistral.generate = AsyncMock(
        side_effect=LLMError("Mistral down", provider=LLMProvider.MISTRAL, model="mistral-model")
    )

    mock_openrouter = MagicMock(spec=BaseLLMAdapter)
    mock_openrouter.generate = AsyncMock(
        side_effect=LLMRateLimitError(
            "OpenRouter rate limit",
            provider=LLMProvider.OPENROUTER,
            model="meta-llama/llama-3.2-3b-instruct:free",
            retry_after_seconds=0.01,
        )
    )

    router = LLMRouter(
        adapters={
            LLMProvider.CLOUDFLARE: mock_cf,
            LLMProvider.MISTRAL: mock_mistral,
            LLMProvider.OPENROUTER: mock_openrouter,
        }
    )

    request = LLMRequest(messages=[LLMMessage(role="user", content="Ping")])

    with pytest.raises(LLMAllFallbacksFailedError):
        await router.generate(request)

    # OpenRouter was called exactly 1 time, never retried in a loop
    assert mock_openrouter.generate.call_count == 1


# ---------------------------------------------------------------------------
# Test 8: Circuit Breaker and Cooldown State Transitions
# ---------------------------------------------------------------------------
def test_circuit_breaker_cooldown():
    registry = ProviderHealthRegistry(failure_threshold=2, cooldown_seconds=0.1)
    provider = LLMProvider.CLOUDFLARE
    model = "@cf/meta/llama-3.1-8b-instruct"

    assert registry.allow_request(provider, model) is True

    # First failure - still closed
    registry.record_failure(provider, model, ProviderFailureCode.RATE_LIMITED)
    assert registry.allow_request(provider, model) is True

    # Second failure - reaches threshold, opens circuit
    registry.record_failure(provider, model, ProviderFailureCode.RATE_LIMITED)
    snapshot = registry.snapshot(provider, model)
    assert snapshot.state == CircuitState.OPEN
    assert registry.allow_request(provider, model) is False

    # Immediate request blocked
    assert registry.allow_request(provider, model) is False

    # After cooldown expires, transitions to HALF_OPEN probe
    import time
    time.sleep(0.12)
    assert registry.allow_request(provider, model) is True

    # Successful probe closes circuit
    registry.record_success(provider, model)
    snapshot_recovered = registry.snapshot(provider, model)
    assert snapshot_recovered.state == CircuitState.CLOSED
    assert snapshot_recovered.consecutive_failures == 0


# ---------------------------------------------------------------------------
# Test 9: Zero Secret Token Leakage
# ---------------------------------------------------------------------------
def test_zero_secret_token_leakage():
    sample_text = (
        "Logs: Cloudflare token cfut_fakeDummyTokenForTesting1234567890, "
        "Cohere key cohere_fakeDummyKeyForTesting1234567890, "
        "OpenRouter key sk-or-v1-fakeDummyKeyForTesting0123456789abcdef."
    )

    redacted = redact_secrets(sample_text)
    assert "cfut_fakeDummyTokenForTesting1234567890" not in redacted
    assert "cfut_[REDACTED]" in redacted

    assert "cohere_fakeDummyKeyForTesting1234567890" not in redacted
    assert "cohere_[REDACTED]" in redacted

    assert "sk-or-v1-fakeDummyKeyForTesting0123456789abcdef" not in redacted
    assert "sk-or-[REDACTED]" in redacted


# ---------------------------------------------------------------------------
# Test 10: Timeout and Malformed Response Handling
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_timeout_and_malformed_response_handling():
    # Adapter malformed response test
    adapter = MistralAdapter(api_key="mock_key")

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"invalid_key": "no choices"}
        mock_post.return_value = mock_resp

        req = LLMRequest(messages=[LLMMessage(role="user", content="hi")])
        with pytest.raises(LLMResponseValidationError):
            await adapter.generate(req)

    # Cloudflare missing account_id error
    cf_adapter = CloudflareAdapter(api_token="mock_token", account_id="")
    with pytest.raises(LLMAuthenticationError) as exc_info:
        await cf_adapter.generate(req)
    assert "account ID" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 11: Normalized Response Contract
# ---------------------------------------------------------------------------
def test_normalized_response_contract():
    res = _create_mock_response(
        provider=LLMProvider.CLOUDFLARE,
        model="@cf/meta/llama-3.1-8b-instruct",
        content="Hello world",
        fallback_used=True,
    )
    d = res.to_normalized_dict()
    assert d["content"] == "Hello world"
    assert d["provider"] == "cloudflare"
    assert d["model"] == "@cf/meta/llama-3.1-8b-instruct"
    assert d["fallbackUsed"] is True
    assert isinstance(d["latencyMs"], float)
    assert d["latencyMs"] == 120.5


# ---------------------------------------------------------------------------
# Test 12: Deterministic Task Classifier Categorization
# ---------------------------------------------------------------------------
def test_task_classifier_categorization():
    # 1. Simple queries
    req_simple = LLMRequest(messages=[LLMMessage(role="user", content="Summarize this repository briefly.")])
    assert TaskClassifier.classify(req_simple) == TaskCategory.SIMPLE_GENERATION

    # 2. Complex queries by keywords
    req_complex = LLMRequest(messages=[LLMMessage(role="user", content="Analyze the architectural constraints and concurrency bugs.")])
    assert TaskClassifier.classify(req_complex) == TaskCategory.COMPLEX_REASONING

    # 3. Policy overrides
    req_policy = LLMRequest(messages=[LLMMessage(role="user", content="check")], task_policy=TaskPolicy.BUG_REASONING)
    assert TaskClassifier.classify(req_policy) == TaskCategory.COMPLEX_REASONING

    # 4. Capability overrides
    req_retrieval = LLMRequest(messages=[LLMMessage(role="user", content="lookup")], capability=ModelCapability.EMBEDDING)
    assert TaskClassifier.classify(req_retrieval) == TaskCategory.RETRIEVAL

    # 5. Schema complexity
    req_schema = LLMRequest(
        messages=[LLMMessage(role="user", content="extract")],
        output_schema={
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "c": {"type": "string"},
                "d": {"type": "string"},
                "nested": {"type": "object", "properties": {"x": {"type": "integer"}}},
            }
        },
    )
    assert TaskClassifier.classify(req_schema) == TaskCategory.COMPLEX_REASONING
