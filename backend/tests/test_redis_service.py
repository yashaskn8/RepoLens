"""Comprehensive unit and integration test suite for RepoLens Redis foundation.

Tests connection lifecycle, graceful degradation, namespacing, exact-response caching,
provider state synchronization, exception resilience, secret sanitization, and optional
live Redis Cloud connectivity.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
import time
from typing import Any, Dict, Optional

import pytest
from pydantic import BaseModel
from redis.exceptions import ConnectionError as RedisConnectionError, RedisError

from app.core.config import get_settings
from app.core.redis import RedisManager
from app.services.redis_service import RedisService, _deserialize, _serialize


class DummyPydanticModel(BaseModel):
    name: str
    count: int
    tags: list[str]


class MockAsyncRedis:
    """In-memory async Redis mock for isolated offline unit testing."""

    def __init__(self, simulate_network_failure: bool = False) -> None:
        self.storage: Dict[str, str] = {}
        self.ttls: Dict[str, float] = {}
        self.closed: bool = False
        self.simulate_network_failure: bool = simulate_network_failure

    async def ping(self) -> bool:
        if self.simulate_network_failure or self.closed:
            raise RedisConnectionError("Simulated Redis connection failure")
        return True

    async def get(self, key: str) -> Optional[str]:
        if self.simulate_network_failure or self.closed:
            raise RedisConnectionError("Simulated Redis connection error on GET")
        # Check simulated expiration
        if key in self.ttls and time.time() > self.ttls[key]:
            self.storage.pop(key, None)
            self.ttls.pop(key, None)
            return None
        return self.storage.get(key)

    async def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        if self.simulate_network_failure or self.closed:
            raise RedisConnectionError("Simulated Redis connection error on SET")
        self.storage[key] = value
        if ex is not None:
            self.ttls[key] = time.time() + ex
        return True

    async def delete(self, key: str) -> int:
        if self.simulate_network_failure or self.closed:
            raise RedisConnectionError("Simulated Redis connection error on DELETE")
        removed = self.storage.pop(key, None) is not None
        self.ttls.pop(key, None)
        return 1 if removed else 0

    async def exists(self, key: str) -> int:
        if self.simulate_network_failure or self.closed:
            raise RedisConnectionError("Simulated Redis connection error on EXISTS")
        if key in self.ttls and time.time() > self.ttls[key]:
            self.storage.pop(key, None)
            self.ttls.pop(key, None)
            return 0
        return 1 if key in self.storage else 0

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture
def mock_redis_manager() -> RedisManager:
    """Create a RedisManager with MockAsyncRedis injected."""
    manager = RedisManager()
    mock_client = MockAsyncRedis()
    manager.set_client(mock_client, available=True)
    return manager


@pytest.fixture
def redis_service(mock_redis_manager: RedisManager) -> RedisService:
    """Create a RedisService backed by mock_redis_manager."""
    return RedisService(manager=mock_redis_manager)


# ------------------------------------------------------------------------------
# Test 1: Redis connection success (initialization & client availability)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_redis_connection_success(mock_redis_manager: RedisManager):
    service = RedisService(manager=mock_redis_manager)
    assert service.is_available is True
    assert mock_redis_manager.is_available is True
    assert await mock_redis_manager.ping() is True


# ------------------------------------------------------------------------------
# Test 2: Redis unavailable -> graceful degradation (no crashes, returns None/False)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_graceful_degradation_when_unavailable():
    manager = RedisManager()
    manager.set_client(None, available=False)
    service = RedisService(manager=manager)

    assert service.is_available is False
    assert await service.get("some_key") is None
    assert await service.set("some_key", {"data": 123}) is False
    assert await service.delete("some_key") is False
    assert await service.exists("some_key") is False

    # Exact response caching also fails gracefully
    assert await service.get_exact_response("repo", "classification", "v1", "prompt") is None
    assert await service.set_exact_response("repo", "classification", "v1", "prompt", {"res": 1}) is False

    health = await service.get_health_status()
    assert health["status"] in ("disabled", "degraded")


# ------------------------------------------------------------------------------
# Test 3: Set and Get with TTL
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_and_get_with_ttl(redis_service: RedisService):
    key = "test_key_1"
    data = {"project": "RepoLens", "stars": 42}
    success = await redis_service.set(key, data, ttl=300, namespace="cache")
    assert success is True

    retrieved = await redis_service.get(key, namespace="cache")
    assert retrieved == data


# ------------------------------------------------------------------------------
# Test 4: Expiration behavior
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_expiration_behavior():
    manager = RedisManager()
    mock_client = MockAsyncRedis()
    manager.set_client(mock_client, available=True)
    service = RedisService(manager=manager)

    # Set key with TTL of 60 seconds
    await service.set("expiring_key", {"val": "fresh"}, ttl=60, namespace="cache")
    assert await service.get("expiring_key", namespace="cache") == {"val": "fresh"}

    # Simulate TTL expiration by manually advancing expiry timestamp into the past
    namespaced_key = service.build_key("expiring_key", namespace="cache")
    mock_client.ttls[namespaced_key] = time.time() - 10

    # Key should now be expired and return None
    assert await service.get("expiring_key", namespace="cache") is None
    assert await service.exists("expiring_key", namespace="cache") is False


# ------------------------------------------------------------------------------
# Test 5: Namespace isolation (cache vs provider vs session)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_namespace_isolation(redis_service: RedisService):
    key = "same_id"
    await redis_service.set(key, {"role": "cache_item"}, namespace="cache")
    await redis_service.set(key, {"role": "provider_state"}, namespace="provider")
    await redis_service.set(key, {"role": "session_meta"}, namespace="session")

    cache_val = await redis_service.get(key, namespace="cache")
    provider_val = await redis_service.get(key, namespace="provider")
    session_val = await redis_service.get(key, namespace="session")

    assert cache_val == {"role": "cache_item"}
    assert provider_val == {"role": "provider_state"}
    assert session_val == {"role": "session_meta"}

    # Invalid namespace raises ValueError
    with pytest.raises(ValueError, match="Invalid namespace"):
        redis_service.build_key(key, namespace="invalid_ns")


# ------------------------------------------------------------------------------
# Test 6: Serialization & deserialization (nested dicts, datetimes, Pydantic)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_serialization_and_deserialization(redis_service: RedisService):
    now = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
    model = DummyPydanticModel(name="test_model", count=100, tags=["ai", "security"])

    payload = {
        "timestamp": now,
        "model": model,
        "nested": {"active": True, "scores": [0.95, 0.98]},
    }

    await redis_service.set("serialized_obj", payload, namespace="cache")
    retrieved = await redis_service.get("serialized_obj", namespace="cache")

    assert retrieved is not None
    assert retrieved["timestamp"] == now.isoformat()
    assert retrieved["model"] == {"name": "test_model", "count": 100, "tags": ["ai", "security"]}
    assert retrieved["nested"]["active"] is True


# ------------------------------------------------------------------------------
# Test 7: Scoped exact-response caching (cross-repo collision defense)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scoped_exact_response_caching(redis_service: RedisService):
    task = "classification"
    model_version = "gemini-3.7-flash"
    prompt = "Classify this bug report"

    # Save exact response for repo_A
    response_a = {"category": "security", "confidence": 0.99}
    set_a = await redis_service.set_exact_response("repo_A", task, model_version, prompt, response_a)
    assert set_a is True

    # Retrieve for repo_A succeeds
    retrieved_a = await redis_service.get_exact_response("repo_A", task, model_version, prompt)
    assert retrieved_a == response_a

    # Retrieve for repo_B with exact same prompt returns None (strict isolation!)
    retrieved_b = await redis_service.get_exact_response("repo_B", task, model_version, prompt)
    assert retrieved_b is None

    # Non-allowlisted task type is rejected from caching
    non_allowlisted = await redis_service.set_exact_response(
        "repo_A", "arbitrary_unsafe_task", model_version, prompt, {"res": "unsafe"}
    )
    assert non_allowlisted is False


# ------------------------------------------------------------------------------
# Test 8: Provider-state persistence & retrieval
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_provider_state_persistence(redis_service: RedisService):
    provider = "cloudflare"
    model = "@cf/meta/llama-3.1-8b-instruct"
    state = {
        "circuit_state": "HALF_OPEN",
        "consecutive_failures": 3,
        "last_failure_code": "RATE_LIMIT",
    }

    success = await redis_service.save_provider_state(provider, model, state, ttl=3600)
    assert success is True

    loaded = await redis_service.get_provider_state(provider, model)
    assert loaded == state


# ------------------------------------------------------------------------------
# Test 9: Redis errors do not crash normal operations
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_exception_resilience():
    # Simulate network failure during active operations
    failing_client = MockAsyncRedis(simulate_network_failure=True)
    manager = RedisManager()
    manager.set_client(failing_client, available=True)
    service = RedisService(manager=manager)

    # Operations must fail safely and return None/False without raising
    assert await service.get("key") is None
    assert await service.set("key", "val") is False
    assert await service.delete("key") is False
    assert await service.exists("key") is False


# ------------------------------------------------------------------------------
# Test 10: Secrets are never stored in Redis (canonical redaction patterns)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_secrets_never_stored_in_redis(redis_service: RedisService):
    """Verify Redis rejects writes containing representative secrets from canonical redaction."""

    # Each tuple: (description, key_or_value_containing_secret)
    secret_samples = [
        ("OpenAI sk- key", {"api_key": "sk-proj-123456789012345678901234567890"}),
        ("Groq gsk_ key", {"token": "gsk_abcdefghij1234567890"}),
        ("HuggingFace hf_ key", {"auth": "hf_abcdefghijklmnop1234"}),
        ("NVIDIA nvapi- key", {"key": "nvapi-abcdefghijklmnop1234"}),
        ("Google AIza key", {"gcp_key": "AIzaSyD1234567890abcdefghij"}),
        ("GitHub PAT ghp_", {"token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}),
        ("JWT token", {"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}),
        ("Cloudflare cfut_ key", {"cf_token": "cfut_abcdefghijklmnop1234"}),
        ("Cohere API key", {"cohere_key": "cohere_abcdefghijklmnop1234"}),
        ("Bearer token", {"auth_header": "Bearer eyJhbGciOiJSUzI1NiJ9token"}),
        ("Generic api_key='...'", {"raw": "api_key='my_secret_value_here'"}),
        ("OpenRouter sk-or-v1 key", {"key": "sk-or-v1-abcdefghijklmnop1234"}),
    ]

    for desc, payload in secret_samples:
        result = await redis_service.set(f"test_{desc}", payload, namespace="cache")
        assert result is False, f"Secret type '{desc}' was NOT rejected by Redis write!"

    # Key containing token is also blocked
    token_key = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    result_key = await redis_service.set(token_key, {"safe": "value"}, namespace="cache")
    assert result_key is False, "GitHub PAT in key was NOT rejected!"

    # Safe payload should succeed
    safe_result = await redis_service.set("safe_key", {"data": "no secrets here"}, namespace="cache")
    assert safe_result is True


# ------------------------------------------------------------------------------
# Test 11: Recovery after transient Redis outage
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_recovery_after_transient_outage():
    """Verify lifecycle: CONNECTED → operation failure auto-degrades → probe → CONNECTED."""

    # Step 1: Initial connection success
    mock_client = MockAsyncRedis()
    manager = RedisManager()
    manager.set_client(mock_client, available=True)
    service = RedisService(manager=manager)

    assert manager.is_available is True
    result = await service.set("key1", {"val": 1}, namespace="cache")
    assert result is True

    # Step 2: Simulate transient network failure
    mock_client.simulate_network_failure = True

    # Step 3: Operation failure automatically marks manager as degraded
    # (no manual mark_degraded() call — the RedisService error handler does it)
    assert await service.get("key1", namespace="cache") is None
    assert manager.is_available is False, "Manager should be auto-degraded after connectivity failure"

    # Further operations also fail gracefully
    assert await service.set("key2", {"val": 2}, namespace="cache") is False
    assert service.is_available is False

    # Step 4: Redis comes back online
    mock_client.simulate_network_failure = False

    # Step 5: probe_health() restores availability
    recovered = await manager.probe_health()
    assert recovered is True
    assert manager.is_available is True

    # Step 6: Normal operations work again
    result = await service.set("key3", {"val": 3}, namespace="cache")
    assert result is True
    retrieved = await service.get("key3", namespace="cache")
    assert retrieved == {"val": 3}


# ------------------------------------------------------------------------------
# Test 12: probe_health returns False when unconfigured
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_probe_health_returns_false_when_no_client():
    """probe_health returns False if there is no client and Redis is unconfigured."""
    manager = RedisManager()
    # No client, not configured
    assert await manager.probe_health() is False


# ------------------------------------------------------------------------------
# Test 13: Optional Live Redis Cloud Integration Test
# ------------------------------------------------------------------------------
@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_redis_cloud_connectivity():
    """Optional integration check: executes only if REDIS_URL is explicitly set."""
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        pytest.skip("REDIS_URL not set in environment; skipping live integration check.")

    manager = RedisManager()
    connected = await manager.initialize()
    try:
        assert connected is True
        service = RedisService(manager=manager)
        test_key = f"test_live_{int(time.time())}"
        await service.set(test_key, {"live_test": True}, ttl=30, namespace="cache")
        val = await service.get(test_key, namespace="cache")
        assert val == {"live_test": True}
        await service.delete(test_key, namespace="cache")
    finally:
        await manager.close()

