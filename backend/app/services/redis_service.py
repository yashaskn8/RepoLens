"""Redis service abstraction providing namespaced caching, provider health sync, and exact-response caching with graceful degradation.

Never serves as a single point of failure: all operations fail silently, returning None or False
when Redis is unavailable or unconfigured. Enforces strict key namespacing, scoped exact-response
boundaries, and secret sanitization.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Set, Union
from uuid import UUID

from pydantic import BaseModel
from redis.exceptions import RedisError

from app.core.config import get_settings
from app.core.redis import RedisManager, get_redis_manager
from app.security.redaction import contains_secrets

logger = logging.getLogger(__name__)

# Valid namespaces for key isolation
ALLOWED_NAMESPACES: Set[str] = {"cache", "provider", "session"}

# Allow-listed deterministic response types for exact caching
ALLOWLISTED_CACHE_TASK_TYPES: Set[str] = {
    "classification",
    "lightweight_classification",
    "extraction",
    "deterministic_summary",
    "verification_rule",
    "ast_analysis",
}

# Secret detection delegates to the canonical security layer in
# app.security.redaction.contains_secrets — no duplicate patterns here.


class SafeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder supporting Pydantic models, datetimes, enums, and UUIDs."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, BaseModel):
            return obj.model_dump()
        return super().default(obj)


def _serialize(value: Any) -> str:
    """Serialize value to JSON with safe type encoders."""
    return json.dumps(value, cls=SafeJSONEncoder, separators=(",", ":"))


def _deserialize(raw: str) -> Any:
    """Deserialize JSON string, falling back to raw string if not JSON."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


class RedisService:
    """Service abstraction for RepoLens Redis operations."""

    def __init__(self, manager: Optional[RedisManager] = None) -> None:
        self._manager = manager or get_redis_manager()

    @property
    def is_available(self) -> bool:
        """Check if Redis is ready for operations."""
        return self._manager.is_available

    def build_key(self, key: str, namespace: str = "cache") -> str:
        """Construct a validated namespaced Redis key: repolens:{namespace}:{key}."""
        ns = namespace.lower().strip()
        if ns not in ALLOWED_NAMESPACES:
            raise ValueError(
                f"Invalid namespace '{namespace}'. Must be one of: {sorted(ALLOWED_NAMESPACES)}"
            )
        cleaned_key = key.strip().strip(":")
        return f"repolens:{ns}:{cleaned_key}"

    @staticmethod
    def _contains_secrets(text: str) -> bool:
        """Check if text contains secrets using canonical RepoLens redaction rules."""
        return contains_secrets(text)

    async def get(self, key: str, namespace: str = "cache") -> Optional[Any]:
        """Fetch a value from Redis; returns None if missing or if Redis is unavailable."""
        client = self._manager.get_client()
        if client is None:
            return None

        namespaced_key = self.build_key(key, namespace)
        try:
            raw = await client.get(namespaced_key)
            if raw is None:
                return None
            return _deserialize(raw)
        except RedisError as exc:
            logger.warning("Redis GET error on key %s (%s): %s", namespaced_key, type(exc).__name__, exc)
            return None
        except Exception as exc:
            logger.warning("Unexpected error during Redis GET on %s: %s", namespaced_key, exc)
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        namespace: str = "cache",
    ) -> bool:
        """Store a value in Redis with optional TTL; returns False if unavailable or invalid."""
        client = self._manager.get_client()
        if client is None:
            return False

        namespaced_key = self.build_key(key, namespace)
        serialized = _serialize(value)

        # Zero Secrets Invariant
        if self._contains_secrets(namespaced_key) or self._contains_secrets(serialized):
            logger.error("SECURITY ALERT: Attempted to cache credentials or sensitive tokens in Redis! Write blocked.")
            return False

        effective_ttl = ttl if ttl is not None else get_settings().REDIS_DEFAULT_CACHE_TTL_SECONDS
        try:
            if effective_ttl and effective_ttl > 0:
                await client.set(namespaced_key, serialized, ex=effective_ttl)
            else:
                await client.set(namespaced_key, serialized)
            return True
        except RedisError as exc:
            logger.warning("Redis SET error on key %s (%s): %s", namespaced_key, type(exc).__name__, exc)
            return False
        except Exception as exc:
            logger.warning("Unexpected error during Redis SET on %s: %s", namespaced_key, exc)
            return False

    async def delete(self, key: str, namespace: str = "cache") -> bool:
        """Delete a key from Redis; returns False if missing or unavailable."""
        client = self._manager.get_client()
        if client is None:
            return False

        namespaced_key = self.build_key(key, namespace)
        try:
            deleted_count = await client.delete(namespaced_key)
            return bool(deleted_count > 0)
        except RedisError as exc:
            logger.warning("Redis DELETE error on %s (%s): %s", namespaced_key, type(exc).__name__, exc)
            return False
        except Exception as exc:
            logger.warning("Unexpected error during Redis DELETE on %s: %s", namespaced_key, exc)
            return False

    async def exists(self, key: str, namespace: str = "cache") -> bool:
        """Check if a key exists in Redis; returns False if unavailable."""
        client = self._manager.get_client()
        if client is None:
            return False

        namespaced_key = self.build_key(key, namespace)
        try:
            count = await client.exists(namespaced_key)
            return bool(count > 0)
        except RedisError as exc:
            logger.warning("Redis EXISTS error on %s (%s): %s", namespaced_key, type(exc).__name__, exc)
            return False
        except Exception as exc:
            logger.warning("Unexpected error during Redis EXISTS on %s: %s", namespaced_key, exc)
            return False

    # --------------------------------------------------------------------------
    # Scoped Exact-Response Caching
    # --------------------------------------------------------------------------

    @staticmethod
    def build_scoped_cache_key(
        repo_scope: str,
        task_type: str,
        model_version: str,
        prompt_and_context: Union[str, Dict[str, Any], List[Any]],
    ) -> str:
        """Generate a secure, scoped cache key preventing cross-repo collisions.

        Format: {repo_scope}:{task_type}:{model_version}:{sha256_hash}
        """
        clean_repo = repo_scope.strip().lower() or "global"
        clean_task = task_type.strip().lower()
        clean_model = model_version.strip().lower().replace("/", "_")

        serialized_input = _serialize(prompt_and_context)
        content_hash = hashlib.sha256(serialized_input.encode("utf-8")).hexdigest()[:32]

        return f"{clean_repo}:{clean_task}:{clean_model}:{content_hash}"

    async def get_exact_response(
        self,
        repo_scope: str,
        task_type: str,
        model_version: str,
        prompt_and_context: Any,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached deterministic response if allowlisted and present."""
        clean_task = task_type.strip().lower()
        if clean_task not in ALLOWLISTED_CACHE_TASK_TYPES:
            return None

        cache_sub_key = self.build_scoped_cache_key(
            repo_scope=repo_scope,
            task_type=clean_task,
            model_version=model_version,
            prompt_and_context=prompt_and_context,
        )
        cached = await self.get(cache_sub_key, namespace="cache")
        if isinstance(cached, dict):
            return cached
        return None

    async def set_exact_response(
        self,
        repo_scope: str,
        task_type: str,
        model_version: str,
        prompt_and_context: Any,
        response: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> bool:
        """Cache a deterministic response if task is allowlisted."""
        clean_task = task_type.strip().lower()
        if clean_task not in ALLOWLISTED_CACHE_TASK_TYPES:
            return False

        cache_sub_key = self.build_scoped_cache_key(
            repo_scope=repo_scope,
            task_type=clean_task,
            model_version=model_version,
            prompt_and_context=prompt_and_context,
        )
        return await self.set(cache_sub_key, response, ttl=ttl, namespace="cache")

    # --------------------------------------------------------------------------
    # Provider Health State Cache Primitives
    #
    # These methods provide low-level Redis persistence primitives for provider
    # health snapshots. They are NOT active distributed synchronization — the
    # authoritative multi-worker provider-state source of truth remains
    # SQLAlchemyProviderHealthRegistry (backed by PostgreSQL with row locking).
    #
    # Future phases may wire these primitives into a read-through cache layer
    # in front of the SQL registry to reduce database polling frequency.
    # --------------------------------------------------------------------------

    async def save_provider_state(
        self,
        provider: str,
        model: str,
        state_data: Dict[str, Any],
        ttl: int = 86400,
    ) -> bool:
        """Cache a provider health snapshot to repolens:provider:{provider}:{model}.

        This is a cache primitive only. SQLAlchemyProviderHealthRegistry remains
        the authoritative source for multi-worker circuit-breaker state.
        """
        clean_provider = provider.strip().lower()
        clean_model = model.strip().lower().replace("/", "_")
        sub_key = f"{clean_provider}:{clean_model}"
        return await self.set(sub_key, state_data, ttl=ttl, namespace="provider")

    async def get_provider_state(
        self,
        provider: str,
        model: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached provider health snapshot from repolens:provider:{provider}:{model}.

        Returns the cached snapshot if available, or None. This does not replace
        the authoritative SQL-backed provider health registry.
        """
        clean_provider = provider.strip().lower()
        clean_model = model.strip().lower().replace("/", "_")
        sub_key = f"{clean_provider}:{clean_model}"
        result = await self.get(sub_key, namespace="provider")
        return result if isinstance(result, dict) else None

    # --------------------------------------------------------------------------
    # Deterministic Tool Result Caching
    # --------------------------------------------------------------------------

    async def get_tool_result(
        self,
        tool_name: str,
        tool_input: Any,
        repo_scope: str = "global",
    ) -> Optional[Any]:
        """Fetch cached deterministic tool execution result."""
        sub_key = self.build_scoped_cache_key(
            repo_scope=repo_scope,
            task_type=f"tool_{tool_name}",
            model_version="v1",
            prompt_and_context=tool_input,
        )
        return await self.get(sub_key, namespace="cache")

    async def set_tool_result(
        self,
        tool_name: str,
        tool_input: Any,
        result: Any,
        ttl: int = 300,
        repo_scope: str = "global",
    ) -> bool:
        """Cache deterministic tool result with short-lived TTL."""
        sub_key = self.build_scoped_cache_key(
            repo_scope=repo_scope,
            task_type=f"tool_{tool_name}",
            model_version="v1",
            prompt_and_context=tool_input,
        )
        return await self.set(sub_key, result, ttl=ttl, namespace="cache")

    # --------------------------------------------------------------------------
    # Health & Telemetry Reporting
    # --------------------------------------------------------------------------

    async def get_health_status(self) -> Dict[str, Any]:
        """Collect operational health and latency for health & telemetry endpoints.

        When Redis is in degraded state, this method uses probe_health() to attempt
        automatic recovery, enabling the transition:
        CONNECTED → transient failure → DEGRADED → probe succeeds → CONNECTED.
        """
        if not self._manager.is_configured:
            return {
                "status": "disabled",
                "configured": False,
                "latency_ms": None,
            }

        try:
            import time
            t0 = time.perf_counter()
            alive = await self._manager.probe_health()
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "status": "connected" if alive else "degraded",
                "configured": True,
                "latency_ms": latency_ms if alive else None,
            }
        except Exception:
            return {
                "status": "degraded",
                "configured": True,
                "latency_ms": None,
            }


# Singleton service instance
_redis_service = RedisService()


def get_redis_service() -> RedisService:
    """Return the global RedisService singleton."""
    return _redis_service
