"""Centralized asynchronous Redis client manager with connection pooling and graceful degradation.

Manages a shared, long-lived redis.asyncio.Redis client instance according to redis-py
recommended practices: single client owning its connection pool, reused across requests,
with clean aclose() cleanup at shutdown and zero crashes when Redis is offline.

Recovery behavior: when a transient outage occurs, the client reference is preserved
(not closed) so that later health probes can restore availability without restarting.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import redis.asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, TimeoutError as RedisTimeoutError

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class RedisManager:
    """Manages the lifecycle, availability, and pooling of the shared async Redis client."""

    def __init__(self) -> None:
        self._client: Optional[aioredis.Redis] = None
        self._available: bool = False
        self._initialized: bool = False
        self._lock = asyncio.Lock()

    @property
    def is_configured(self) -> bool:
        """Check if REDIS_URL is configured and enabled in settings."""
        settings = get_settings()
        return bool(settings.REDIS_ENABLED and settings.REDIS_URL and settings.REDIS_URL.strip())

    @property
    def is_available(self) -> bool:
        """Check if Redis is currently connected and ready to service requests."""
        return bool(self._available and self._client is not None)

    def get_client(self) -> Optional[aioredis.Redis]:
        """Return the shared async Redis client instance if available, otherwise None."""
        if not self.is_available:
            return None
        return self._client

    async def initialize(self) -> bool:
        """Initialize the shared async Redis client and perform startup connectivity check.

        Never raises exceptions; gracefully marks Redis as unavailable on any connection failure
        to prevent Redis from becoming a single point of failure.
        """
        async with self._lock:
            settings = get_settings()
            if not self.is_configured:
                logger.info("Redis is unconfigured or disabled; operating in cache-disabled degraded mode.")
                self._available = False
                self._client = None
                self._initialized = True
                return False

            redis_url = settings.REDIS_URL.strip() if settings.REDIS_URL else ""
            client: Optional[aioredis.Redis] = None
            try:
                # Mask credentials in logs for security
                masked_url = self._mask_url(redis_url)
                logger.info("Connecting to Redis at %s...", masked_url)

                client = aioredis.from_url(
                    redis_url,
                    max_connections=settings.REDIS_MAX_CONNECTIONS,
                    socket_timeout=settings.REDIS_TIMEOUT_SECONDS,
                    socket_connect_timeout=settings.REDIS_TIMEOUT_SECONDS,
                    decode_responses=True,
                )

                # Safe non-blocking startup connectivity check
                await asyncio.wait_for(
                    client.ping(),
                    timeout=settings.REDIS_TIMEOUT_SECONDS,
                )

                self._client = client
                self._available = True
                self._initialized = True
                logger.info("Redis connectivity confirmed; runtime caching active.")
                return True

            except (RedisConnectionError, RedisTimeoutError, asyncio.TimeoutError) as exc:
                logger.warning(
                    "Redis connectivity check failed (%s); operating in cache-disabled degraded mode.",
                    type(exc).__name__,
                )
                # Keep client reference alive so health probes can restore availability
                # without requiring an application restart.
                self._client = client
                self._available = False
                self._initialized = True
                return False

            except Exception as exc:
                logger.warning(
                    "Unexpected error initializing Redis client (%s); operating in cache-disabled degraded mode.",
                    exc,
                )
                self._client = client
                self._available = False
                self._initialized = True
                return False

    async def close(self) -> None:
        """Gracefully close all pooled connections and release client resources."""
        async with self._lock:
            if self._client is not None:
                try:
                    await self._client.aclose()
                    logger.info("Redis client connections closed successfully.")
                except Exception as exc:
                    logger.warning("Error closing Redis connections: %s", exc)
                finally:
                    self._client = None
                    self._available = False
                    self._initialized = False

    def mark_degraded(self) -> None:
        """Mark Redis as degraded after a transient runtime failure.

        Preserves the client reference so probe_health() can attempt
        recovery without recreating the client or restarting the application.
        """
        if self._available:
            self._available = False
            logger.warning("Redis marked degraded after transient failure; recovery probes will attempt restoration.")

    async def ping(self) -> bool:
        """Probe Redis health with a short timeout; updates availability status."""
        client = self._client
        if client is None:
            self._available = False
            return False

        settings = get_settings()
        try:
            res = await asyncio.wait_for(client.ping(), timeout=settings.REDIS_TIMEOUT_SECONDS)
            self._available = bool(res)
            return self._available
        except Exception:
            self._available = False
            return False

    async def probe_health(self) -> bool:
        """Attempt to restore Redis availability after a transient outage.

        If the client reference is alive, pings it. If the client was never created
        (e.g. initial startup failed), attempts to recreate it. Uses bounded timeout
        to prevent blocking and does not create retry storms.

        Returns True if Redis is now available, False otherwise.
        """
        if self._client is not None:
            return await self.ping()

        # Client was never created or was closed; try to recreate if configured
        if not self.is_configured:
            return False

        return await self.initialize()

    def set_client(self, client: Optional[aioredis.Redis], available: bool = True) -> None:
        """Inject an explicit client (useful for unit testing and mocks)."""
        self._client = client
        self._available = bool(client is not None and available)
        self._initialized = True

    @staticmethod
    def _mask_url(url: str) -> str:
        """Mask credentials from connection URL for safe logging."""
        if not url:
            return ""
        try:
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(url)
            if parsed.password:
                netloc = f"{parsed.username or ''}:***@{parsed.hostname or ''}"
                if parsed.port:
                    netloc += f":{parsed.port}"
                return urlunparse(parsed._replace(netloc=netloc))
            return url
        except Exception:
            return "redis://***"


# Singleton instance
_redis_manager = RedisManager()


def get_redis_manager() -> RedisManager:
    """Return the global RedisManager singleton."""
    return _redis_manager

