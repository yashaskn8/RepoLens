"""Optional loopback-only Ollama adapter for low-risk local generation."""

from __future__ import annotations

import ipaddress
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import (
    LLMError,
    LLMResponseValidationError,
    ProviderFailureCode,
)
from app.llm.types import LLMProvider, LLMRequest, LLMResponse


def _loopback_base_url(value: str) -> str:
    """Validate that local inference cannot be repurposed as an SSRF transport."""
    parsed = urlparse(value)
    hostname = parsed.hostname
    loopback = hostname == "localhost"
    if hostname and not loopback:
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = False
    if (
        parsed.scheme not in {"http", "https"}
        or not loopback
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("OLLAMA_BASE_URL must be an uncredentialed loopback HTTP(S) origin")
    return value.rstrip("/")


class OllamaAdapter(BaseLLMAdapter):
    """Call an operator-managed Ollama server without installing or pulling models."""

    def __init__(
        self,
        *,
        enabled: bool | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        failure_cooldown_seconds: float | None = None,
    ) -> None:
        settings = get_settings()
        self.enabled = settings.LOCAL_LLM_ENABLED if enabled is None else enabled
        configured_url = base_url or settings.OLLAMA_BASE_URL
        self.base_url = (
            _loopback_base_url(configured_url)
            if self.enabled
            else configured_url.rstrip("/")
        )
        self.model = model or settings.OLLAMA_MODEL
        self.timeout = timeout or settings.OLLAMA_TIMEOUT
        self.failure_cooldown_seconds = (
            failure_cooldown_seconds
            if failure_cooldown_seconds is not None
            else settings.OLLAMA_FAILURE_COOLDOWN_SECONDS
        )
        self._cooldown_until = 0.0

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.OLLAMA

    @property
    def cooldown_remaining_seconds(self) -> float:
        return max(0.0, self._cooldown_until - time.monotonic())

    async def generate(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self.model
        if not self.enabled:
            raise self._unavailable("Local Ollama execution is disabled.", model)
        if self.cooldown_remaining_seconds > 0:
            raise self._unavailable("Local Ollama endpoint is in failure cooldown.", model)

        payload: dict[str, Any] = {
            "model": model,
            "messages": [message.model_dump() for message in request.messages],
            "stream": False,
            "options": {"temperature": request.temperature},
        }
        if request.max_tokens is not None:
            payload["options"]["num_predict"] = request.max_tokens
        if request.json_mode:
            payload["format"] = "json"

        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=request.timeout_seconds or self.timeout) as client:
                response = await client.post(f"{self.base_url}/api/chat", json=payload)
        except (httpx.HTTPError, TimeoutError) as exc:
            self._begin_cooldown()
            normalized = self._normalize_transport_error(exc, model)
            normalized.retryable = False
            raise normalized from exc

        if response.status_code != 200:
            error = self._normalize_http_error(response, model)
            if error.retryable:
                self._begin_cooldown()
                error.retryable = False
            raise error

        try:
            data = response.json()
            content = data.get("message", {}).get("content")
            if not isinstance(content, str) or not content.strip():
                raise ValueError("missing message content")
            prompt_tokens = self._nonnegative_int(data.get("prompt_eval_count"))
            completion_tokens = self._nonnegative_int(data.get("eval_count"))
        except Exception as exc:
            raise LLMResponseValidationError(
                "Ollama returned an invalid chat response.",
                provider=self.provider,
                model=model,
            ) from exc

        return LLMResponse(
            content=content,
            model=str(data.get("model") or model),
            provider=self.provider,
            metadata=self._build_metadata(
                model_name=str(data.get("model") or model),
                execution_time_ms=(time.perf_counter() - started) * 1000.0,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                temperature=request.temperature,
                extra={"local_execution": True, "cloud_execution": False},
            ),
            finish_reason=str(data.get("done_reason") or "stop"),
        )

    def _begin_cooldown(self) -> None:
        self._cooldown_until = time.monotonic() + max(0.0, self.failure_cooldown_seconds)

    def _unavailable(self, message: str, model: str) -> LLMError:
        return LLMError(
            message,
            provider=self.provider,
            model=model,
            retryable=False,
            failure_code=ProviderFailureCode.UNAVAILABLE,
        )

    @staticmethod
    def _nonnegative_int(value: object) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None
        return value


__all__ = ["OllamaAdapter"]
