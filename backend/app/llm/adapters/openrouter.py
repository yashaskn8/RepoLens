"""OpenRouter LLM adapter implementing Chat Completions API for last-resort fallback."""

import time
from typing import Any, Dict, Optional
import httpx

from app.core.config import get_settings
from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import LLMAuthenticationError, LLMResponseValidationError
from app.llm.types import LLMProvider, LLMRequest, LLMResponse


class OpenRouterAdapter(BaseLLMAdapter):
    """Adapter for OpenRouter API (strict last-resort fallback)."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        settings = get_settings()
        self.api_key = settings.OPENROUTER_API_KEY if api_key is None else api_key
        self.base_url = (settings.OPENROUTER_BASE_URL if base_url is None else base_url).rstrip("/")

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.OPENROUTER

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Send chat completion request to OpenRouter API."""
        settings = get_settings()
        model = request.model or settings.OPENROUTER_DEFAULT_MODEL
        timeout = request.timeout_seconds or settings.LLM_DEFAULT_TIMEOUT

        if not self.api_key:
            raise LLMAuthenticationError(
                "OpenRouter API key is not configured in settings or environment.",
                provider=self.provider,
                model=model,
            )

        messages_payload = [{"role": msg.role, "content": msg.content} for msg in request.messages]

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages_payload,
            "temperature": request.temperature,
        }
        if request.max_tokens:
            payload["max_tokens"] = request.max_tokens
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://repolens.dev",
            "X-Title": "RepoLens",
        }

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, json=payload, headers=headers)

            if response.status_code != 200:
                raise self._normalize_http_error(response, model)

            data = response.json()
        except Exception as exc:
            if not isinstance(exc, Exception) or not hasattr(exc, "status_code"):
                raise self._normalize_transport_error(exc, model)
            raise

        execution_time_ms = (time.perf_counter() - start_time) * 1000.0

        try:
            choices = data.get("choices", [])
            if not choices:
                raise LLMResponseValidationError(
                    "OpenRouter returned empty choices list.",
                    provider=self.provider,
                    model=model,
                )

            choice = choices[0]
            content_text = choice.get("message", {}).get("content", "")
            finish_reason = choice.get("finish_reason")

            usage = data.get("usage", {})
            prompt_tokens = usage.get("prompt_tokens")
            completion_tokens = usage.get("completion_tokens")

            metadata = self._build_metadata(
                model_name=model,
                execution_time_ms=execution_time_ms,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                temperature=request.temperature,
                extra={"fallback_used": True},
            )

            return LLMResponse(
                content=content_text,
                model=model,
                provider=self.provider,
                metadata=metadata,
                finish_reason=finish_reason,
            )
        except LLMResponseValidationError:
            raise
        except Exception as exc:
            raise LLMResponseValidationError(
                f"Failed to parse OpenRouter response: {str(exc)}",
                provider=self.provider,
                model=model,
            ) from exc
