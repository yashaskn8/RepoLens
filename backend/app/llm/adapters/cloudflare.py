"""Cloudflare Workers AI adapter implementing both OpenAI-compatible and native AI REST APIs."""

import time
from typing import Any, Dict, Optional
import httpx

from app.core.config import get_settings
from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import LLMAuthenticationError, LLMResponseValidationError
from app.llm.types import LLMProvider, LLMRequest, LLMResponse


class CloudflareAdapter(BaseLLMAdapter):
    """Adapter for Cloudflare Workers AI."""

    def __init__(
        self,
        api_token: Optional[str] = None,
        account_id: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        settings = get_settings()
        self.api_token = api_token or settings.CLOUDFLARE_API_TOKEN
        self.account_id = account_id or settings.CLOUDFLARE_ACCOUNT_ID
        self.base_url = (base_url or settings.CLOUDFLARE_BASE_URL).rstrip("/")

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.CLOUDFLARE

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Send chat request to Cloudflare Workers AI."""
        settings = get_settings()
        model = request.model or settings.CLOUDFLARE_DEFAULT_MODEL
        timeout = request.timeout_seconds or settings.LLM_DEFAULT_TIMEOUT

        if not self.api_token:
            raise LLMAuthenticationError(
                "Cloudflare API token is not configured in settings or environment.",
                provider=self.provider,
                model=model,
            )

        if not self.account_id:
            raise LLMAuthenticationError(
                "Cloudflare account ID is not configured (CLOUDFLARE_ACCOUNT_ID required for Workers AI).",
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

        # Use OpenAI-compatible Workers AI chat completions endpoint
        url = f"{self.base_url}/accounts/{self.account_id}/ai/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_token}",
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
            # Support both OpenAI-compatible envelope and native Workers AI envelope
            if "choices" in data and len(data["choices"]) > 0:
                choice = data["choices"][0]
                content_text = choice.get("message", {}).get("content", "")
                finish_reason = choice.get("finish_reason")
            elif "result" in data and isinstance(data["result"], dict):
                content_text = data["result"].get("response", "")
                finish_reason = "stop"
            else:
                raise LLMResponseValidationError(
                    "Cloudflare Workers AI returned unexpected response structure.",
                    provider=self.provider,
                    model=model,
                )

            usage = data.get("usage", {})
            prompt_tokens = usage.get("prompt_tokens")
            completion_tokens = usage.get("completion_tokens")

            metadata = self._build_metadata(
                model_name=model,
                execution_time_ms=execution_time_ms,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                temperature=request.temperature,
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
                f"Failed to parse Cloudflare Workers AI response: {str(exc)}",
                provider=self.provider,
                model=model,
            ) from exc
