"""Gemini LLM adapter implementing Google Generative Language REST API."""

import time
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import get_settings
from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import LLMAuthenticationError, LLMResponseValidationError
from app.llm.types import LLMMessage, LLMProvider, LLMRequest, LLMResponse


class GeminiAdapter(BaseLLMAdapter):
    """Adapter for Google Gemini API."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        settings = get_settings()
        self.api_key = settings.GEMINI_API_KEY if api_key is None else api_key
        self.base_url = (settings.GEMINI_BASE_URL if base_url is None else base_url).rstrip("/")

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.GEMINI

    def _convert_messages(self, messages: List[LLMMessage]) -> tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """Convert standard LLMMessages into Gemini system_instruction and contents format."""
        system_instruction = None
        contents = []

        for msg in messages:
            if msg.role == "system":
                system_instruction = {
                    "parts": [{"text": msg.content}]
                }
            else:
                role = "model" if msg.role == "assistant" else "user"
                contents.append({
                    "role": role,
                    "parts": [{"text": msg.content}]
                })

        return system_instruction, contents

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Send chat messages to Gemini API and parse response."""
        settings = get_settings()
        model = request.model or settings.MODEL_ARCHITECTURE
        timeout = request.timeout_seconds or settings.LLM_DEFAULT_TIMEOUT

        if not self.api_key:
            raise LLMAuthenticationError(
                "Gemini API key is not configured in settings or environment.",
                provider=self.provider,
                model=model,
            )

        system_instruction, contents = self._convert_messages(request.messages)

        generation_config: Dict[str, Any] = {
            "temperature": request.temperature,
        }
        if request.max_tokens:
            generation_config["maxOutputTokens"] = request.max_tokens
        if request.json_mode:
            generation_config["responseMimeType"] = "application/json"

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": generation_config,
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction

        # Optional Google Search Grounding for Research and Fact Retrieval
        if request.extra_params.get("enable_search_grounding") or request.extra_params.get("tools"):
            payload["tools"] = request.extra_params.get("tools", [{"googleSearch": {}}])

        url = f"{self.base_url}/models/{model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
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
            candidates = data.get("candidates", [])
            if not candidates:
                raise LLMResponseValidationError("Gemini returned empty candidates list.", provider=self.provider, model=model)

            candidate = candidates[0]
            parts = candidate.get("content", {}).get("parts", [])
            content_text = "".join(part.get("text", "") for part in parts)
            finish_reason = candidate.get("finishReason")
            grounding_metadata = candidate.get("groundingMetadata")

            usage = data.get("usageMetadata", {})
            prompt_tokens = usage.get("promptTokenCount")
            completion_tokens = usage.get("candidatesTokenCount")

            extra_meta = {}
            if grounding_metadata:
                extra_meta["grounding_metadata"] = grounding_metadata

            metadata = self._build_metadata(
                model_name=model,
                execution_time_ms=execution_time_ms,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                temperature=request.temperature,
                extra=extra_meta if extra_meta else None,
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
                f"Failed to parse Gemini response payload: {str(exc)}",
                provider=self.provider,
                model=model,
            )
