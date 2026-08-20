"""Abstract base adapter for LLM providers."""

from abc import ABC, abstractmethod
import time
from typing import Any, Dict, Optional
import httpx

from app.llm.exceptions import (
    LLMAuthenticationError,
    LLMError,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from app.llm.types import LLMProvider, LLMRequest, LLMResponse
from app.schemas.metadata import ModelExecutionMetadata


class BaseLLMAdapter(ABC):
    """Abstract interface and common utilities for all LLM provider adapters."""

    @property
    @abstractmethod
    def provider(self) -> LLMProvider:
        """Provider identification enum."""
        pass

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Asynchronously send chat messages to the model and return normalized response."""
        pass

    def _normalize_http_error(self, response: httpx.Response, model: str) -> LLMError:
        """Map HTTP error status codes into normalized LLM exceptions."""
        status = response.status_code
        text = response.text
        try:
            body = response.json()
            err_msg = body.get("error", {}).get("message") or body.get("detail") or text
        except Exception:
            err_msg = text

        if status in (401, 403):
            return LLMAuthenticationError(
                f"Authentication failed for {self.provider.value} ({status}): {err_msg}",
                provider=self.provider,
                model=model,
            )
        elif status == 429:
            retry_after = response.headers.get("retry-after")
            retry_sec = float(retry_after) if retry_after and retry_after.isdigit() else None
            return LLMRateLimitError(
                f"Rate limit exceeded for {self.provider.value}: {err_msg}",
                provider=self.provider,
                model=model,
                retry_after_seconds=retry_sec,
            )
        elif status == 408 or status == 504:
            return LLMTimeoutError(
                f"Gateway timeout for {self.provider.value}: {err_msg}",
                provider=self.provider,
                model=model,
            )
        elif status >= 500:
            return LLMProviderUnavailableError(
                f"Provider server error for {self.provider.value} ({status}): {err_msg}",
                provider=self.provider,
                model=model,
                status_code=status,
            )
        else:
            return LLMError(
                f"Request to {self.provider.value} failed with status {status}: {err_msg}",
                provider=self.provider,
                model=model,
                status_code=status,
            )

    def _normalize_transport_error(self, exc: Exception, model: str) -> LLMError:
        """Map network / transport exceptions into normalized LLM exceptions."""
        if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
            return LLMTimeoutError(
                f"Request to {self.provider.value} timed out: {str(exc)}",
                provider=self.provider,
                model=model,
            )
        return LLMProviderUnavailableError(
            f"Network connection failure for {self.provider.value}: {str(exc)}",
            provider=self.provider,
            model=model,
        )

    def _build_metadata(
        self,
        model_name: str,
        execution_time_ms: float,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> ModelExecutionMetadata:
        """Create standard ModelExecutionMetadata object."""
        total_tokens = None
        if prompt_tokens is not None and completion_tokens is not None:
            total_tokens = prompt_tokens + completion_tokens

        return ModelExecutionMetadata(
            model_name=model_name,
            provider=self.provider.value,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            execution_time_ms=execution_time_ms,
            temperature=temperature,
            extra_metadata=extra or {},
        )
