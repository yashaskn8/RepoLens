"""Canonical provider failure taxonomy and normalized AI Gateway exceptions."""

from enum import Enum
from typing import List, Optional

from app.llm.types import LLMProvider


class ProviderFailureCode(str, Enum):
    """Stable failure categories used by routing, health, telemetry, and lineage."""

    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILURE = "AUTH_FAILURE"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    CONTEXT_LIMIT = "CONTEXT_LIMIT"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    UNKNOWN = "UNKNOWN"


class LLMError(Exception):
    """Base exception class for all LLM Gateway errors."""

    def __init__(
        self,
        message: str,
        provider: Optional[LLMProvider] = None,
        model: Optional[str] = None,
        status_code: Optional[int] = None,
        retryable: bool = False,
        failure_code: ProviderFailureCode = ProviderFailureCode.UNKNOWN,
    ):
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.model = model
        self.status_code = status_code
        self.retryable = retryable
        self.failure_code = failure_code

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(message='{self.message}', "
            f"provider={self.provider}, model='{self.model}', "
            f"status_code={self.status_code}, retryable={self.retryable}, "
            f"failure_code={self.failure_code.value})"
        )


class LLMAuthenticationError(LLMError):
    """Raised when authentication fails or API keys are missing/invalid (HTTP 401/403)."""

    def __init__(self, message: str, provider: Optional[LLMProvider] = None, model: Optional[str] = None):
        super().__init__(
            message,
            provider=provider,
            model=model,
            status_code=401,
            retryable=False,
            failure_code=ProviderFailureCode.AUTH_FAILURE,
        )


class LLMRateLimitError(LLMError):
    """Raised when provider rate limits are exceeded (HTTP 429)."""

    def __init__(
        self,
        message: str,
        provider: Optional[LLMProvider] = None,
        model: Optional[str] = None,
        retry_after_seconds: Optional[float] = None,
    ):
        super().__init__(
            message,
            provider=provider,
            model=model,
            status_code=429,
            retryable=True,
            failure_code=ProviderFailureCode.RATE_LIMITED,
        )
        self.retry_after_seconds = retry_after_seconds


class LLMTimeoutError(LLMError):
    """Raised when a request exceeds the configured deadline."""

    def __init__(self, message: str, provider: Optional[LLMProvider] = None, model: Optional[str] = None):
        super().__init__(
            message,
            provider=provider,
            model=model,
            status_code=408,
            retryable=True,
            failure_code=ProviderFailureCode.TIMEOUT,
        )


class LLMProviderUnavailableError(LLMError):
    """Raised when a provider server error occurs (HTTP 500, 502, 503, 504) or network fails."""

    def __init__(
        self,
        message: str,
        provider: Optional[LLMProvider] = None,
        model: Optional[str] = None,
        status_code: Optional[int] = 503,
    ):
        super().__init__(
            message,
            provider=provider,
            model=model,
            status_code=status_code,
            retryable=True,
            failure_code=ProviderFailureCode.UNAVAILABLE,
        )


class LLMResponseValidationError(LLMError):
    """Raised when model response fails schema parsing or JSON validation."""

    def __init__(self, message: str, provider: Optional[LLMProvider] = None, model: Optional[str] = None):
        super().__init__(
            message,
            provider=provider,
            model=model,
            status_code=None,
            retryable=False,
            failure_code=ProviderFailureCode.INVALID_OUTPUT,
        )


class LLMContextLimitError(LLMError):
    """Raised when estimated or provider-reported context exceeds a model limit."""

    def __init__(self, message: str, provider: Optional[LLMProvider] = None, model: Optional[str] = None):
        super().__init__(
            message,
            provider=provider,
            model=model,
            status_code=413,
            retryable=False,
            failure_code=ProviderFailureCode.CONTEXT_LIMIT,
        )


class LLMQuotaExhaustedError(LLMError):
    """Raised when request or provider quota cannot reserve another attempt."""

    def __init__(self, message: str, provider: Optional[LLMProvider] = None, model: Optional[str] = None):
        super().__init__(
            message,
            provider=provider,
            model=model,
            status_code=None,
            retryable=False,
            failure_code=ProviderFailureCode.QUOTA_EXHAUSTED,
        )


class LLMAllFallbacksFailedError(LLMError):
    """Raised by the router when primary and all configured fallback models fail."""

    def __init__(self, message: str, attempted_errors: List[LLMError]):
        super().__init__(message, retryable=False)
        self.attempted_errors = attempted_errors
