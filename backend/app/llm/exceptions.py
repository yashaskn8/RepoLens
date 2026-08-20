"""Normalized exception hierarchy for LLM Gateway operations."""

from typing import List, Optional
from app.llm.types import LLMProvider


class LLMError(Exception):
    """Base exception class for all LLM Gateway errors."""

    def __init__(
        self,
        message: str,
        provider: Optional[LLMProvider] = None,
        model: Optional[str] = None,
        status_code: Optional[int] = None,
        retryable: bool = False,
    ):
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.model = model
        self.status_code = status_code
        self.retryable = retryable

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(message='{self.message}', "
            f"provider={self.provider}, model='{self.model}', "
            f"status_code={self.status_code}, retryable={self.retryable})"
        )


class LLMAuthenticationError(LLMError):
    """Raised when authentication fails or API keys are missing/invalid (HTTP 401/403)."""

    def __init__(self, message: str, provider: Optional[LLMProvider] = None, model: Optional[str] = None):
        super().__init__(message, provider=provider, model=model, status_code=401, retryable=False)


class LLMRateLimitError(LLMError):
    """Raised when provider rate limits are exceeded (HTTP 429)."""

    def __init__(
        self,
        message: str,
        provider: Optional[LLMProvider] = None,
        model: Optional[str] = None,
        retry_after_seconds: Optional[float] = None,
    ):
        super().__init__(message, provider=provider, model=model, status_code=429, retryable=True)
        self.retry_after_seconds = retry_after_seconds


class LLMTimeoutError(LLMError):
    """Raised when a request exceeds the configured deadline."""

    def __init__(self, message: str, provider: Optional[LLMProvider] = None, model: Optional[str] = None):
        super().__init__(message, provider=provider, model=model, status_code=408, retryable=True)


class LLMProviderUnavailableError(LLMError):
    """Raised when a provider server error occurs (HTTP 500, 502, 503, 504) or network fails."""

    def __init__(
        self,
        message: str,
        provider: Optional[LLMProvider] = None,
        model: Optional[str] = None,
        status_code: Optional[int] = 503,
    ):
        super().__init__(message, provider=provider, model=model, status_code=status_code, retryable=True)


class LLMResponseValidationError(LLMError):
    """Raised when model response fails schema parsing or JSON validation."""

    def __init__(self, message: str, provider: Optional[LLMProvider] = None, model: Optional[str] = None):
        super().__init__(message, provider=provider, model=model, status_code=None, retryable=False)


class LLMAllFallbacksFailedError(LLMError):
    """Raised by the router when primary and all configured fallback models fail."""

    def __init__(self, message: str, attempted_errors: List[LLMError]):
        super().__init__(message, retryable=False)
        self.attempted_errors = attempted_errors
