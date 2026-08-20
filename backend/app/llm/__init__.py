"""Canonical LLM Gateway package for RepoLens."""

from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import (
    LLMAllFallbacksFailedError,
    LLMAuthenticationError,
    LLMError,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMResponseValidationError,
    LLMTimeoutError,
)
from app.llm.router import LLMRouter, get_llm_router
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    TaskPolicy,
)

__all__ = [
    "LLMProvider",
    "TaskPolicy",
    "LLMMessage",
    "LLMRequest",
    "LLMResponse",
    "BaseLLMAdapter",
    "LLMError",
    "LLMAuthenticationError",
    "LLMRateLimitError",
    "LLMTimeoutError",
    "LLMProviderUnavailableError",
    "LLMResponseValidationError",
    "LLMAllFallbacksFailedError",
    "LLMRouter",
    "get_llm_router",
]
