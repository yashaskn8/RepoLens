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
from app.llm.router import LLMRouter, configure_persistent_llm_router, get_llm_router
from app.llm.gateway import CapabilityAIGateway
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    TaskPolicy,
    ModelCapability,
)

__all__ = [
    "LLMProvider",
    "TaskPolicy",
    "ModelCapability",
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
    "CapabilityAIGateway",
    "configure_persistent_llm_router",
    "get_llm_router",
]
