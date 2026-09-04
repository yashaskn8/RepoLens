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
from app.llm.admission import AdmissionDecision, AIAdmissionPlan, AIWorkPlan
from app.llm.economy import CloudBudgetSnapshot, WorkflowCloudBudget
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    TaskPolicy,
    ModelCapability,
)

from app.llm.langchain_adapter import (
    RepoLensChatModel,
    convert_langchain_to_repolens_messages,
    convert_repolens_to_aimessage,
)
from app.llm.prompts import (
    create_repository_analysis_prompt,
    create_security_review_prompt,
    create_structured_extraction_prompt,
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
    "AdmissionDecision",
    "AIAdmissionPlan",
    "AIWorkPlan",
    "CloudBudgetSnapshot",
    "WorkflowCloudBudget",
    "configure_persistent_llm_router",
    "get_llm_router",
    "RepoLensChatModel",
    "convert_langchain_to_repolens_messages",
    "convert_repolens_to_aimessage",
    "create_repository_analysis_prompt",
    "create_security_review_prompt",
    "create_structured_extraction_prompt",
]
