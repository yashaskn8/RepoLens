"""Canonical types and schemas for LLM Gateway operations."""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field
from app.schemas.metadata import ModelExecutionMetadata


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    GEMINI = "gemini"
    GROQ = "groq"
    NVIDIA = "nvidia"
    HUGGINGFACE = "huggingface"


class TaskPolicy(str, Enum):
    """Task policies dictating model selection and fallback priority."""

    ARCHITECTURE = "architecture"
    INTEGRATION_CODE = "integration_code"
    BUG_REASONING = "bug_reasoning"
    SECURITY_REASONING = "security_reasoning"
    LIGHTWEIGHT_CLASSIFICATION = "lightweight_classification"
    VERIFICATION = "verification"
    RESEARCH = "research"
    FIX_PLANNING = "fix_planning"
    PATCH_GENERATION = "patch_generation"
    PATCH_CRITIC = "patch_critic"
    CHANGE_REVIEW = "change_review"


class LLMMessage(BaseModel):
    """Normalized chat message structure."""

    role: Literal["system", "user", "assistant"] = Field(..., description="Message author role")
    content: str = Field(..., description="Content text of the message")


class LLMRequest(BaseModel):
    """Request payload passed to LLMRouter or adapters."""

    messages: List[LLMMessage] = Field(..., min_length=1, description="Ordered conversation history")
    task_policy: Optional[TaskPolicy] = Field(default=None, description="Task policy for automatic routing")
    provider: Optional[LLMProvider] = Field(default=None, description="Explicit provider override")
    model: Optional[str] = Field(default=None, description="Explicit model ID override")
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: Optional[int] = Field(default=None, ge=1, description="Maximum tokens to generate")
    json_mode: bool = Field(default=False, description="Require valid JSON output from the model")
    timeout_seconds: Optional[float] = Field(default=None, ge=1.0, description="Request timeout override in seconds")
    extra_params: Dict[str, Any] = Field(default_factory=dict, description="Additional provider-specific parameters")


class LLMResponse(BaseModel):
    """Normalized response returned by LLMRouter and adapters."""

    content: str = Field(..., description="Generated text content")
    model: str = Field(..., description="Actual model ID that processed the request")
    provider: LLMProvider = Field(..., description="Provider that served the response")
    metadata: ModelExecutionMetadata = Field(..., description="Telemetry and token usage metadata")
    finish_reason: Optional[str] = Field(default=None, description="Model stop/finish reason")
