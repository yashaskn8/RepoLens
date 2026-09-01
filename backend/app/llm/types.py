"""Canonical request, response, capability, and budget types for the AI Gateway."""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class ModelCapability(str, Enum):
    """Capabilities requested by workflows instead of provider-specific models."""

    CODE_REASONING = "CODE_REASONING"
    STRUCTURED_EXTRACTION = "STRUCTURED_EXTRACTION"
    PATCH_GENERATION = "PATCH_GENERATION"
    DEEP_REASONING = "DEEP_REASONING"
    SECURITY_REASONING = "SECURITY_REASONING"
    VERIFICATION = "VERIFICATION"
    CLASSIFICATION = "CLASSIFICATION"
    RESEARCH = "RESEARCH"
    EMBEDDING = "EMBEDDING"
    RERANKING = "RERANKING"


class ModelCostTier(int, Enum):
    """Comparable cost/escalation tiers; lower tiers are always attempted first."""

    FREE = 0
    CHEAP = 1
    STANDARD = 2
    PREMIUM = 3


class AIValidationResult(str, Enum):
    """Persistable validation outcome for one model attempt."""

    NOT_REQUESTED = "NOT_REQUESTED"
    VALID = "VALID"
    INVALID = "INVALID"
    UNCERTAIN = "UNCERTAIN"


class AIRequestBudget(BaseModel):
    """Hard limits owned by one logical AI request."""

    model_config = ConfigDict(frozen=True)

    # One cheap attempt, bounded transient retries, and one stronger fallback
    # cover the normal path without turning failures into an all-provider sweep.
    max_ai_calls: int = Field(default=4, ge=1, le=100)
    max_input_tokens: int = Field(default=100_000, ge=1)
    max_output_tokens: int = Field(default=16_384, ge=1)
    max_escalation_tier: ModelCostTier = ModelCostTier.PREMIUM
    max_context_tokens: int = Field(default=128_000, ge=1)


class AIExecutionLineage(BaseModel):
    """Safe identifiers/digests used to persist AI provenance without source text."""

    model_config = ConfigDict(frozen=True)

    tenant_id: Optional[str] = Field(default=None, max_length=36)
    request_id: Optional[str] = Field(default=None, max_length=128)
    work_item_id: Optional[str] = Field(default=None, max_length=36)
    attempt_id: Optional[str] = Field(default=None, max_length=36)
    parent_execution_id: Optional[str] = Field(default=None, max_length=36)
    prompt_template_version: str = Field(default="unspecified", min_length=1, max_length=128)
    output_schema_version: Optional[str] = Field(default=None, max_length=128)
    evidence_digest: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    policy_snapshot_id: Optional[str] = Field(default=None, max_length=36)


class LLMMessage(BaseModel):
    """Normalized chat message structure."""

    role: Literal["system", "user", "assistant"] = Field(..., description="Message author role")
    content: str = Field(..., description="Content text of the message")


class LLMRequest(BaseModel):
    """Request payload passed to LLMRouter or adapters."""

    messages: List[LLMMessage] = Field(..., min_length=1, description="Ordered conversation history")
    task_policy: Optional[TaskPolicy] = Field(default=None, description="Task policy for automatic routing")
    capability: Optional[ModelCapability] = Field(default=None, description="Provider-neutral capability request")
    provider: Optional[LLMProvider] = Field(default=None, description="Explicit provider override")
    model: Optional[str] = Field(default=None, description="Explicit model ID override")
    excluded_providers: List[LLMProvider] = Field(
        default_factory=list,
        description="Providers excluded for independent verification or operational policy.",
    )
    excluded_models: List[str] = Field(default_factory=list)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: Optional[int] = Field(default=None, ge=1, description="Maximum tokens to generate")
    json_mode: bool = Field(default=False, description="Require valid JSON output from the model")
    output_schema: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Bounded JSON Schema subset used to validate structured model output",
    )
    confidence_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Escalate sequentially when validated JSON reports lower confidence",
    )
    allow_escalation: bool = Field(default=True, description="Permit a stronger sequential candidate when needed")
    budget: AIRequestBudget = Field(default_factory=AIRequestBudget)
    lineage: AIExecutionLineage = Field(default_factory=AIExecutionLineage)
    timeout_seconds: Optional[float] = Field(default=None, ge=1.0, description="Request timeout override in seconds")
    extra_params: Dict[str, Any] = Field(default_factory=dict, description="Additional provider-specific parameters")

    @model_validator(mode="after")
    def enforce_gateway_contract(self) -> "LLMRequest":
        if self.output_schema is not None:
            self.json_mode = True
        if self.max_tokens is not None and self.max_tokens > self.budget.max_output_tokens:
            raise ValueError("max_tokens cannot exceed budget.max_output_tokens")
        return self


class LLMResponse(BaseModel):
    """Normalized response returned by LLMRouter and adapters."""

    content: str = Field(..., description="Generated text content")
    model: str = Field(..., description="Actual model ID that processed the request")
    provider: LLMProvider = Field(..., description="Provider that served the response")
    metadata: ModelExecutionMetadata = Field(..., description="Telemetry and token usage metadata")
    finish_reason: Optional[str] = Field(default=None, description="Model stop/finish reason")
