"""Model execution metadata schema for telemetry and observability."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ModelExecutionMetadata(BaseModel):
    """Execution telemetry and token usage metadata for AI model operations."""

    model_name: str = Field(..., description="Name or identifier of the AI model invoked")
    provider: Optional[str] = Field(default=None, description="AI provider name (e.g. google, anthropic, openai)")
    prompt_tokens: Optional[int] = Field(default=None, ge=0, description="Tokens consumed by the prompt")
    completion_tokens: Optional[int] = Field(default=None, ge=0, description="Tokens generated in the completion")
    total_tokens: Optional[int] = Field(default=None, ge=0, description="Total tokens consumed")
    execution_time_ms: Optional[float] = Field(default=None, ge=0.0, description="Execution wall-clock time in milliseconds")
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0, description="Sampling temperature used")
    extra_metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional custom metadata or telemetry tags")

    model_config = {
        "json_schema_extra": {
            "example": {
                "model_name": "gemini-1.5-pro",
                "provider": "google",
                "prompt_tokens": 1250,
                "completion_tokens": 340,
                "total_tokens": 1590,
                "execution_time_ms": 842.5,
                "temperature": 0.2,
                "extra_metadata": {"cache_hit": True}
            }
        }
    }
