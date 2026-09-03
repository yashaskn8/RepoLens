"""RepoLens LangChain Chat Model Adapter.

Thin interoperability layer wrapping RepoLens's LLMRouter and runtime AI Gateway
(TaskClassifier, CapabilityAIGateway, ProviderHealthRegistry, quotas, budgets,
circuit breakers, and provider adapters).

LangChain never acts as a second router: all generation requests route through
LLMRouter.generate(...) as the single authoritative gateway.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Type,
    TypeVar,
    Union,
)

from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    ChatMessage,
    HumanMessage,
    SystemMessage,
)
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from app.llm.exceptions import LLMError, LLMResponseValidationError
from app.llm.router import LLMRouter, get_llm_router
from app.llm.structured import StructuredOutputGateway
from app.llm.types import (
    AIExecutionLineage,
    AIRequestBudget,
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
    TaskPolicy,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


def convert_langchain_to_repolens_messages(messages: Sequence[BaseMessage]) -> List[LLMMessage]:
    """Convert a sequence of LangChain BaseMessage objects to RepoLens LLMMessage objects.

    Supported message types:
    - SystemMessage -> role="system"
    - HumanMessage -> role="user"
    - AIMessage -> role="assistant"

    Raises ValueError on unsupported message types or non-string/multimodal contents.
    Preserves ordering and does not mutate input message objects.
    """
    repolens_messages: List[LLMMessage] = []
    for msg in messages:
        if not isinstance(msg, BaseMessage):
            raise ValueError(f"Expected BaseMessage instance, got: {type(msg).__name__}")

        if isinstance(msg.content, str):
            content_str = msg.content
        elif isinstance(msg.content, list):
            parts: List[str] = []
            for part in msg.content:
                if isinstance(part, str):
                    parts.append(part)
                elif isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    parts.append(part["text"])
                else:
                    raise ValueError(
                        f"Unsupported content block in {type(msg).__name__}: {part}. "
                        "Multimodal content is not supported in this phase."
                    )
            content_str = "".join(parts)
        else:
            raise ValueError(f"Unsupported content type in {type(msg).__name__}: {type(msg.content).__name__}")

        if isinstance(msg, SystemMessage):
            role = "system"
        elif isinstance(msg, HumanMessage):
            role = "user"
        elif isinstance(msg, AIMessage):
            role = "assistant"
        elif isinstance(msg, ChatMessage):
            if msg.role in ("system", "user", "assistant"):
                role = msg.role
            else:
                raise ValueError(f"Unsupported role in ChatMessage: {msg.role}")
        else:
            raise ValueError(f"Unsupported LangChain message type: {type(msg).__name__}")

        repolens_messages.append(LLMMessage(role=role, content=content_str))

    return repolens_messages


def convert_repolens_to_aimessage(response: LLMResponse) -> AIMessage:
    """Convert a RepoLens LLMResponse into a LangChain AIMessage with standard metadata.

    Populates:
    - usage_metadata: {"input_tokens": ..., "output_tokens": ..., "total_tokens": ...}
    - response_metadata: {"provider": ..., "model": ..., "finish_reason": ..., "latencyMs": ..., "fallbackUsed": ...}

    Strictly avoids exposing API keys, raw credentials, or sensitive headers.
    """
    extra = response.metadata.extra_metadata or {}
    fallback_used = bool(
        extra.get("fallback_used", False)
        or extra.get("retry_count", 0) > 0
        or extra.get("fallbacks_attempted")
    )

    usage_metadata: Dict[str, int] = {
        "input_tokens": response.metadata.prompt_tokens or 0,
        "output_tokens": response.metadata.completion_tokens or 0,
        "total_tokens": response.metadata.total_tokens or 0,
    }

    response_metadata: Dict[str, Any] = {
        "provider": response.provider.value if isinstance(response.provider, LLMProvider) else str(response.provider),
        "model": response.model,
        "finish_reason": response.finish_reason or "stop",
        "latencyMs": round(response.metadata.execution_time_ms, 2) if response.metadata.execution_time_ms is not None else None,
        "fallbackUsed": fallback_used,
    }
    if extra.get("retry_count"):
        response_metadata["retry_count"] = extra["retry_count"]

    return AIMessage(
        content=response.content,
        response_metadata=response_metadata,
        usage_metadata=usage_metadata,
    )


class RepoLensChatModel(BaseChatModel):
    """RepoLens custom LangChain chat model adapter.

    Acts as a thin interoperability layer routing all requests through RepoLens's
    existing LLMRouter and governance architecture (TaskClassifier, CapabilityAIGateway,
    ProviderHealthRegistry, quotas, budgets, circuit breakers, and provider adapters).
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    router: Any = Field(default=None, description="LLMRouter instance (defaults to global singleton)")
    task_policy: Optional[TaskPolicy] = Field(default=None, description="RepoLens task policy for automatic routing")
    capability: Optional[ModelCapability] = Field(default=None, description="Provider-neutral capability request")
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: Optional[int] = Field(default=None, ge=1, description="Maximum tokens to generate")
    timeout_seconds: Optional[float] = Field(default=None, ge=1.0, description="Request timeout override in seconds")
    allow_escalation: bool = Field(default=True, description="Permit sequential model escalation when needed")
    budget: Optional[AIRequestBudget] = Field(default=None, description="Budget constraints for the request")
    lineage: Optional[AIExecutionLineage] = Field(default=None, description="Audit lineage information")
    structured_output_schema: Optional[Dict[str, Any]] = Field(
        default=None, description="Bounded JSON Schema for structured output"
    )
    confidence_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Minimum confidence threshold")
    extra_params: Dict[str, Any] = Field(default_factory=dict, description="Additional model parameters")

    @property
    def _llm_type(self) -> str:
        """Return identifier for LangChain model tracking."""
        return "repolens-chat-model"

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        """Asynchronously dispatch request to RepoLens LLMRouter."""
        router = self.router or get_llm_router()
        repolens_messages = convert_langchain_to_repolens_messages(messages)

        # Merge invocation kwargs with model configuration
        task_policy = kwargs.get("task_policy", self.task_policy)
        capability = kwargs.get("capability", self.capability)
        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = kwargs.get("max_tokens", self.max_tokens)
        timeout_seconds = kwargs.get("timeout_seconds", self.timeout_seconds)
        raw_output_schema = kwargs.get("output_schema", self.structured_output_schema)
        output_schema = raw_output_schema if isinstance(raw_output_schema, dict) else None
        confidence_threshold = kwargs.get("confidence_threshold", self.confidence_threshold)
        allow_escalation = kwargs.get("allow_escalation", self.allow_escalation)
        budget = kwargs.get("budget", self.budget) or AIRequestBudget()
        lineage = kwargs.get("lineage", self.lineage) or AIExecutionLineage()

        extra_params = dict(self.extra_params)
        extra_params.update(kwargs.get("extra_params", {}))
        if stop is not None:
            extra_params["stop"] = stop

        request = LLMRequest(
            messages=repolens_messages,
            task_policy=task_policy,
            capability=capability,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout_seconds=timeout_seconds,
            output_schema=output_schema,
            confidence_threshold=confidence_threshold,
            allow_escalation=allow_escalation,
            budget=budget,
            lineage=lineage,
            extra_params=extra_params,
        )

        response = await router.generate(request)
        ai_message = convert_repolens_to_aimessage(response)

        return ChatResult(generations=[ChatGeneration(message=ai_message)])

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        """Synchronous generation fallback.

        If called within an active event loop, raises RuntimeError directing caller to ainvoke().
        If called outside an active event loop, safely executes via asyncio.run().
        """
        try:
            asyncio.get_running_loop()
            raise RuntimeError(
                "RepoLensChatModel is async-first. Within an active event loop, "
                "please use await model.ainvoke(...) instead of invoke()."
            )
        except RuntimeError as exc:
            if "no running event loop" in str(exc).lower():
                return asyncio.run(self._agenerate(messages, stop=stop, run_manager=None, **kwargs))
            raise

    def with_structured_output(
        self,
        schema: Union[Dict[str, Any], Type[BaseModel], Any],
        *,
        include_raw: bool = False,
        **kwargs: Any,
    ) -> Runnable:
        """Create a Runnable that structures model output according to the provided schema.

        Reuses RepoLens's authoritative StructuredOutputGateway validation pipeline:
        LangChain schema -> JSON Schema -> LLMRequest.output_schema -> LLMRouter
        -> CapabilityAIGateway -> StructuredOutputGateway -> validated JSON -> Pydantic / dict.

        Supports:
        - Pydantic BaseModel classes
        - Raw JSON Schema dictionaries
        - TypedDict types (via Pydantic TypeAdapter)
        """
        json_schema: Dict[str, Any]
        pydantic_cls: Optional[Type[BaseModel]] = None

        if isinstance(schema, type) and issubclass(schema, BaseModel):
            json_schema = schema.model_json_schema()
            pydantic_cls = schema
        elif isinstance(schema, dict):
            if "properties" in schema or "type" in schema:
                json_schema = schema
            elif "parameters" in schema and isinstance(schema["parameters"], dict):
                json_schema = schema["parameters"]
            else:
                json_schema = schema
        elif hasattr(schema, "__annotations__"):
            try:
                adapter = TypeAdapter(schema)
                json_schema = adapter.json_schema()
            except Exception as exc:
                raise ValueError(f"Failed to generate JSON schema from TypedDict {schema}: {exc}") from exc
        else:
            raise ValueError(
                f"Unsupported schema type: {type(schema).__name__}. Must be Pydantic BaseModel, dict, or TypedDict."
            )

        bound_capability = self.capability or ModelCapability.STRUCTURED_EXTRACTION
        bound_model = self.model_copy(
            update={
                "structured_output_schema": json_schema,
                "capability": bound_capability,
            }
        )

        async def _parse_and_validate(input_val: Any) -> Any:
            raw_message: AIMessage = await bound_model.ainvoke(input_val, **kwargs)

            try:
                gateway = StructuredOutputGateway()
                provider_val = LLMProvider.MISTRAL
                model_name = "structured-gateway"
                if raw_message.response_metadata.get("provider"):
                    try:
                        provider_val = LLMProvider(raw_message.response_metadata["provider"])
                    except Exception:
                        pass
                if raw_message.response_metadata.get("model"):
                    model_name = str(raw_message.response_metadata["model"])

                validation = gateway.validate(
                    raw_message.content,
                    schema=json_schema,
                    confidence_threshold=self.confidence_threshold,
                    provider=provider_val,
                    model=model_name,
                )
                parsed_val = validation.value

                if pydantic_cls is not None:
                    final_parsed = pydantic_cls.model_validate(parsed_val)
                else:
                    final_parsed = parsed_val

                if include_raw:
                    return {
                        "raw": raw_message,
                        "parsed": final_parsed,
                        "parsing_error": None,
                    }
                return final_parsed

            except Exception as exc:
                if include_raw:
                    return {
                        "raw": raw_message,
                        "parsed": None,
                        "parsing_error": exc,
                    }
                raise

        return RunnableLambda(_parse_and_validate)
