"""Comprehensive unit test suite for RepoLens LangChain Integration Layer.

Verifies message conversion, routing preservation, usage/response metadata,
async-first lifecycle, structured output through StructuredOutputGateway,
prompt template composition, and error propagation without real network calls.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import (
    AIMessage,
    ChatMessage,
    FunctionMessage,
    HumanMessage,
    SystemMessage,
)
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

from app.llm.exceptions import (
    LLMAllFallbacksFailedError,
    LLMError,
    LLMResponseValidationError,
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
from app.llm.router import LLMRouter
from app.llm.structured import StructuredOutputGateway
from app.llm.types import (
    LLMMessage,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelCapability,
    TaskPolicy,
)
from app.schemas.metadata import ModelExecutionMetadata


# ------------------------------------------------------------------------------
# Test Fixtures & Helpers
# ------------------------------------------------------------------------------
def create_dummy_llm_response(
    content: str = "Test output from RepoLens router",
    provider: LLMProvider = LLMProvider.MISTRAL,
    model: str = "mistral-large",
    prompt_tokens: int = 15,
    completion_tokens: int = 25,
    total_tokens: int = 40,
    execution_time_ms: float = 120.5,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> LLMResponse:
    """Create a normalized LLMResponse for mock testing."""
    return LLMResponse(
        content=content,
        provider=provider,
        model=model,
        finish_reason="stop",
        metadata=ModelExecutionMetadata(
            model_name=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            execution_time_ms=execution_time_ms,
            extra_metadata=extra_metadata or {},
        ),
    )


class SampleAnalysisOutput(BaseModel):
    """Target Pydantic model for structured output verification."""

    summary: str = Field(description="Summary of analysis")
    risk_level: str = Field(description="Risk level: low, medium, or high")
    findings_count: int = Field(description="Number of findings")


# ------------------------------------------------------------------------------
# Test 1: Message Conversion & Ordering
# ------------------------------------------------------------------------------
def test_message_conversion_and_ordering():
    """Verify SystemMessage, HumanMessage, and AIMessage convert accurately with order preserved."""
    lc_messages = [
        SystemMessage(content="You are an expert system auditor."),
        HumanMessage(content="Analyze repository auth module."),
        AIMessage(content="Auth module uses Argon2id password hashing."),
        HumanMessage(content="Are cookies configured as HttpOnly?"),
    ]

    repolens_messages = convert_langchain_to_repolens_messages(lc_messages)

    assert len(repolens_messages) == 4
    assert repolens_messages[0] == LLMMessage(role="system", content="You are an expert system auditor.")
    assert repolens_messages[1] == LLMMessage(role="user", content="Analyze repository auth module.")
    assert repolens_messages[2] == LLMMessage(role="assistant", content="Auth module uses Argon2id password hashing.")
    assert repolens_messages[3] == LLMMessage(role="user", content="Are cookies configured as HttpOnly?")

    # Verify input list is unchanged (no mutation)
    assert len(lc_messages) == 4
    assert isinstance(lc_messages[0], SystemMessage)


def test_message_conversion_unsupported_type_fails():
    """Verify unsupported message types raise explicit ValueError."""
    unsupported_msg = FunctionMessage(name="dummy_tool", content="tool output")
    with pytest.raises(ValueError, match="Unsupported LangChain message type"):
        convert_langchain_to_repolens_messages([unsupported_msg])


def test_message_conversion_invalid_content_type_fails():
    """Verify multimodal / non-text content blocks raise explicit ValueError."""
    multimodal_msg = HumanMessage(content=[{"type": "image_url", "image_url": "https://example.com/pic.jpg"}])
    with pytest.raises(ValueError, match="Multimodal content is not supported in this phase"):
        convert_langchain_to_repolens_messages([multimodal_msg])

    with pytest.raises(ValueError, match="Expected BaseMessage instance"):
        convert_langchain_to_repolens_messages(["raw string instead of BaseMessage"])  # type: ignore


# ------------------------------------------------------------------------------
# Test 2: Response Conversion & Standard Metadata Separation
# ------------------------------------------------------------------------------
def test_response_conversion_metadata_separation():
    """Verify token metrics populate usage_metadata and operational telemetry populates response_metadata."""
    response = create_dummy_llm_response(
        content="Clean analysis response",
        provider=LLMProvider.CLOUDFLARE,
        model="@cf/meta/llama-3.3-70b-instruct",
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        execution_time_ms=250.75,
        extra_metadata={"fallback_used": False, "retry_count": 0},
    )

    ai_msg = convert_repolens_to_aimessage(response)

    # Standard LangChain usage_metadata
    assert ai_msg.usage_metadata == {
        "input_tokens": 100,
        "output_tokens": 50,
        "total_tokens": 150,
    }

    # Safe response_metadata
    assert ai_msg.response_metadata["provider"] == "cloudflare"
    assert ai_msg.response_metadata["model"] == "@cf/meta/llama-3.3-70b-instruct"
    assert ai_msg.response_metadata["finish_reason"] == "stop"
    assert ai_msg.response_metadata["latencyMs"] == 250.75
    assert ai_msg.response_metadata["fallbackUsed"] is False

    # Zero sensitive token leakage in metadata
    metadata_repr = str(ai_msg.response_metadata)
    assert "sk-" not in metadata_repr
    assert "ghp_" not in metadata_repr
    assert "authorization" not in metadata_repr.lower()


# ------------------------------------------------------------------------------
# Test 3: Async ainvoke routes through LLMRouter without bypassing
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ainvoke_routes_through_llm_router():
    """Verify LangChain ainvoke ultimately calls LLMRouter.generate and preserves configuration."""
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response())

    model = RepoLensChatModel(
        router=mock_router,
        task_policy=TaskPolicy.ARCHITECTURE,
        temperature=0.2,
        max_tokens=2048,
    )

    messages = [
        SystemMessage(content="System prompt"),
        HumanMessage(content="User query"),
    ]

    result_ai_msg = await model.ainvoke(messages)

    assert isinstance(result_ai_msg, AIMessage)
    assert result_ai_msg.content == "Test output from RepoLens router"

    # Verify LLMRouter was called exactly once with the expected LLMRequest
    mock_router.generate.assert_awaited_once()
    called_request: LLMRequest = mock_router.generate.call_args[0][0]

    assert isinstance(called_request, LLMRequest)
    assert called_request.task_policy == TaskPolicy.ARCHITECTURE
    assert called_request.temperature == 0.2
    assert called_request.max_tokens == 2048
    assert len(called_request.messages) == 2
    assert called_request.messages[0].role == "system"
    assert called_request.messages[1].role == "user"


# ------------------------------------------------------------------------------
# Test 4: Provider Adapters are NEVER called directly by LangChain
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_adapters_not_called_directly_by_langchain():
    """Verify LangChain calls the router gateway, not any provider adapter directly."""
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(provider=LLMProvider.MISTRAL))

    model = RepoLensChatModel(router=mock_router, capability=ModelCapability.CODE_REASONING)
    await model.ainvoke("Write a unit test")

    # The router's generate method was called
    mock_router.generate.assert_awaited_once()
    # Direct adapter methods on router (get_adapter) were NOT called by the model
    assert not hasattr(mock_router, "get_adapter") or not mock_router.get_adapter.called


# ------------------------------------------------------------------------------
# Test 5: Sync invoke raises error within active event loop
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sync_invoke_raises_error_within_running_event_loop():
    """Verify invoking sync invoke() inside a running asyncio loop raises descriptive RuntimeError."""
    mock_router = MagicMock(spec=LLMRouter)
    model = RepoLensChatModel(router=mock_router)

    with pytest.raises(RuntimeError, match="RepoLensChatModel is async-first.*ainvoke"):
        model.invoke("Hello from sync call inside async loop")


def test_sync_invoke_works_outside_running_event_loop():
    """Verify sync invoke() functions safely via asyncio.run when no event loop is running."""
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(content="Sync response outside loop"))
    model = RepoLensChatModel(router=mock_router)

    result = model.invoke("Hello from outside event loop")
    assert isinstance(result, AIMessage)
    assert result.content == "Sync response outside loop"


# ------------------------------------------------------------------------------
# Test 6: Structured Output Integration with Pydantic BaseModel
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# Test 6: Structured Output Integration with Pydantic BaseModel
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_with_structured_output_pydantic_no_duplicate_validation():
    """Verify with_structured_output calls router once and does NOT re-run StructuredOutputGateway.validate()."""
    valid_json_content = '{"summary": "Secure authentication module", "risk_level": "low", "findings_count": 0}'

    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(content=valid_json_content))

    model = RepoLensChatModel(router=mock_router)
    structured_model = model.with_structured_output(SampleAnalysisOutput)

    with patch.object(StructuredOutputGateway, "validate") as mock_gateway_validate:
        parsed_result = await structured_model.ainvoke("Analyze the auth module")

        # Proves Problem 1 fix: LangChain layer does NOT create an independent validation pass
        mock_gateway_validate.assert_not_called()

    assert isinstance(parsed_result, SampleAnalysisOutput)
    assert parsed_result.summary == "Secure authentication module"
    assert parsed_result.risk_level == "low"
    assert parsed_result.findings_count == 0

    # Verify router called exactly once with structured schema and json_mode
    mock_router.generate.assert_awaited_once()
    called_request: LLMRequest = mock_router.generate.call_args[0][0]
    assert called_request.output_schema is not None
    assert "properties" in called_request.output_schema
    assert called_request.json_mode is True


# ------------------------------------------------------------------------------
# Test 7: Structured Output Integration with raw JSON Schema Dict
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_with_structured_output_json_schema_dict():
    """Verify with_structured_output works with raw JSON Schema dictionary."""
    dict_schema = {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["healthy", "degraded"]},
            "score": {"type": "integer"},
        },
        "required": ["status", "score"],
    }
    valid_json = '{"status": "healthy", "score": 95}'

    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(content=valid_json))

    model = RepoLensChatModel(router=mock_router)
    structured_model = model.with_structured_output(dict_schema)

    result = await structured_model.ainvoke("Check system health")

    assert isinstance(result, dict)
    assert result["status"] == "healthy"
    assert result["score"] == 95
    mock_router.generate.assert_awaited_once()


# ------------------------------------------------------------------------------
# Test 8: Structured Output Error Handling (include_raw=False vs include_raw=True)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_invalid_structured_output_fails_fast_when_include_raw_false():
    """Verify include_raw=False propagates validation errors immediately without swallowing."""
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(
        side_effect=LLMResponseValidationError(
            "Gateway rejected invalid schema",
            provider=LLMProvider.MISTRAL,
            model="mistral-large",
        )
    )

    model = RepoLensChatModel(router=mock_router)
    structured_model = model.with_structured_output(SampleAnalysisOutput, include_raw=False)

    with pytest.raises(LLMResponseValidationError, match="Gateway rejected invalid schema"):
        await structured_model.ainvoke("Generate analysis")

    mock_router.generate.assert_awaited_once()


@pytest.mark.asyncio
async def test_structured_output_include_raw_on_gateway_rejection():
    """Verify include_raw=True returns safe dictionary when gateway rejects structured output."""
    mock_router = MagicMock(spec=LLMRouter)
    validation_err = LLMResponseValidationError(
        "Structured model output failed schema validation",
        provider=LLMProvider.MISTRAL,
        model="mistral-large",
    )
    mock_router.generate = AsyncMock(side_effect=validation_err)

    model = RepoLensChatModel(router=mock_router)
    structured_model = model.with_structured_output(SampleAnalysisOutput, include_raw=True)

    result = await structured_model.ainvoke("Analyze")

    assert isinstance(result, dict)
    assert result["raw"] is None
    assert result["parsed"] is None
    assert result["parsing_error"] is validation_err
    # Exactly one router attempt, no second raw retrieval call made
    mock_router.generate.assert_awaited_once()


@pytest.mark.asyncio
async def test_structured_output_include_raw_success_and_parse_error():
    """Verify include_raw=True returns raw AIMessage on success, and raw AIMessage if Pydantic parsing fails."""
    # 1. Success case
    valid_json = '{"summary": "Fine", "risk_level": "low", "findings_count": 1}'
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(content=valid_json))

    model = RepoLensChatModel(router=mock_router)
    structured_model = model.with_structured_output(SampleAnalysisOutput, include_raw=True)

    result = await structured_model.ainvoke("Analyze")

    assert isinstance(result, dict)
    assert isinstance(result["raw"], AIMessage)
    assert isinstance(result["parsed"], SampleAnalysisOutput)
    assert result["parsing_error"] is None

    # 2. Pydantic model validation failure on returned JSON (e.g. wrong type for findings_count)
    bad_type_json = '{"summary": "Fine", "risk_level": "low", "findings_count": "not_an_int"}'
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(content=bad_type_json))

    result_bad = await structured_model.ainvoke("Analyze")
    assert isinstance(result_bad["raw"], AIMessage)
    assert result_bad["parsed"] is None
    assert result_bad["parsing_error"] is not None


# ------------------------------------------------------------------------------
# Test 9: PromptTemplate | RepoLensChatModel Runnable Composition
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_prompt_template_runnable_composition():
    """Verify ChatPromptTemplate | RepoLensChatModel pipe composition executes cleanly."""
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(content="Composition test response"))

    model = RepoLensChatModel(router=mock_router, capability=ModelCapability.REPOSITORY_ANALYSIS)
    prompt = create_repository_analysis_prompt()

    chain = prompt | model

    result = await chain.ainvoke(
        {
            "repository_name": "RepoLens",
            "branch_name": "main",
            "context_summary": "Clean architecture with FastAPI & Redis",
            "task_description": "Analyze caching layer",
        }
    )

    assert isinstance(result, AIMessage)
    assert result.content == "Composition test response"

    # Verify rendered messages passed to LLMRouter
    called_request: LLMRequest = mock_router.generate.call_args[0][0]
    assert len(called_request.messages) == 2
    assert "You are RepoLens" in called_request.messages[0].content
    assert "Repository: RepoLens" in called_request.messages[1].content


# ------------------------------------------------------------------------------
# Test 10: Router Exception Propagation (No swallowing, no double retries)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_router_exceptions_propagate_without_swallowing():
    """Verify LLMAllFallbacksFailedError propagates cleanly without LangChain swallowing or re-retrying."""
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(
        side_effect=LLMAllFallbacksFailedError("All providers exhausted", attempted_errors=[])
    )

    model = RepoLensChatModel(router=mock_router)

    with pytest.raises(LLMAllFallbacksFailedError, match="All providers exhausted"):
        await model.ainvoke("Execute critical task")

    # LangChain called router once and did not spin up an independent retry loop
    mock_router.generate.assert_awaited_once()


# ------------------------------------------------------------------------------
# Test 11: Prompt Template Factories
# ------------------------------------------------------------------------------
def test_prompt_factories_deterministic_and_clean():
    """Verify prompt factories return valid ChatPromptTemplates without credentials."""
    repo_prompt = create_repository_analysis_prompt()
    extract_prompt = create_structured_extraction_prompt()
    sec_prompt = create_security_review_prompt()

    assert isinstance(repo_prompt, ChatPromptTemplate)
    assert isinstance(extract_prompt, ChatPromptTemplate)
    assert isinstance(sec_prompt, ChatPromptTemplate)

    # Check variable names
    assert set(repo_prompt.input_variables) == {"repository_name", "branch_name", "context_summary", "task_description"}
    assert set(extract_prompt.input_variables) == {"schema_description", "content", "directives"}
    assert set(sec_prompt.input_variables) == {"repository_name", "scope", "diff_content", "focus_areas"}


# ------------------------------------------------------------------------------
# Test 12: TypedDict Structured Output & Full Prompt Pipeline Composition
# ------------------------------------------------------------------------------
from typing import TypedDict


class FindingTypedDict(TypedDict):
    title: str
    severity: str


@pytest.mark.asyncio
async def test_with_structured_output_typed_dict():
    """Verify with_structured_output supports TypedDict schema."""
    valid_json = '{"title": "Unauthenticated endpoint", "severity": "HIGH"}'
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(content=valid_json))

    model = RepoLensChatModel(router=mock_router)
    structured_model = model.with_structured_output(FindingTypedDict)

    result = await structured_model.ainvoke("Audit endpoint")
    assert isinstance(result, dict)
    assert result["title"] == "Unauthenticated endpoint"
    assert result["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_prompt_structured_model_pipeline():
    """Verify prompt | structured_model pipeline composition works end-to-end."""
    valid_json = '{"summary": "Pipeline OK", "risk_level": "low", "findings_count": 0}'
    mock_router = MagicMock(spec=LLMRouter)
    mock_router.generate = AsyncMock(return_value=create_dummy_llm_response(content=valid_json))

    model = RepoLensChatModel(router=mock_router)
    structured_model = model.with_structured_output(SampleAnalysisOutput)
    prompt = create_structured_extraction_prompt()

    chain = prompt | structured_model

    result = await chain.ainvoke(
        {
            "schema_description": "SampleAnalysisOutput schema",
            "content": "Repository analysis content",
            "directives": "Extract summary, risk_level, findings_count",
        }
    )

    assert isinstance(result, SampleAnalysisOutput)
    assert result.summary == "Pipeline OK"
    assert result.risk_level == "low"
    assert result.findings_count == 0
