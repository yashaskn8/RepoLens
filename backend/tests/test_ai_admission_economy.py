"""Acceptance tests for deterministic AI admission and shared cloud ceilings."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from app.agents.architecture import run_architecture_agent
from app.agents.bug import run_bug_agent
from app.agents.security import run_security_agent
from app.llm.admission import AdmissionDecision, build_admission_map, build_admission_plan
from app.llm.economy import WorkflowCloudBudget
from app.llm.base import BaseLLMAdapter
from app.llm.capabilities import ModelCapabilityRegistry, ModelCapabilitySpec
from app.llm.gateway import CapabilityAIGateway
from app.llm.types import AIRequestBudget, LLMMessage, LLMProvider, LLMRequest, LLMResponse, ModelCapability, ModelCostTier
from app.schemas.metadata import ModelExecutionMetadata


def _scanner_finding() -> dict:
    return {
        "tool": "semgrep",
        "rule_id": "python.lang.security.test",
        "title": "Deterministic scanner finding",
        "description": "A scanner-attested finding.",
        "severity": "HIGH",
        "evidence": {
            "file_path": "src/app.py",
            "start_line": 3,
            "end_line": 4,
            "code_snippet": "dangerous_call()",
        },
    }


def test_admission_prioritizes_deterministic_scanner_facts() -> None:
    state = {
        "static_findings": [_scanner_finding()],
        "routes": [],
        "frontend_calls": [],
        "manifest_summary": {"total_files": 1},
    }

    plan = build_admission_plan(state, "security")
    assert plan.decision == AdmissionDecision.DETERMINISTIC_ONLY
    assert plan.max_output_tokens == 0
    assert "independently verifiable" in plan.reason
    assert build_admission_map(state)["security"]["decision"] == "DETERMINISTIC_ONLY"


def test_admission_skips_specialist_without_evidence() -> None:
    plan = build_admission_plan(
        {"static_findings": [], "routes": [], "frontend_calls": []},
        "bug",
    )
    assert plan.decision == AdmissionDecision.SKIP
    assert plan.unresolved is False


@pytest.mark.asyncio
async def test_skipped_specialists_never_touch_router() -> None:
    state = {
        "scan_id": str(uuid4()),
        "static_findings": [],
        "routes": [],
        "frontend_calls": [],
        "manifest_summary": {"total_files": 0},
        "languages": {},
        "frameworks": [],
    }
    router = AsyncMock()
    with patch("app.agents.architecture.get_llm_router", return_value=router), \
         patch("app.agents.bug.get_llm_router", return_value=router), \
         patch("app.agents.security.get_llm_router", return_value=router):
        architecture = await run_architecture_agent(state)
        bug = await run_bug_agent(state)
        security = await run_security_agent(state)

    assert architecture["model_executions"] == []
    assert bug["model_executions"] == []
    assert security["model_executions"] == []
    router.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_scanner_only_security_never_touches_router() -> None:
    state = {
        "scan_id": str(uuid4()),
        "static_findings": [_scanner_finding()],
        "routes": [],
        "frontend_calls": [],
        "languages": {},
        "frameworks": [],
    }
    router = AsyncMock()
    with patch("app.agents.security.get_llm_router", return_value=router):
        result = await run_security_agent(state)

    assert len(result["candidate_findings"]) == 1
    router.generate.assert_not_awaited()


def test_workflow_cloud_budget_counts_only_remote_attempts() -> None:
    budget = WorkflowCloudBudget(mode="strict", max_cloud_calls=2, max_cloud_tokens=1_000)
    assert budget.reserve(LLMProvider.OLLAMA, input_tokens=900, output_tokens=900)
    assert budget.used_cloud_calls == 0
    assert budget.reserve(LLMProvider.CLOUDFLARE, input_tokens=100, output_tokens=100)
    assert budget.reserve(LLMProvider.GROQ, input_tokens=100, output_tokens=100)
    assert not budget.reserve(LLMProvider.GEMINI, input_tokens=1, output_tokens=1)
    snapshot = budget.snapshot()
    assert snapshot.used_cloud_calls == 2
    assert snapshot.exhausted is True


@pytest.mark.asyncio
async def test_strict_cloud_ceiling_limits_actual_gateway_invocations() -> None:
    spec = ModelCapabilitySpec(
        provider=LLMProvider.GEMINI,
        model="cloud-model",
        capabilities=frozenset({ModelCapability.REPOSITORY_ANALYSIS}),
        cost_tier=ModelCostTier.CHEAP,
        quality_rank=1,
        context_window_tokens=8_000,
        max_output_tokens=1_000,
    )
    adapter = AsyncMock(spec=BaseLLMAdapter)
    adapter.generate.return_value = LLMResponse(
        content="ok",
        provider=LLMProvider.GEMINI,
        model="cloud-model",
        metadata=ModelExecutionMetadata(model_name="cloud-model", provider="gemini"),
    )
    gateway = CapabilityAIGateway(
        {LLMProvider.GEMINI: adapter},
        registry=ModelCapabilityRegistry((spec,)),
        max_retries=0,
    )
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="facts")],
        capability=ModelCapability.REPOSITORY_ANALYSIS,
        budget=AIRequestBudget(max_ai_calls=2, max_escalation_tier=ModelCostTier.CHEAP),
    )
    budget = WorkflowCloudBudget(mode="strict", max_cloud_calls=1, max_cloud_tokens=10_000)

    from app.llm.economy import bind_workflow_cloud_budget, reset_workflow_cloud_budget

    token = bind_workflow_cloud_budget(budget)
    try:
        assert (await gateway.generate(request)).content == "ok"
        with pytest.raises(Exception, match="All sequential candidates|cloud-use budget"):
            await gateway.generate(request)
    finally:
        reset_workflow_cloud_budget(token)

    assert adapter.generate.await_count == 1
