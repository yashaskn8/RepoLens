"""Tests for Phase 3B: Root-Cause Fix Planner and Adversarial Plan Validation."""

from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.analysis.store import EvidenceStore
from app.context.engine import ContextEngine
from app.context.schemas import ContextBundle
from app.graph.repository_graph import RepositoryGraph
from app.ingestion.schemas import FileEntry, RepositoryManifest
from app.llm.types import (
    LLMProvider,
    LLMResponse,
    ModelExecutionMetadata,
    TaskPolicy,
)
from app.planning.agent import FixPlannerAgent
from app.planning.schemas import (
    FixPlan,
    FixScope,
    OrderedChangeStep,
    PlanValidationStatus,
)
from app.planning.service import FixPlanningService
from app.planning.validator import validate_fix_plan
from app.research.schemas import ResearchEvidence, ResearchResult, SourceTier
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


# =========================================================================
# 1. Adversarial Plan Validation Tests
# =========================================================================

def test_fix_planner_rejects_invented_files():
    """Verify planner rejects plans that reference files not present in the repository."""
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash="1234567890ab",
        total_files=1,
        total_size_bytes=100,
        languages={"python": 1},
        frameworks=[],
        files=[FileEntry(path="app/real_file.py", language="python", size_bytes=100, lines_count=10, symbols=[])],
    )

    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="SQL Injection",
        description="SQL injection in query",
        severity=Severity.HIGH,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/real_file.py", start_line=5, end_line=6)],
    )

    # Adversarial Plan targeting invented file
    plan = FixPlan(
        finding_id=finding.id,
        root_cause="Unsanitized user input",
        objective="Sanitize query",
        files_expected_to_change=["app/invented_file.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/invented_file.py",
                description="Modify invented file",
                rationale="Required change",
            )
        ],
        validation_plan=["pytest tests/"],
    )

    report = validate_fix_plan(plan=plan, finding=finding, manifest=manifest)

    assert not report.is_valid
    assert report.status == PlanValidationStatus.REJECTED
    assert any("invented file" in r for r in report.rejection_reasons)


def test_fix_planner_rejects_unconfirmed_rejected_finding():
    """Verify planner refuses to plan remediation for a finding marked REJECTED by verifier."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Hallucinated Issue",
        description="Fake issue that verifier caught",
        severity=Severity.LOW,
        verification_verdict=VerificationVerdict.REJECTED,
        evidences=[Evidence(file_path="app/main.py", start_line=1, end_line=5)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="N/A",
        objective="Fix",
        files_expected_to_change=["app/main.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/main.py",
                description="Change",
                rationale="Change",
            )
        ],
        validation_plan=["pytest"],
    )

    report = validate_fix_plan(plan=plan, finding=finding)

    assert not report.is_valid
    assert report.status == PlanValidationStatus.REJECTED
    assert any("REJECTED by independent verification" in r for r in report.rejection_reasons)


def test_fix_planner_rejects_alias_workarounds():
    """Verify planner rejects solutions that propose adding alias routes to hide contract mismatches."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Route Mismatch on Orders Endpoint",
        description="Frontend calls /submit but backend defines /checkout",
        severity=Severity.HIGH,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/routes.py", start_line=10, end_line=15)],
    )

    # Adversarial Plan proposing forbidden alias workaround
    plan = FixPlan(
        finding_id=finding.id,
        root_cause="Endpoint name mismatch between frontend and backend",
        objective="Add alias route to hide contract mismatch without updating frontend call",
        files_expected_to_change=["app/routes.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/routes.py",
                description="Add alias route /submit that forwards internally to /checkout",
                rationale="Quick fix without touching frontend client",
            )
        ],
        validation_plan=["Test endpoint alias"],
    )

    report = validate_fix_plan(plan=plan, finding=finding)

    assert not report.is_valid
    assert report.status == PlanValidationStatus.REJECTED
    assert any("alias workaround" in r for r in report.rejection_reasons)


def test_fix_planner_rejects_raw_code_generation_in_plan():
    """Verify planner rejects change steps that contain raw code blocks instead of structured instructions."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Zero Division Bug",
        description="Unhandled division",
        severity=Severity.MEDIUM,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/calc.py", start_line=2, end_line=4)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="No zero check",
        objective="Add zero check",
        files_expected_to_change=["app/calc.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/calc.py",
                description="```python\ndef calculate(a, b):\n    if b == 0:\n        return 0\n    return a / b\n```",
                rationale="Replace code directly",
            )
        ],
        validation_plan=["pytest"],
    )

    report = validate_fix_plan(plan=plan, finding=finding)

    assert not report.is_valid
    assert report.status == PlanValidationStatus.REJECTED
    assert any("raw code blocks" in r for r in report.rejection_reasons)


# =========================================================================
# 2. FixPlannerAgent & Service Execution Tests
# =========================================================================

@pytest.mark.asyncio
async def test_fix_planner_agent_successful_plan_generation():
    """Verify FixPlannerAgent invokes router and produces valid FixPlan."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Unsanitized SQL Query with Formatted String",
        description="Formatted string in SQL execution allows SQL injection.",
        severity=Severity.HIGH,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[
            Evidence(
                file_path="app/db/query.py",
                start_line=8,
                end_line=9,
                code_snippet="query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"",
            )
        ],
    )

    context_bundle = ContextBundle(
        scan_id="scan-123",
        query="SQL injection execute_user_query",
        analysis_intent="fix_planning",
        relevant_chunks=[],
    )

    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash="abcdef",
        total_files=1,
        total_size_bytes=200,
        languages={"python": 1},
        frameworks=[],
        files=[FileEntry(path="app/db/query.py", language="python", size_bytes=200, lines_count=20, symbols=[])],
    )

    mock_plan_json = """{
        "root_cause": "Direct string interpolation of untrusted user_id parameter into SQLite query statement.",
        "objective": "Replace format-string SQL query with parameterized placeholder syntax.",
        "files_expected_to_change": ["app/db/query.py"],
        "symbols_expected_to_change": ["execute_user_query"],
        "ordered_changes": [
            {
                "step_number": 1,
                "target_file": "app/db/query.py",
                "target_symbol": "execute_user_query",
                "description": "Refactor cursor.execute to use parameterized query with tuple parameters instead of formatted string",
                "rationale": "Ensures database driver safely escapes input, eliminating SQL injection vulnerability"
            }
        ],
        "interfaces_affected": ["execute_user_query signature remains unchanged"],
        "migration_config_impact": null,
        "regression_risks": ["Tuple parameter type mismatch if user_id is not a string/primitive"],
        "validation_plan": ["Run unit test with special SQL metacharacters like quote and semicolon"],
        "estimated_scope": "function",
        "assumptions": ["SQLite database cursor supports standard ? parameterization"]
    }"""

    mock_resp = LLMResponse(
        content=mock_plan_json,
        model="gemini-3.7-flash",
        provider=LLMProvider.GEMINI,
        metadata=ModelExecutionMetadata(
            model_name="gemini-3.7-flash",
            provider="gemini",
            execution_time_ms=40.0,
        ),
    )

    with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_resp

        agent = FixPlannerAgent()
        plan = await agent.plan(
            finding=finding,
            context_bundle=context_bundle,
            manifest=manifest,
        )

        assert isinstance(plan, FixPlan)
        assert plan.finding_id == finding.id
        assert plan.files_expected_to_change == ["app/db/query.py"]
        assert len(plan.ordered_changes) == 1
        assert plan.estimated_scope == FixScope.FUNCTION
        assert plan.validation_report is not None
        assert plan.validation_report.is_valid
        assert plan.validation_report.status == PlanValidationStatus.VALID


@pytest.mark.asyncio
async def test_fix_planning_service_orchestration():
    """Verify FixPlanningService coordinates ContextEngine, ResearchResult, and FixPlannerAgent."""
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash="abcdef",
        total_files=1,
        total_size_bytes=200,
        languages={"python": 1},
        frameworks=[],
        files=[FileEntry(path="app/routes.py", language="python", size_bytes=200, lines_count=20, symbols=[])],
    )
    evidence_store = EvidenceStore(manifest=manifest)
    context_engine = ContextEngine(evidence_store=evidence_store)

    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Deprecated FastAPI Route Syntax",
        description="on_event deprecated",
        severity=Severity.LOW,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/routes.py", start_line=1, end_line=5)],
    )

    research_res = ResearchResult(
        target_framework="FastAPI",
        detected_version="0.95.0",
        recommended_version="0.115.0",
        migration_summary="Migrate on_event to lifespan",
        repository_impact="Affects app initialization",
        evidences=[
            ResearchEvidence(
                source_url="https://fastapi.tiangolo.com/advanced/events/",
                source_title="Lifespan Events",
                supported_claim="Lifespan replaces on_event",
                source_tier=SourceTier.OFFICIAL_DOCS,
            )
        ],
    )

    mock_plan_json = """{
        "root_cause": "Deprecated startup handler",
        "objective": "Migrate to lifespan",
        "files_expected_to_change": ["app/routes.py"],
        "symbols_expected_to_change": ["startup"],
        "ordered_changes": [
            {
                "step_number": 1,
                "target_file": "app/routes.py",
                "target_symbol": "startup",
                "description": "Convert startup function to asynccontextmanager lifespan handler",
                "rationale": "Adheres to official FastAPI 0.115.0 migration guidelines"
            }
        ],
        "validation_plan": ["pytest tests/"]
    }"""

    mock_resp = LLMResponse(
        content=mock_plan_json,
        model="mock-model",
        provider=LLMProvider.GEMINI,
        metadata=ModelExecutionMetadata(model_name="mock", provider="gemini", execution_time_ms=10.0),
    )

    with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_resp

        service = FixPlanningService()
        plan = await service.create_fix_plan(
            finding=finding,
            context_engine=context_engine,
            research_result=research_res,
            manifest=manifest,
        )

        assert plan.finding_id == finding.id
        assert plan.validation_report.is_valid
