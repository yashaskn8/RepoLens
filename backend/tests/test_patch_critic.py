"""Tests for Phase 3E: Conditional Independent Patch Critic and Single-Revision Cap."""

from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.analysis.store import EvidenceStore
from app.context.engine import ContextEngine
from app.context.schemas import ContextBundle
from app.ingestion.schemas import FileEntry, RepositoryManifest
from app.llm.types import (
    LLMProvider,
    LLMResponse,
    ModelExecutionMetadata,
    TaskPolicy,
)
from app.patching.critic import PatchCriticAgent, should_escalate_to_critic
from app.patching.schemas import (
    CriticVerdict,
    PatchCriticReport,
    PatchProposal,
    PatchVerificationResult,
    PatchWorkflowResult,
    VerificationStatus,
)
from app.patching.workflow import PatchWorkflowCoordinator
from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


# =========================================================================
# 1. Conditional Escalation Rules Tests
# =========================================================================

def test_should_escalate_on_security_finding():
    """Verify security findings are unconditionally escalated to the independent critic."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="SQL Injection Vulnerability",
        description="SQL Injection in auth query",
        category="security",
        severity=Severity.HIGH,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/db/query.py", start_line=1, end_line=5)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="SQL string formatting",
        objective="Parameterize query",
        files_expected_to_change=["app/db/query.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/db/query.py", description="Fix", rationale="Fix")],
        validation_plan=["pytest"],
    )

    proposal = PatchProposal(
        finding_id=finding.id,
        plan_id=plan.id,
        unified_diff="--- a/app/db/query.py\n+++ b/app/db/query.py\n@@ -1,1 +1,1 @@\n-a\n+b\n",
        files_modified=["app/db/query.py"],
        explanation="Fix",
        expected_behavior_change="Fix",
    )

    verif = PatchVerificationResult(
        patch_id=proposal.id,
        finding_id=finding.id,
        status=VerificationStatus.PASSED,
        syntax_valid=True,
        security_clean=True,
        contract_aligned=True,
        target_finding_resolved=True,
        explanation="All checks passed",
    )

    escalate, reasons = should_escalate_to_critic(finding, plan, proposal, verif)
    assert escalate
    assert any("security" in r.lower() for r in reasons)


def test_should_not_escalate_on_low_risk_clean_patch():
    """Verify low-severity non-security single-file patch with PASSED verification skips critic."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Fix typo in comment",
        description="Typo in docstring",
        category="documentation",
        severity=Severity.LOW,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/utils.py", start_line=1, end_line=2)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="Typo",
        objective="Fix typo",
        files_expected_to_change=["app/utils.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/utils.py", description="Fix", rationale="Fix")],
        validation_plan=["pytest"],
    )

    proposal = PatchProposal(
        finding_id=finding.id,
        plan_id=plan.id,
        unified_diff="--- a/app/utils.py\n+++ b/app/utils.py\n@@ -1,1 +1,1 @@\n-# typoo\n+# typo\n",
        files_modified=["app/utils.py"],
        explanation="Fix comment typo",
        expected_behavior_change="None",
    )

    verif = PatchVerificationResult(
        patch_id=proposal.id,
        finding_id=finding.id,
        status=VerificationStatus.PASSED,
        syntax_valid=True,
        security_clean=True,
        contract_aligned=True,
        target_finding_resolved=True,
        explanation="Clean pass",
    )

    escalate, reasons = should_escalate_to_critic(finding, plan, proposal, verif)
    assert not escalate
    assert len(reasons) == 0


def test_should_escalate_on_needs_review_verification():
    """Verify patches with NEEDS_REVIEW verification status are escalated to critic."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Minor logic bug",
        description="Division by zero potential",
        category="bug",
        severity=Severity.MEDIUM,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/calc.py", start_line=1, end_line=2)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="Missing check",
        objective="Fix",
        files_expected_to_change=["app/calc.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/calc.py", description="Fix", rationale="Fix")],
        validation_plan=["pytest"],
    )

    proposal = PatchProposal(
        finding_id=finding.id,
        plan_id=plan.id,
        unified_diff="--- a/app/calc.py\n+++ b/app/calc.py\n@@ -1,1 +1,1 @@\n-a\n+b\n",
        files_modified=["app/calc.py"],
        explanation="Fix",
        expected_behavior_change="Fix",
    )

    verif = PatchVerificationResult(
        patch_id=proposal.id,
        finding_id=finding.id,
        status=VerificationStatus.NEEDS_REVIEW,
        syntax_valid=True,
        security_clean=True,
        contract_aligned=True,
        target_finding_resolved=True,
        explanation="Minor warning",
    )

    escalate, reasons = should_escalate_to_critic(finding, plan, proposal, verif)
    assert escalate
    assert any("NEEDS_REVIEW" in r for r in reasons)


# =========================================================================
# 2. PatchCriticAgent Evaluation Tests
# =========================================================================

@pytest.mark.asyncio
async def test_patch_critic_agent_approve_verdict():
    """Verify PatchCriticAgent parses APPROVE response with telemetry."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="SQL Injection",
        description="SQL injection in accounts query",
        severity=Severity.HIGH,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/db/query.py", start_line=1, end_line=2)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="String formatting in query",
        objective="Use parameters",
        files_expected_to_change=["app/db/query.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/db/query.py", description="Fix", rationale="Fix")],
        validation_plan=["pytest"],
    )

    proposal = PatchProposal(
        finding_id=finding.id,
        plan_id=plan.id,
        unified_diff="--- a/app/db/query.py\n+++ b/app/db/query.py\n@@ -1,1 +1,1 @@\n-f\n+?\n",
        files_modified=["app/db/query.py"],
        explanation="Parameterized query",
        expected_behavior_change="Safe query execution",
    )

    verif = PatchVerificationResult(
        patch_id=proposal.id,
        finding_id=finding.id,
        status=VerificationStatus.PASSED,
        syntax_valid=True,
        security_clean=True,
        contract_aligned=True,
        target_finding_resolved=True,
        explanation="Clean pass",
    )

    context_bundle = ContextBundle(
        scan_id="scan-123",
        query="Critic context",
        analysis_intent="critic",
        relevant_chunks=[],
    )

    mock_critic_json = """{
        "verdict": "APPROVE",
        "critic_score": 0.98,
        "concerns": [],
        "required_revisions": null,
        "evidence_notes": "Diff precisely replaces string formatting with parameterized query placeholders without touching external contracts."
    }"""

    mock_resp = LLMResponse(
        content=mock_critic_json,
        model="nvidia/nemotron-3-ultra-550b-a55b",
        provider=LLMProvider.NVIDIA,
        metadata=ModelExecutionMetadata(
            model_name="nemotron-3-ultra",
            provider="nvidia",
            execution_time_ms=50.0,
        ),
    )

    with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_resp

        critic = PatchCriticAgent()
        report = await critic.evaluate_patch(
            finding=finding,
            fix_plan=plan,
            proposal=proposal,
            verification_result=verif,
            context_bundle=context_bundle,
            escalation_reasons=["Security finding."],
        )

        assert isinstance(report, PatchCriticReport)
        assert report.verdict == CriticVerdict.APPROVE
        assert report.critic_score == 0.98
        assert len(report.concerns) == 0


# =========================================================================
# 3. Single-Revision Hard Cap Workflow Tests
# =========================================================================

@pytest.mark.asyncio
async def test_patch_workflow_single_revision_cap():
    """Verify workflow executes at most ONE automatic revision when critic requests REVISE and stops."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Authentication Token Bug",
        description="Auth token missing expiry",
        category="security",
        severity=Severity.HIGH,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/auth.py", start_line=1, end_line=5)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="No token expiry",
        objective="Add expiry",
        files_expected_to_change=["app/auth.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/auth.py", description="Fix", rationale="Fix")],
        validation_plan=["pytest"],
    )

    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash="abcdef",
        total_files=1,
        total_size_bytes=100,
        languages={"python": 1},
        frameworks=[],
        files=[FileEntry(path="app/auth.py", language="python", size_bytes=100, lines_count=10, symbols=[])],
    )
    evidence_store = EvidenceStore(manifest=manifest)
    context_engine = ContextEngine(evidence_store=evidence_store)

    # First critic call returns REVISE; second critic call returns APPROVE
    first_critic_report = PatchCriticReport(
        patch_id=uuid4(),
        finding_id=finding.id,
        verdict=CriticVerdict.REVISE,
        critic_score=0.7,
        concerns=["Token expiry added but missing UTC timezone enforcement"],
        required_revisions="Use datetime.now(timezone.utc) for expiry timestamp",
        evidence_notes="Initial patch incomplete.",
    )

    second_critic_report = PatchCriticReport(
        patch_id=uuid4(),
        finding_id=finding.id,
        verdict=CriticVerdict.APPROVE,
        critic_score=0.95,
        concerns=[],
        evidence_notes="Revised patch satisfies timezone requirement.",
    )

    mock_critic_agent = AsyncMock()
    mock_critic_agent.evaluate_patch.side_effect = [first_critic_report, second_critic_report]

    proposal = PatchProposal(
        finding_id=finding.id,
        plan_id=plan.id,
        unified_diff="--- a/app/auth.py\n+++ b/app/auth.py\n@@ -1,1 +1,1 @@\n-a\n+b\n",
        files_modified=["app/auth.py"],
        explanation="Token fix",
        expected_behavior_change="Expiry added",
    )

    mock_patch_service = AsyncMock()
    mock_patch_service.generate_patch_proposal.return_value = proposal

    verif_res = PatchVerificationResult(
        patch_id=proposal.id,
        finding_id=finding.id,
        status=VerificationStatus.PASSED,
        syntax_valid=True,
        security_clean=True,
        contract_aligned=True,
        target_finding_resolved=True,
        explanation="Passed",
    )

    mock_verif_service = AsyncMock()
    mock_verif_service.verify_patch.return_value = verif_res

    coordinator = PatchWorkflowCoordinator(
        patch_service=mock_patch_service,
        verification_service=mock_verif_service,
        critic_agent=mock_critic_agent,
    )

    result = await coordinator.execute_patch_workflow(
        finding=finding,
        fix_plan=plan,
        context_engine=context_engine,
        original_repo_dir="fake_dir",
        manifest=manifest,
    )

    assert isinstance(result, PatchWorkflowResult)
    assert result.critic_escalated
    assert result.revision_count == 1  # Exactly 1 revision loop
    assert result.final_verdict == "APPROVED"
    assert mock_critic_agent.evaluate_patch.call_count == 2
