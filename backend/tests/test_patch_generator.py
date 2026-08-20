"""Tests for Phase 3C: Evidence-Constrained Safe Patch Generation."""

import os
import tempfile
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
from app.patching.agent import PatchGeneratorAgent
from app.patching.schemas import (
    PatchProposal,
    PatchValidationStatus,
)
from app.patching.service import PatchService
from app.patching.validator import parse_diff_files, validate_patch_proposal
from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


# =========================================================================
# 1. Diff Parser & Validation Tests
# =========================================================================

def test_parse_diff_files_extraction():
    """Verify parse_diff_files correctly extracts normalized file targets."""
    sample_diff = (
        "--- a/app/db/query.py\n"
        "+++ b/app/db/query.py\n"
        "@@ -8,2 +8,2 @@\n"
        "-    query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"\n"
        "+    query = \"SELECT * FROM accounts WHERE user_id = ?\"\n"
        "--- a/frontend/src/api.ts\n"
        "+++ b/frontend/src/api.ts\n"
        "@@ -1,2 +1,2 @@\n"
    )
    files = parse_diff_files(sample_diff)
    assert files == ["app/db/query.py", "frontend/src/api.ts"]


def test_validate_patch_proposal_valid_diff():
    """Verify a syntactically correct diff conforming to FixPlan passes validation."""
    finding_id = uuid4()
    plan = FixPlan(
        finding_id=finding_id,
        root_cause="SQL Injection",
        objective="Sanitize SQL query",
        files_expected_to_change=["app/db/query.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/db/query.py",
                description="Use parameterized query",
                rationale="Prevents injection",
            )
        ],
        validation_plan=["pytest tests/"],
    )

    valid_diff = (
        "--- a/app/db/query.py\n"
        "+++ b/app/db/query.py\n"
        "@@ -8,2 +8,2 @@\n"
        "-    query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"\n"
        "+    cursor.execute('SELECT * FROM accounts WHERE user_id = ?', (user_id,))\n"
    )

    proposal = PatchProposal(
        finding_id=finding_id,
        plan_id=plan.id,
        unified_diff=valid_diff,
        files_modified=["app/db/query.py"],
        explanation="Parameterized the SQL query to eliminate SQL injection.",
        expected_behavior_change="Safe query execution.",
    )

    report = validate_patch_proposal(
        proposal=proposal,
        fix_plan=plan,
        repo_files={"app/db/query.py"},
    )

    assert report.is_valid
    assert report.status == PatchValidationStatus.VALID
    assert report.hunks_count == 1
    assert report.parsed_files == ["app/db/query.py"]


def test_validate_patch_proposal_fabricated_path():
    """Verify patch modifying a non-existent file path is rejected."""
    plan = FixPlan(
        finding_id=uuid4(),
        root_cause="Bug",
        objective="Fix",
        files_expected_to_change=["app/real.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/real.py", description="Fix", rationale="Fix")],
        validation_plan=["pytest"],
    )

    fabricated_diff = (
        "--- a/app/nonexistent_fake.py\n"
        "+++ b/app/nonexistent_fake.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-old\n"
        "+new\n"
    )

    proposal = PatchProposal(
        finding_id=plan.finding_id,
        plan_id=plan.id,
        unified_diff=fabricated_diff,
        files_modified=["app/nonexistent_fake.py"],
        explanation="Fake change",
        expected_behavior_change="None",
    )

    report = validate_patch_proposal(
        proposal=proposal,
        fix_plan=plan,
        repo_files={"app/real.py"},
    )

    assert not report.is_valid
    assert report.status == PatchValidationStatus.REJECTED
    assert any("fabricated file" in r for r in report.rejection_reasons)


def test_validate_patch_proposal_unrelated_file_outside_plan():
    """Verify patch modifying a real repo file that was NOT approved in FixPlan is rejected."""
    plan = FixPlan(
        finding_id=uuid4(),
        root_cause="Bug",
        objective="Fix",
        files_expected_to_change=["app/main.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/main.py", description="Fix", rationale="Fix")],
        validation_plan=["pytest"],
    )

    unapproved_diff = (
        "--- a/app/unapproved_helper.py\n"
        "+++ b/app/unapproved_helper.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-old\n"
        "+new\n"
    )

    proposal = PatchProposal(
        finding_id=plan.finding_id,
        plan_id=plan.id,
        unified_diff=unapproved_diff,
        files_modified=["app/unapproved_helper.py"],
        explanation="Unapproved change",
        expected_behavior_change="None",
    )

    report = validate_patch_proposal(
        proposal=proposal,
        fix_plan=plan,
        repo_files={"app/main.py", "app/unapproved_helper.py"},
    )

    assert not report.is_valid
    assert report.status == PatchValidationStatus.REJECTED
    assert any("outside approved FixPlan" in r for r in report.rejection_reasons)


def test_validate_patch_proposal_malformed_diff():
    """Verify malformed diffs without valid headers or change lines are rejected."""
    plan = FixPlan(
        finding_id=uuid4(),
        root_cause="Bug",
        objective="Fix",
        files_expected_to_change=["app/main.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/main.py", description="Fix", rationale="Fix")],
        validation_plan=["pytest"],
    )

    malformed_diff = "Just raw code replacement without diff headers: def foo(): pass"

    proposal = PatchProposal(
        finding_id=plan.finding_id,
        plan_id=plan.id,
        unified_diff=malformed_diff,
        files_modified=["app/main.py"],
        explanation="Malformed",
        expected_behavior_change="None",
    )

    report = validate_patch_proposal(proposal=proposal, fix_plan=plan)

    assert not report.is_valid
    assert report.status == PatchValidationStatus.REJECTED
    assert any("Malformed unified diff" in r for r in report.rejection_reasons)


# =========================================================================
# 2. PatchGeneratorAgent & Service Integration Tests
# =========================================================================

@pytest.mark.asyncio
async def test_patch_generator_agent_execution():
    """Verify PatchGeneratorAgent dispatches to TaskPolicy.PATCH_GENERATION and parses PatchProposal."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="SQL Injection Vulnerability",
        description="SQL injection in query.py",
        severity=Severity.HIGH,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/db/query.py", start_line=8, end_line=9)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="String formatting in SQL query",
        objective="Parameterize SQL query",
        files_expected_to_change=["app/db/query.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/db/query.py",
                description="Change cursor.execute to parameterized query",
                rationale="Eliminates vulnerability",
            )
        ],
        validation_plan=["pytest tests/"],
    )

    context_bundle = ContextBundle(
        scan_id="scan-123",
        query="SQL injection query.py",
        analysis_intent="patch_generation",
        relevant_chunks=[],
    )

    source_files = {
        "app/db/query.py": (
            "import sqlite3\n\n"
            "def execute_user_query(user_id: str):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()\n"
        )
    }

    mock_patch_json = """{
        "unified_diff": "--- a/app/db/query.py\\n+++ b/app/db/query.py\\n@@ -6,2 +6,2 @@\\n-    query = f\\"SELECT * FROM accounts WHERE user_id = '{user_id}'\\"\\n-    cursor.execute(query)\\n+    query = \\"SELECT * FROM accounts WHERE user_id = ?\\"\\n+    cursor.execute(query, (user_id,))",
        "explanation": "Replaced f-string SQL query interpolation with parameterized query placeholder (?) and tuple binding.",
        "expected_behavior_change": "SQL query parameters are safely escaped by the database driver.",
        "generated_tests_or_test_plan": ["pytest tests/test_query.py"]
    }"""

    mock_resp = LLMResponse(
        content=mock_patch_json,
        model="Qwen/Qwen3-Coder-Next",
        provider=LLMProvider.HUGGINGFACE,
        metadata=ModelExecutionMetadata(model_name="Qwen/Qwen3-Coder-Next", provider="huggingface", execution_time_ms=30.0),
    )

    with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_resp

        agent = PatchGeneratorAgent()
        proposal = await agent.generate_patch(
            finding=finding,
            fix_plan=plan,
            context_bundle=context_bundle,
            source_files=source_files,
        )

        assert isinstance(proposal, PatchProposal)
        assert proposal.finding_id == finding.id
        assert proposal.plan_id == plan.id
        assert "app/db/query.py" in proposal.files_modified
        assert proposal.validation_report is not None
        assert proposal.validation_report.is_valid
        assert proposal.validation_report.status == PatchValidationStatus.VALID


@pytest.mark.asyncio
async def test_patch_service_read_only_isolation():
    """Verify PatchService reads source files without mutating the cloned repository."""
    finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        title="Logic Bug",
        description="Division by zero",
        severity=Severity.MEDIUM,
        verification_verdict=VerificationVerdict.CONFIRMED,
        evidences=[Evidence(file_path="app/calc.py", start_line=2, end_line=3)],
    )

    plan = FixPlan(
        finding_id=finding.id,
        root_cause="Missing zero check",
        objective="Add zero check",
        files_expected_to_change=["app/calc.py"],
        ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/calc.py", description="Add check", rationale="Fix")],
        validation_plan=["pytest"],
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        calc_path = os.path.join(tmpdir, "app", "calc.py")
        os.makedirs(os.path.dirname(calc_path), exist_ok=True)
        original_content = "def divide(a, b):\n    return a / b\n"
        with open(calc_path, "w", encoding="utf-8") as f:
            f.write(original_content)

        manifest = RepositoryManifest(
            repository_url="https://github.com/org/repo.git",
            commit_hash="abcdef",
            total_files=1,
            total_size_bytes=len(original_content),
            languages={"python": 1},
            frameworks=[],
            files=[FileEntry(path="app/calc.py", language="python", size_bytes=len(original_content), lines_count=2, symbols=[])],
        )
        evidence_store = EvidenceStore(manifest=manifest)
        context_engine = ContextEngine(evidence_store=evidence_store)

        mock_patch_json = """{
            "unified_diff": "--- a/app/calc.py\\n+++ b/app/calc.py\\n@@ -1,2 +1,4 @@\\n def divide(a, b):\\n+    if b == 0:\\n+        return 0.0\\n     return a / b",
            "explanation": "Added zero divisor check.",
            "expected_behavior_change": "Returns 0.0 when b is 0.",
            "generated_tests_or_test_plan": ["pytest tests/test_calc.py"]
        }"""

        mock_resp = LLMResponse(
            content=mock_patch_json,
            model="mock",
            provider=LLMProvider.HUGGINGFACE,
            metadata=ModelExecutionMetadata(model_name="mock", provider="huggingface", execution_time_ms=10.0),
        )

        with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = mock_resp

            service = PatchService()
            proposal = await service.generate_patch_proposal(
                finding=finding,
                fix_plan=plan,
                context_engine=context_engine,
                repo_dir=tmpdir,
                manifest=manifest,
            )

            assert proposal.validation_report.is_valid

            # Verify original file content was NOT modified
            with open(calc_path, "r", encoding="utf-8") as f:
                current_disk_content = f.read()
            assert current_disk_content == original_content
