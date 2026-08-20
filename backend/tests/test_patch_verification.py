"""Tests for Phase 3D: Deterministic Patch Safety & Verification Service."""

import os
import tempfile
from uuid import uuid4
import pytest

from app.ingestion.manifest import build_manifest
from app.patching.schemas import (
    PatchProposal,
    PatchVerificationResult,
    VerificationStatus,
)
from app.patching.verification import PatchVerificationService
from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


def _setup_mock_repo(tmpdir: str):
    """Create a minimal real repository structure on disk for isolated testing."""
    app_dir = os.path.join(tmpdir, "app")
    db_dir = os.path.join(app_dir, "db")
    os.makedirs(db_dir, exist_ok=True)

    query_file = os.path.join(db_dir, "query.py")
    with open(query_file, "w", encoding="utf-8") as f:
        f.write(
            "import sqlite3\n\n"
            "def execute_user_query(user_id: str):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()\n"
        )

    main_file = os.path.join(app_dir, "main.py")
    with open(main_file, "w", encoding="utf-8") as f:
        f.write(
            "from fastapi import FastAPI\n\n"
            "app = FastAPI()\n\n"
            "@app.get('/api/v1/health')\n"
            "def health(): return {'status': 'ok'}\n"
        )

    return query_file, main_file


@pytest.mark.asyncio
async def test_patch_verification_full_pass_on_isolated_sandbox():
    """Verify that a clean, valid patch passes all 12 deterministic checks while leaving original repo untouched."""
    with tempfile.TemporaryDirectory() as tmpdir:
        query_file, _ = _setup_mock_repo(tmpdir)
        with open(query_file, "r", encoding="utf-8") as f:
            original_query_content = f.read()

        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="SQL Injection in Database Query Utility",
            description="Formatted string query",
            severity=Severity.HIGH,
            verification_verdict=VerificationVerdict.CONFIRMED,
            evidences=[
                Evidence(
                    file_path="app/db/query.py",
                    start_line=6,
                    end_line=7,
                    code_snippet="query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"",
                )
            ],
        )

        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Formatted string in SQL query",
            objective="Use parameterized query",
            files_expected_to_change=["app/db/query.py"],
            ordered_changes=[
                OrderedChangeStep(
                    step_number=1,
                    target_file="app/db/query.py",
                    description="Replace f-string with parameterized query",
                    rationale="Remediates SQL injection",
                )
            ],
            validation_plan=["pytest tests/"],
        )

        valid_diff = (
            "--- a/app/db/query.py\n"
            "+++ b/app/db/query.py\n"
            "@@ -6,2 +6,2 @@\n"
            "-    query = f\"SELECT * FROM accounts WHERE user_id = '{user_id}'\"\n"
            "-    cursor.execute(query)\n"
            "+    query = \"SELECT * FROM accounts WHERE user_id = ?\"\n"
            "+    cursor.execute(query, (user_id,))\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=valid_diff,
            files_modified=["app/db/query.py"],
            explanation="Replaced formatted SQL string with parameterized query.",
            expected_behavior_change="Safe query parameter binding.",
        )

        service = PatchVerificationService()
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        assert isinstance(result, PatchVerificationResult)
        assert result.status == VerificationStatus.PASSED
        assert result.syntax_valid
        assert result.security_clean
        assert result.contract_aligned
        assert result.target_finding_resolved
        assert len(result.checks_passed) == 12
        assert len(result.checks_failed) == 0

        # Verify original file was strictly NOT modified on disk
        with open(query_file, "r", encoding="utf-8") as f:
            disk_content = f.read()
        assert disk_content == original_query_content


@pytest.mark.asyncio
async def test_patch_verification_rejects_introduced_secrets():
    """Verify that a patch introducing hardcoded API keys or AWS tokens is rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _setup_mock_repo(tmpdir)
        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Bug Fix",
            description="Bug",
            severity=Severity.LOW,
            verification_verdict=VerificationVerdict.CONFIRMED,
            evidences=[Evidence(file_path="app/main.py", start_line=1, end_line=2)],
        )

        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Bug",
            objective="Fix",
            files_expected_to_change=["app/main.py"],
            ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/main.py", description="Fix", rationale="Fix")],
            validation_plan=["pytest"],
        )

        # Malicious diff introducing secret
        leaking_diff = (
            "--- a/app/main.py\n"
            "+++ b/app/main.py\n"
            "@@ -1,2 +1,3 @@\n"
            " from fastapi import FastAPI\n"
            "+SECRET_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"
            " app = FastAPI()\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=leaking_diff,
            files_modified=["app/main.py"],
            explanation="Fix with hardcoded secret key.",
            expected_behavior_change="Leaked key",
        )

        service = PatchVerificationService()
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        assert result.status == VerificationStatus.FAILED
        assert not result.security_clean
        assert "check_11_no_secrets_introduced" in result.checks_failed


@pytest.mark.asyncio
async def test_patch_verification_rejects_broken_syntax():
    """Verify that a patch creating unparseable Python syntax is rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _setup_mock_repo(tmpdir)
        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Bug",
            description="Bug",
            severity=Severity.LOW,
            verification_verdict=VerificationVerdict.CONFIRMED,
            evidences=[Evidence(file_path="app/main.py", start_line=1, end_line=2)],
        )

        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Bug",
            objective="Fix",
            files_expected_to_change=["app/main.py"],
            ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/main.py", description="Fix", rationale="Fix")],
            validation_plan=["pytest"],
        )

        # Broken syntax diff
        broken_diff = (
            "--- a/app/main.py\n"
            "+++ b/app/main.py\n"
            "@@ -1,2 +1,3 @@\n"
            " from fastapi import FastAPI\n"
            "+def broken_syntax( { [\n"
            " app = FastAPI()\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=broken_diff,
            files_modified=["app/main.py"],
            explanation="Broken syntax",
            expected_behavior_change="Crash",
        )

        service = PatchVerificationService()
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        # Broken syntax fails verification
        assert result.status == VerificationStatus.FAILED
        assert not result.syntax_valid
        assert "check_6_tree_sitter_parse" in result.checks_failed


@pytest.mark.asyncio
async def test_patch_verification_rejects_scope_overreach():
    """Verify that a patch modifying files outside the approved FixPlan fails scope confinement."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _setup_mock_repo(tmpdir)
        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Local Bug",
            description="Bug in query.py",
            severity=Severity.LOW,
            verification_verdict=VerificationVerdict.CONFIRMED,
            evidences=[Evidence(file_path="app/db/query.py", start_line=1, end_line=2)],
        )

        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Bug in query",
            objective="Fix query only",
            files_expected_to_change=["app/db/query.py"],
            ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/db/query.py", description="Fix", rationale="Fix")],
            validation_plan=["pytest"],
        )

        # Diff modifying main.py instead of query.py
        unauthorized_diff = (
            "--- a/app/main.py\n"
            "+++ b/app/main.py\n"
            "@@ -1,2 +1,3 @@\n"
            " from fastapi import FastAPI\n"
            "+# Unauthorized edit\n"
            " app = FastAPI()\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=unauthorized_diff,
            files_modified=["app/main.py"],
            explanation="Unapproved file edit",
            expected_behavior_change="None",
        )

        service = PatchVerificationService()
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        assert result.status == VerificationStatus.FAILED
        assert "check_5_scope_confinement" in result.checks_failed
