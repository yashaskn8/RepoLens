"""Tests for Phase 3D & 3.5D: Deterministic Patch Safety & Verification Service."""

import os
import tempfile
from uuid import uuid4
import pytest

from app.analysis.base import BaseScannerAdapter
from app.ingestion.manifest import build_manifest
from app.patching.schemas import (
    CheckStatus,
    PatchProposal,
    PatchVerificationResult,
    VerificationStatus,
)
from app.patching.verification import PatchVerificationService
from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.static_finding import ScannerResult, StaticFinding, ToolStatus


class MockCompletedScannerAdapter(BaseScannerAdapter):
    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def tool_path(self) -> str:
        return "semgrep"

    @property
    def is_enabled(self) -> bool:
        return True

    def is_available(self) -> bool:
        return True

    def _build_command(self, repo_dir: str):
        return ["semgrep"]

    def parse_output(self, stdout: str, stderr: str, returncode: int):
        return []

    async def scan(self, repo_dir: str) -> ScannerResult:
        return ScannerResult(tool="semgrep", status=ToolStatus.COMPLETED, findings=[])


class MockFlaggingScannerAdapter(BaseScannerAdapter):
    def __init__(self, findings=None):
        self._findings = findings or []

    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def tool_path(self) -> str:
        return "semgrep"

    @property
    def is_enabled(self) -> bool:
        return True

    def is_available(self) -> bool:
        return True

    def _build_command(self, repo_dir: str):
        return ["semgrep"]

    def parse_output(self, stdout: str, stderr: str, returncode: int):
        return self._findings

    async def scan(self, repo_dir: str) -> ScannerResult:
        return ScannerResult(tool="semgrep", status=ToolStatus.COMPLETED, findings=self._findings)


class MockUnavailableScannerAdapter(BaseScannerAdapter):
    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def tool_path(self) -> str:
        return "semgrep"

    @property
    def is_enabled(self) -> bool:
        return False

    def is_available(self) -> bool:
        return False

    def _build_command(self, repo_dir: str):
        return ["semgrep"]

    def parse_output(self, stdout: str, stderr: str, returncode: int):
        return []

    async def scan(self, repo_dir: str) -> ScannerResult:
        return ScannerResult(tool="semgrep", status=ToolStatus.UNAVAILABLE, findings=[])


class MockDynamicScannerAdapter(BaseScannerAdapter):
    def __init__(self, pre_findings=None, post_findings=None):
        self.pre_findings = pre_findings or []
        self.post_findings = post_findings or []
        self._calls = 0

    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def tool_path(self) -> str:
        return "semgrep"

    @property
    def is_enabled(self) -> bool:
        return True

    def is_available(self) -> bool:
        return True

    def _build_command(self, repo_dir: str):
        return ["semgrep"]

    def parse_output(self, stdout: str, stderr: str, returncode: int):
        return []

    async def scan(self, repo_dir: str) -> ScannerResult:
        self._calls += 1
        # Call 1 is post-patch scan on temp_dir, Call 2 is pre-patch baseline scan on original_repo_dir
        if self._calls == 1:
            return ScannerResult(tool="semgrep", status=ToolStatus.COMPLETED, findings=self.post_findings)
        return ScannerResult(tool="semgrep", status=ToolStatus.COMPLETED, findings=self.pre_findings)




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
            rule_id="semgrep.py-sql-injection",
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

        service = PatchVerificationService(scanner_adapters=[MockCompletedScannerAdapter()])
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

        service = PatchVerificationService(scanner_adapters=[MockCompletedScannerAdapter()])
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
            "@@ -1,3 +1,4 @@\n"
            " from fastapi import FastAPI\n"
            "+def broken_syntax( { [\n"
            " \n"
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

        service = PatchVerificationService(scanner_adapters=[MockCompletedScannerAdapter()])
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
            "@@ -1,3 +1,4 @@\n"
            " from fastapi import FastAPI\n"
            "+# Unauthorized edit\n"
            " \n"
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

        service = PatchVerificationService(scanner_adapters=[MockCompletedScannerAdapter()])
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        assert result.status == VerificationStatus.FAILED
        assert "check_5_scope_confinement" in result.checks_failed


# =========================================================================
# Adversarial Tests for Phase 3.5D
# =========================================================================


@pytest.mark.asyncio
async def test_adversarial_fake_clean_patch_cannot_obtain_12_of_12_when_scanners_unavailable():
    """Verify that a patch cannot obtain 12/12 PASSED when static scanners are UNAVAILABLE."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _setup_mock_repo(tmpdir)
        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="SQL Injection",
            description="SQL",
            severity=Severity.HIGH,
            rule_id="semgrep.py-sql",
            evidences=[Evidence(file_path="app/db/query.py", start_line=1, end_line=2, code_snippet="query = f'...'")],
        )

        plan = FixPlan(
            finding_id=finding.id,
            root_cause="SQL",
            objective="Fix",
            files_expected_to_change=["app/db/query.py"],
            ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/db/query.py", description="Fix", rationale="Fix")],
            validation_plan=["pytest"],
        )

        diff = (
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
            unified_diff=diff,
            files_modified=["app/db/query.py"],
            explanation="Fix query",
            expected_behavior_change="Safe binding",
        )

        # Scanners are UNAVAILABLE
        service = PatchVerificationService(scanner_adapters=[MockUnavailableScannerAdapter()])
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        # Must NOT be PASSED (should be NEEDS_REVIEW due to UNAVAILABLE scanners)
        assert result.status == VerificationStatus.NEEDS_REVIEW
        assert "check_10_scanners_clean" in result.checks_failed
        c10 = next(c for c in result.checks if c.check_name == "check_10_scanners_clean")
        assert c10.status == CheckStatus.UNAVAILABLE
        assert not c10.passed



@pytest.mark.asyncio
async def test_adversarial_patch_introducing_route_mismatch_fails_check_7():
    """Verify that a patch mutating route methods breaks contract check 7."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _setup_mock_repo(tmpdir)
        # Add frontend call matching GET /api/v1/health
        fe_file = os.path.join(tmpdir, "app", "frontend.tsx")
        with open(fe_file, "w", encoding="utf-8") as f:
            f.write(
                "import React from 'react';\n\n"
                "export const HealthChecker = () => {\n"
                "    fetch('/api/v1/health');\n"
                "    return <div>Status</div>;\n"
                "};\n"
            )

        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Refactor Health",
            description="Refactor",
            severity=Severity.LOW,
            category="route_mismatch",
            evidences=[Evidence(file_path="app/main.py", start_line=1, end_line=2)],
        )


        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Refactor",
            objective="Change health to POST",
            files_expected_to_change=["app/main.py"],
            ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/main.py", description="Change method", rationale="Refactor")],
            validation_plan=["pytest"],
        )

        # Diff changing @app.get to @app.post, creating a method mismatch against frontend
        diff = (
            "--- a/app/main.py\n"
            "+++ b/app/main.py\n"
            "@@ -4,2 +4,2 @@\n"
            "-@app.get('/api/v1/health')\n"
            "+@app.post('/api/v1/health')\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=diff,
            files_modified=["app/main.py"],
            explanation="Changed method to POST",
            expected_behavior_change="POST required",
        )

        service = PatchVerificationService(scanner_adapters=[MockCompletedScannerAdapter()])
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        assert result.status == VerificationStatus.FAILED
        assert "check_7_route_contracts" in result.checks_failed
        assert not result.contract_aligned


@pytest.mark.asyncio
async def test_adversarial_patch_with_unresolved_scanner_finding_fails_check_9():
    """Verify that if deterministic scanner still flags rule on patched code, check 9 fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _setup_mock_repo(tmpdir)
        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Insecure Query",
            description="Query",
            severity=Severity.HIGH,
            rule_id="semgrep.py-sql",
            evidences=[Evidence(file_path="app/db/query.py", start_line=1, end_line=2)],
        )

        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Query",
            objective="Fix",
            files_expected_to_change=["app/db/query.py"],
            ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/db/query.py", description="Fix", rationale="Fix")],
            validation_plan=["pytest"],
        )

        diff = (
            "--- a/app/db/query.py\n"
            "+++ b/app/db/query.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+# Ineffective fix\n"
            " import sqlite3\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=diff,
            files_modified=["app/db/query.py"],
            explanation="Comment added",
            expected_behavior_change="None",
        )

        still_failing = StaticFinding(
            tool="semgrep",
            rule_id="semgrep.py-sql",
            title="SQL Injection",
            description="Still present",
            severity=Severity.HIGH,
            evidence=Evidence(file_path="app/db/query.py", start_line=6, end_line=7),
        )

        service = PatchVerificationService(scanner_adapters=[MockFlaggingScannerAdapter(findings=[still_failing])])
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        assert "check_9_finding_remediation" in result.checks_failed
        assert not result.target_finding_resolved


@pytest.mark.asyncio
async def test_adversarial_patch_introducing_new_high_severity_scanner_finding_fails_check_12():
    """Verify that a patch introducing a new HIGH/CRITICAL static scanner finding fails check 12."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _setup_mock_repo(tmpdir)
        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Clean Fix",
            description="Fix",
            severity=Severity.LOW,
            rule_id="semgrep.clean-rule",
            evidences=[Evidence(file_path="app/db/query.py", start_line=1, end_line=2)],
        )

        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Fix",
            objective="Fix",
            files_expected_to_change=["app/db/query.py"],
            ordered_changes=[OrderedChangeStep(step_number=1, target_file="app/db/query.py", description="Fix", rationale="Fix")],
            validation_plan=["pytest"],
        )

        diff = (
            "--- a/app/db/query.py\n"
            "+++ b/app/db/query.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+# Add something\n"
            " import sqlite3\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=diff,
            files_modified=["app/db/query.py"],
            explanation="Edit",
            expected_behavior_change="None",
        )

        new_crit_finding = StaticFinding(
            tool="semgrep",
            rule_id="semgrep.dangerous-exec",
            title="Remote Code Execution",
            description="Dangerous exec introduced",
            severity=Severity.CRITICAL,
            evidence=Evidence(file_path="app/db/query.py", start_line=1, end_line=2),
        )

        service = PatchVerificationService(
            scanner_adapters=[MockDynamicScannerAdapter(pre_findings=[], post_findings=[new_crit_finding])]
        )

        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        assert result.status == VerificationStatus.FAILED
        assert "check_12_no_new_critical_findings" in result.checks_failed
