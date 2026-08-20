"""Tests for Phase 3.5E: Strict Unified-Diff Application & Patch Safety."""

import os
import tempfile
from uuid import uuid4
import pytest

from app.ingestion.manifest import build_manifest
from app.patching.applier import (
    PatchApplyError,
    apply_unified_diff_to_directory,
    parse_unified_diff,
)
from app.patching.schemas import (
    CheckStatus,
    PatchProposal,
    PatchVerificationResult,
    VerificationStatus,
)
from app.patching.verification import PatchVerificationService
from app.planning.schemas import FixPlan, OrderedChangeStep
from app.schemas.enums import Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.static_finding import ScannerResult, ToolStatus
from app.analysis.base import BaseScannerAdapter


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


def _create_sample_file(directory: str, filename: str, content: str) -> str:
    filepath = os.path.join(directory, filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


# =========================================================================
# Unit Tests for Strict Unified Diff Applier
# =========================================================================


def test_strict_applier_valid_multi_hunk_patch():
    """Verify that a valid multi-hunk patch applies cleanly and modifies the exact lines."""
    with tempfile.TemporaryDirectory() as tmpdir:
        content = (
            "import os\n"
            "import sys\n"
            "\n"
            "def foo():\n"
            "    old_foo = 1\n"
            "    return old_foo\n"
            "\n"
            "def bar():\n"
            "    old_bar = 2\n"
            "    return old_bar\n"
        )
        _create_sample_file(tmpdir, "app/main.py", content)

        multi_hunk_diff = (
            "--- a/app/main.py\n"
            "+++ b/app/main.py\n"
            "@@ -4,3 +4,3 @@\n"
            " def foo():\n"
            "-    old_foo = 1\n"
            "+    new_foo = 100\n"
            "     return old_foo\n"
            "@@ -8,3 +8,3 @@\n"
            " def bar():\n"
            "-    old_bar = 2\n"
            "+    new_bar = 200\n"
            "     return old_bar\n"
        )

        res = apply_unified_diff_to_directory(multi_hunk_diff, tmpdir)
        assert "app/main.py" in res
        patched_lines = res["app/main.py"].splitlines()
        assert "    new_foo = 100" in patched_lines
        assert "    new_bar = 200" in patched_lines
        assert "    old_foo = 1" not in patched_lines
        assert "    old_bar = 2" not in patched_lines



def test_strict_applier_rejects_stale_context():
    """Verify that a hunk with stale context lines raises PatchApplyError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        content = (
            "line 1\n"
            "line 2 actual context\n"
            "line 3 to delete\n"
            "line 4\n"
        )
        _create_sample_file(tmpdir, "app/main.py", content)

        stale_diff = (
            "--- a/app/main.py\n"
            "+++ b/app/main.py\n"
            "@@ -1,4 +1,4 @@\n"
            " line 1\n"
            "-line 2 STALE DIFFERENT CONTEXT\n"
            "+line 2 new context\n"
            " line 3 to delete\n"
            " line 4\n"
        )

        with pytest.raises(PatchApplyError) as excinfo:
            apply_unified_diff_to_directory(stale_diff, tmpdir)

        assert "Stale context line mismatch" in str(excinfo.value) or "Deletion line mismatch" in str(excinfo.value)
        assert excinfo.value.file_path == "app/main.py"


def test_strict_applier_rejects_incorrect_deleted_line():
    """Verify that a mismatch on a '-' deletion line raises PatchApplyError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        content = (
            "def authenticate():\n"
            "    token = get_token()\n"
            "    return token\n"
        )
        _create_sample_file(tmpdir, "app/auth.py", content)

        wrong_deletion_diff = (
            "--- a/app/auth.py\n"
            "+++ b/app/auth.py\n"
            "@@ -1,3 +1,3 @@\n"
            " def authenticate():\n"
            "-    token = WRONG_TOKEN_LINE_NOT_IN_SOURCE()\n"
            "+    token = get_secure_token()\n"
            "     return token\n"
        )

        with pytest.raises(PatchApplyError) as excinfo:
            apply_unified_diff_to_directory(wrong_deletion_diff, tmpdir)

        assert "Deletion line mismatch" in str(excinfo.value)
        assert excinfo.value.file_path == "app/auth.py"


def test_strict_applier_rejects_malformed_ranges():
    """Verify that internal count mismatches in hunk headers raise PatchApplyError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        content = "line 1\nline 2\nline 3\n"
        _create_sample_file(tmpdir, "app/file.py", content)

        # Header claims 5 lines in orig, but only 2 lines provided in hunk
        malformed_diff = (
            "--- a/app/file.py\n"
            "+++ b/app/file.py\n"
            "@@ -1,5 +1,2 @@\n"
            "-line 1\n"
            "+line 1 modified\n"
        )

        with pytest.raises(PatchApplyError) as excinfo:
            apply_unified_diff_to_directory(malformed_diff, tmpdir)

        assert "does not match actual hunk line counts" in str(excinfo.value)


def test_strict_applier_rejects_path_traversal():
    """Verify that any patch attempting relative or absolute directory traversal is rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        traversal_diff = (
            "--- a/../secret.txt\n"
            "+++ b/../secret.txt\n"
            "@@ -1,1 +1,1 @@\n"
            "-secret\n"
            "+hacked\n"
        )

        with pytest.raises(PatchApplyError) as excinfo:
            apply_unified_diff_to_directory(traversal_diff, tmpdir)

        assert "Path traversal detected" in str(excinfo.value)


def test_strict_applier_rejects_overlapping_hunks():
    """Verify that overlapping hunk ranges on the same file are detected and rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        content = (
            "line 1\nline 2\nline 3\nline 4\nline 5\n"
        )
        _create_sample_file(tmpdir, "app/main.py", content)

        # Hunk 1 covers lines 2-4, Hunk 2 covers lines 3-5 (overlap!)
        overlapping_diff = (
            "--- a/app/main.py\n"
            "+++ b/app/main.py\n"
            "@@ -2,3 +2,3 @@\n"
            " line 2\n"
            "-line 3\n"
            "+line 3 new\n"
            " line 4\n"
            "@@ -3,3 +3,3 @@\n"
            " line 3\n"
            "-line 4\n"
            "+line 4 new\n"
            " line 5\n"
        )

        with pytest.raises(PatchApplyError) as excinfo:
            apply_unified_diff_to_directory(overlapping_diff, tmpdir)

        assert "Overlapping hunks detected" in str(excinfo.value)


def test_strict_applier_creates_new_text_file():
    """Verify that a patch creating a new text file succeeds."""
    with tempfile.TemporaryDirectory() as tmpdir:
        new_file_diff = (
            "--- /dev/null\n"
            "+++ b/app/utils.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+def helper():\n"
            "+    return 42\n"
            "+\n"
        )

        res = apply_unified_diff_to_directory(new_file_diff, tmpdir)
        assert "app/utils.py" in res
        created_path = os.path.join(tmpdir, "app", "utils.py")
        assert os.path.exists(created_path)
        with open(created_path, "r", encoding="utf-8") as f:
            assert "def helper():" in f.read()


def test_strict_applier_rejects_binary_patches():
    """Verify that binary patch modifications are strictly rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        binary_diff = (
            "--- a/logo.png\n"
            "+++ b/logo.png\n"
            "GIT binary patch\n"
            "literal 12\n"
            "zcmd^&@#!*\n"
        )

        with pytest.raises(PatchApplyError) as excinfo:
            apply_unified_diff_to_directory(binary_diff, tmpdir)

        assert "Binary patches are strictly rejected" in str(excinfo.value) or "Binary file patch rejected" in str(excinfo.value)


# =========================================================================
# Integration Tests with PatchVerificationService and Original Immutability
# =========================================================================


@pytest.mark.asyncio
async def test_verification_fails_on_patch_apply_error_and_preserves_original_repo():
    """Verify that deterministic verification fails when PatchApplyError occurs, and original repo is unchanged."""
    with tempfile.TemporaryDirectory() as orig_dir:
        orig_file = _create_sample_file(
            orig_dir,
            "src/service.py",
            "def calculate(x):\n    return x * 2\n",
        )
        with open(orig_file, "r", encoding="utf-8") as f:
            original_content = f.read()

        manifest = build_manifest(orig_dir, "https://github.com/org/repo.git", "1234567890ab")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Logic Error",
            description="Calculation error",
            severity=Severity.HIGH,
            verification_verdict=VerificationVerdict.CONFIRMED,
            evidences=[Evidence(file_path="src/service.py", start_line=1, end_line=2)],
        )

        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Logic error",
            objective="Fix calculation",
            files_expected_to_change=["src/service.py"],
            ordered_changes=[OrderedChangeStep(step_number=1, target_file="src/service.py", description="Fix", rationale="Fix")],
            validation_plan=["pytest"],
        )

        # Corrupted deletion diff that will raise PatchApplyError
        corrupted_diff = (
            "--- a/src/service.py\n"
            "+++ b/src/service.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def calculate(x):\n"
            "-    return WRONG_CODE_NOT_IN_SOURCE\n"
            "+    return x * 4\n"
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff=corrupted_diff,
            files_modified=["src/service.py"],
            explanation="Corrupted patch",
            expected_behavior_change="Fix",
        )

        service = PatchVerificationService(scanner_adapters=[MockCompletedScannerAdapter()])
        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=orig_dir,
            manifest=manifest,
        )

        # Verification must fail cleanly
        assert isinstance(result, PatchVerificationResult)
        assert result.status == VerificationStatus.FAILED
        assert "check_6_tree_sitter_parse" in result.checks_failed

        # Original repo must remain strictly unchanged
        with open(orig_file, "r", encoding="utf-8") as f:
            assert f.read() == original_content
