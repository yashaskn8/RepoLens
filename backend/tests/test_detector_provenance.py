"""Unit tests for canonical detector provenance fields and verification dispatch."""

import os
import tempfile
import pytest
from uuid import uuid4

from app.analysis.base import BaseScannerAdapter
from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.ingestion.manifest import build_manifest
from app.patching.schemas import CheckStatus, PatchProposal
from app.patching.verification import PatchVerificationService
from app.planning.schemas import FixPlan
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


class MockCleanScannerAdapter(BaseScannerAdapter):
    def __init__(self, tool_name="semgrep"):
        self._tool_name = tool_name

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def tool_path(self) -> str:
        return self._tool_name

    @property
    def is_enabled(self) -> bool:
        return True

    def is_available(self) -> bool:
        return True

    def _build_command(self, repo_dir: str):
        return [self._tool_name]

    def parse_output(self, raw_json_str: str, repo_dir: str):
        return []

    async def scan(self, repo_dir: str) -> ScannerResult:
        return ScannerResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=[])


@pytest.mark.asyncio
async def test_detector_provenance_dispatches_cleanly_in_check_9():
    """Verify check_9 uses source_tool and detector_id to verify finding resolution."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file
        app_file = os.path.join(tmpdir, "main.py")
        with open(app_file, "w", encoding="utf-8") as f:
            f.write("# Safe file\n")

        manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "abcdef1234567890abcdef1234567890abcdef12")

        finding = Finding(
            id=uuid4(),
            scan_id=uuid4(),
            title="Insecure cookie flags",
            description="Missing httponly flag",
            severity=Severity.HIGH,
            source_tool="semgrep",
            detector_id="python.flask.security.insecure-cookie-flags",
            detector_kind="static_scanner",
            evidences=[Evidence(file_path="main.py", start_line=1, end_line=1, code_snippet="set_cookie()")],
        )

        from app.planning.schemas import OrderedChangeStep
        plan = FixPlan(
            finding_id=finding.id,
            root_cause="Flags missing",
            objective="Add flags",
            files_expected_to_change=["main.py"],
            ordered_changes=[
                OrderedChangeStep(
                    step_number=1,
                    target_file="main.py",
                    description="Add flags",
                    rationale="Security hardening",
                )
            ],
            validation_plan=["pytest tests/"],
        )

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=plan.id,
            unified_diff="--- a/main.py\n+++ b/main.py\n@@ -1,1 +1,1 @@\n-# Safe file\n+# Safe file with flags\n",
            files_modified=["main.py"],
            explanation="Added flags",
            expected_behavior_change="Safe cookies",
        )

        # Semgrep returns clean scan
        mock_semgrep = MockCleanScannerAdapter(tool_name="semgrep")
        service = PatchVerificationService(scanner_adapters=[mock_semgrep])

        result = await service.verify_patch(
            proposal=proposal,
            finding=finding,
            fix_plan=plan,
            original_repo_dir=tmpdir,
            manifest=manifest,
        )

        c9 = next(c for c in result.checks if c.check_name == "check_9_finding_remediation")
        assert c9.status == CheckStatus.PASSED
        assert "verified detector 'python.flask.security.insecure-cookie-flags' is resolved" in c9.details
