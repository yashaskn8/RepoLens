"""Comprehensive tests for deterministic static analysis scanner adapters (Phase 3.5F).

Each scanner (Semgrep, Trivy, OSV) is tested for:
  - no findings (accepted exit code, empty results)
  - findings present (accepted exit code, parseable output)
  - unavailable executable
  - timeout (subprocess.TimeoutExpired)
  - invalid JSON output
  - actual tool failure exit code (rejected exit code)

Also tests:
  - RepositoryIntelligenceService handling of one scanner failure
  - bounded stderr capture
"""

import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import pytest

from app.analysis.adapters import OSVScannerAdapter, SemgrepAdapter, TrivyAdapter
from app.analysis.base import ScannerOutputError, _bound_stderr
from app.analysis.schemas import ScannerResult, ToolStatus
from app.analysis.service import RepositoryIntelligenceService
from app.analysis.base import BaseScannerAdapter
from app.schemas.enums import Severity


# ---------------------------------------------------------------------------
#  Fixture data
# ---------------------------------------------------------------------------

SEMGREP_NO_FINDINGS = json.dumps({"results": [], "errors": []})

SEMGREP_WITH_FINDINGS = json.dumps({
    "results": [
        {
            "check_id": "python.jwt.security.unverified-jwt-decode.unverified-jwt-decode",
            "path": "src/auth/jwt.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 40},
            "extra": {
                "message": "jwt.decode without verify=False allows forged signatures.",
                "severity": "ERROR",
                "lines": "jwt.decode(token, verify=False)",
                "metadata": {
                    "category": "security",
                    "confidence": "HIGH",
                    "fix": "jwt.decode(token, key=SECRET, algorithms=['HS256'])",
                },
            },
        }
    ]
})

TRIVY_NO_FINDINGS = json.dumps({"Results": []})

TRIVY_WITH_FINDINGS = json.dumps({
    "Results": [
        {
            "Target": "package-lock.json",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-45857",
                    "PkgName": "axios",
                    "InstalledVersion": "0.21.1",
                    "FixedVersion": "1.6.0",
                    "Severity": "CRITICAL",
                    "Title": "Axios Cross-Site Request Forgery Vulnerability",
                    "Description": "Axios before 1.6.0 allows CSRF token bypass.",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-45857",
                }
            ],
        }
    ]
})

OSV_NO_FINDINGS = json.dumps({"results": []})

OSV_WITH_FINDINGS = json.dumps({
    "results": [
        {
            "source": {"path": "requirements.txt"},
            "packages": [
                {
                    "package": {"name": "urllib3", "version": "1.26.4", "ecosystem": "PyPI"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-q2x7-8rv6-6q7h",
                            "summary": "urllib3 Proxy-Authorization Header Injection",
                            "aliases": ["CVE-2023-43804"],
                            "database_specific": {"severity": "HIGH"},
                        }
                    ],
                }
            ],
        }
    ]
})

INVALID_JSON = "this is { not valid json ]]]"


# ---------------------------------------------------------------------------
#  Helper: mock _execute_command to simulate scanner subprocess
# ---------------------------------------------------------------------------

def _make_execute_mock(returncode: int, stdout: str, stderr: str = ""):
    """Create an async mock for _execute_command returning (returncode, stdout, stderr)."""

    async def _mock_execute(cmd, cwd, timeout_seconds=None):
        return returncode, stdout, stderr

    return _mock_execute


def _make_timeout_mock():
    """Create an async mock for _execute_command that raises subprocess.TimeoutExpired."""

    async def _mock_execute(cmd, cwd, timeout_seconds=None):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=60)

    return _mock_execute


# ===========================================================================
#  SEMGREP TESTS
# ===========================================================================

class TestSemgrepAdapter:

    @pytest.mark.asyncio
    async def test_no_findings(self):
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(0, SEMGREP_NO_FINDINGS)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_findings_present(self):
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(0, SEMGREP_WITH_FINDINGS)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.tool == "semgrep"
        assert f.rule_id == "python.jwt.security.unverified-jwt-decode.unverified-jwt-decode"
        assert f.severity == Severity.HIGH
        assert f.category == "security"

    @pytest.mark.asyncio
    async def test_findings_exit_code_1(self):
        """Semgrep with --error returns exit code 1 when findings exist — still COMPLETED."""
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(1, SEMGREP_WITH_FINDINGS)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_unavailable_executable(self):
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=False):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.UNAVAILABLE
        assert "not installed or not in PATH" in result.error_message
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_timeout(self):
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_timeout_mock()):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.TIMEOUT
        assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_invalid_json(self):
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(0, INVALID_JSON)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.INVALID_OUTPUT
        assert "Invalid JSON" in result.error_message

    @pytest.mark.asyncio
    async def test_failure_exit_code(self):
        """Exit code 2+ is a real error, not findings."""
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(2, "", stderr="semgrep: fatal config error")):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.FAILED
        assert "unexpected code 2" in result.error_message
        assert result.diagnostic_stderr is not None
        assert "fatal config error" in result.diagnostic_stderr


# ===========================================================================
#  TRIVY TESTS
# ===========================================================================

class TestTrivyAdapter:

    @pytest.mark.asyncio
    async def test_no_findings(self):
        adapter = TrivyAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(0, TRIVY_NO_FINDINGS)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_findings_present(self):
        adapter = TrivyAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(0, TRIVY_WITH_FINDINGS)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.tool == "trivy"
        assert f.rule_id == "CVE-2023-45857"
        assert f.severity == Severity.CRITICAL
        assert "Upgrade axios to version 1.6.0" in f.mitigation

    @pytest.mark.asyncio
    async def test_unavailable_executable(self):
        adapter = TrivyAdapter()
        with patch.object(adapter, "is_available", return_value=False):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.UNAVAILABLE
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_timeout(self):
        adapter = TrivyAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_timeout_mock()):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.TIMEOUT
        assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_invalid_json(self):
        adapter = TrivyAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(0, INVALID_JSON)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.INVALID_OUTPUT
        assert "Invalid JSON" in result.error_message

    @pytest.mark.asyncio
    async def test_failure_exit_code(self):
        """Trivy only accepts exit code 0. Any non-zero = FAILED."""
        adapter = TrivyAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(1, "", stderr="trivy: database download failed")):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.FAILED
        assert "unexpected code 1" in result.error_message
        assert result.diagnostic_stderr is not None
        assert "database download failed" in result.diagnostic_stderr


# ===========================================================================
#  OSV-SCANNER TESTS
# ===========================================================================

class TestOSVScannerAdapter:

    @pytest.mark.asyncio
    async def test_no_findings(self):
        adapter = OSVScannerAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(0, OSV_NO_FINDINGS)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_findings_present(self):
        adapter = OSVScannerAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(1, OSV_WITH_FINDINGS)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.COMPLETED
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.tool == "osv-scanner"
        assert f.rule_id == "GHSA-q2x7-8rv6-6q7h"
        assert f.severity == Severity.HIGH
        assert f.category == "dependency"

    @pytest.mark.asyncio
    async def test_unavailable_executable(self):
        adapter = OSVScannerAdapter()
        with patch.object(adapter, "is_available", return_value=False):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.UNAVAILABLE
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_timeout(self):
        adapter = OSVScannerAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_timeout_mock()):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.TIMEOUT
        assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_invalid_json(self):
        adapter = OSVScannerAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(0, INVALID_JSON)):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.INVALID_OUTPUT
        assert "Invalid JSON" in result.error_message

    @pytest.mark.asyncio
    async def test_failure_exit_code(self):
        """Exit code 128 is a fatal error for osv-scanner."""
        adapter = OSVScannerAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", _make_execute_mock(128, "", stderr="osv-scanner: fatal internal error")):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.FAILED
        assert "unexpected code 128" in result.error_message
        assert result.diagnostic_stderr is not None


# ===========================================================================
#  BOUNDED STDERR TESTS
# ===========================================================================

class TestBoundedStderr:

    def test_empty_stderr_returns_none(self):
        assert _bound_stderr("") is None
        assert _bound_stderr(None) is None
        assert _bound_stderr("   \n  ") is None

    def test_normal_stderr_preserved(self):
        err = "Warning: some deprecation notice"
        assert _bound_stderr(err) == err

    def test_long_stderr_truncated(self):
        err = "x" * 5000
        bounded = _bound_stderr(err)
        assert len(bounded) < 5000
        assert bounded.endswith("... [truncated]")

    @pytest.mark.asyncio
    async def test_stderr_captured_in_completed_result(self):
        """Stderr from successful scan is preserved in diagnostic_stderr."""
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command",
                          _make_execute_mock(0, SEMGREP_NO_FINDINGS, stderr="some diagnostics")):
            result = await adapter.scan("/tmp/repo")

        assert result.status == ToolStatus.COMPLETED
        assert result.diagnostic_stderr == "some diagnostics"


# ===========================================================================
#  INTELLIGENCE SERVICE: SCANNER FAILURE ISOLATION
# ===========================================================================

class TestIntelligenceServiceFailureIsolation:

    @pytest.mark.asyncio
    async def test_one_scanner_failure_does_not_hide_others(self):
        """If one scanner fails, others still produce results and failure is recorded."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory(prefix="intel_svc_fail_test_") as tmp_dir:
            with open(os.path.join(tmp_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write("def compute(x):\n    return x * 2\n")

            # Working scanner
            mock_semgrep = AsyncMock(spec=BaseScannerAdapter)
            mock_semgrep.tool_name = "semgrep"
            mock_semgrep.scan.return_value = ScannerResult(
                tool="semgrep",
                status=ToolStatus.COMPLETED,
                findings=[],
            )

            # Crashing scanner — unhandled exception
            mock_trivy = AsyncMock(spec=BaseScannerAdapter)
            mock_trivy.tool_name = "trivy"
            mock_trivy.scan.side_effect = RuntimeError("segfault simulation")

            # Failed scanner — proper FAILED result
            mock_osv = AsyncMock(spec=BaseScannerAdapter)
            mock_osv.tool_name = "osv-scanner"
            mock_osv.scan.return_value = ScannerResult(
                tool="osv-scanner",
                status=ToolStatus.FAILED,
                error_message="osv-scanner exited with unexpected code 128.",
            )

            service = RepositoryIntelligenceService(
                scanner_adapters=[mock_semgrep, mock_trivy, mock_osv]
            )
            evidence_store = await service.analyze_repository(
                repo_dir=tmp_dir,
                repository_url="https://github.com/org/test-repo",
                commit_hash="abc123",
                branch="main",
            )

            # Semgrep completed cleanly
            assert evidence_store.scanner_results["semgrep"].status == ToolStatus.COMPLETED

            # Trivy exception was converted to FAILED (not missing or crash)
            assert "trivy" in evidence_store.scanner_results
            assert evidence_store.scanner_results["trivy"].status == ToolStatus.FAILED
            assert "segfault simulation" in evidence_store.scanner_results["trivy"].error_message

            # OSV recorded as FAILED
            assert evidence_store.scanner_results["osv-scanner"].status == ToolStatus.FAILED

    @pytest.mark.asyncio
    async def test_failed_scanner_not_counted_as_clean(self):
        """A FAILED scanner must not contribute findings (= false clean)."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory(prefix="intel_svc_clean_test_") as tmp_dir:
            with open(os.path.join(tmp_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")

            mock_scanner = AsyncMock(spec=BaseScannerAdapter)
            mock_scanner.tool_name = "semgrep"
            mock_scanner.scan.return_value = ScannerResult(
                tool="semgrep",
                status=ToolStatus.FAILED,
                error_message="Process died.",
            )

            service = RepositoryIntelligenceService(scanner_adapters=[mock_scanner])
            evidence_store = await service.analyze_repository(
                repo_dir=tmp_dir,
                repository_url="https://github.com/org/test-repo",
                commit_hash="abc123",
            )

            # FAILED scanner should be recorded as FAILED, not COMPLETED
            assert evidence_store.scanner_results["semgrep"].status == ToolStatus.FAILED
            # No findings from FAILED scanner (EvidenceStore only indexes COMPLETED)
            assert len(evidence_store.all_findings) == 0


# ===========================================================================
#  SCANNER OUTPUT ERROR
# ===========================================================================

class TestScannerOutputError:

    def test_parse_output_raises_on_invalid_json_semgrep(self):
        adapter = SemgrepAdapter()
        with pytest.raises(ScannerOutputError, match="Invalid JSON"):
            adapter.parse_output(INVALID_JSON, "/tmp/repo")

    def test_parse_output_raises_on_invalid_json_trivy(self):
        adapter = TrivyAdapter()
        with pytest.raises(ScannerOutputError, match="Invalid JSON"):
            adapter.parse_output(INVALID_JSON, "/tmp/repo")

    def test_parse_output_raises_on_invalid_json_osv(self):
        adapter = OSVScannerAdapter()
        with pytest.raises(ScannerOutputError, match="Invalid JSON"):
            adapter.parse_output(INVALID_JSON, "/tmp/repo")

    def test_parse_output_raises_on_wrong_type_semgrep(self):
        """If root JSON is an array instead of object, raise ScannerOutputError."""
        adapter = SemgrepAdapter()
        with pytest.raises(ScannerOutputError, match="Expected JSON object"):
            adapter.parse_output(json.dumps([1, 2, 3]), "/tmp/repo")

    def test_parse_output_raises_on_wrong_type_osv(self):
        adapter = OSVScannerAdapter()
        with pytest.raises(ScannerOutputError, match="Expected JSON object"):
            adapter.parse_output(json.dumps([1, 2, 3]), "/tmp/repo")

    def test_trivy_accepts_list_format(self):
        """Trivy output may be a list of result objects (legacy format) — no error."""
        adapter = TrivyAdapter()
        findings = adapter.parse_output(json.dumps([{"Target": "f.txt"}]), "/tmp/repo")
        assert findings == []  # valid structure, no vulns
