"""Unit tests for deterministic static analysis scanner adapters (Semgrep, Trivy, OSV-Scanner) using fixture outputs."""

import json
from unittest.mock import patch
import pytest

from app.analysis.adapters import OSVScannerAdapter, SemgrepAdapter, TrivyAdapter
from app.analysis.schemas import ToolStatus
from app.schemas.enums import Severity


@pytest.mark.asyncio
async def test_semgrep_adapter_parsing_fixture():
    """Verify SemgrepAdapter parses standard Semgrep JSON output into canonical StaticFinding objects."""
    mock_semgrep_json = {
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
                        "fix": "jwt.decode(token, key=SECRET, algorithms=['HS256'])"
                    }
                }
            }
        ]
    }

    adapter = SemgrepAdapter()
    findings = adapter.parse_output(json.dumps(mock_semgrep_json), repo_dir="/tmp/sample_repo")

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.rule_id == "python.jwt.security.unverified-jwt-decode.unverified-jwt-decode"
    assert f.severity == Severity.HIGH
    assert f.category == "security"
    assert f.confidence == "HIGH"
    assert f.evidence.file_path == "src/auth/jwt.py"
    assert f.evidence.start_line == 42
    assert "jwt.decode" in f.evidence.code_snippet
    assert f.mitigation is not None


@pytest.mark.asyncio
async def test_trivy_adapter_parsing_fixture():
    """Verify TrivyAdapter parses Vulnerabilities, Secrets, and Misconfigurations."""
    mock_trivy_json = {
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
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-45857"
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-secret-access-key",
                        "Title": "AWS Secret Access Key",
                        "Severity": "CRITICAL",
                        "StartLine": 15,
                        "EndLine": 15,
                        "Code": {
                            "Lines": [{"Content": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}]
                        }
                    }
                ]
            }
        ]
    }

    adapter = TrivyAdapter()
    findings = adapter.parse_output(json.dumps(mock_trivy_json), repo_dir="/tmp/sample_repo")

    assert len(findings) == 2

    vuln = next(f for f in findings if f.category == "vulnerability")
    assert vuln.rule_id == "CVE-2023-45857"
    assert vuln.severity == Severity.CRITICAL
    assert "Upgrade axios to version 1.6.0" in vuln.mitigation

    secret = next(f for f in findings if f.category == "secret")
    assert secret.rule_id == "aws-secret-access-key"
    assert secret.severity == Severity.CRITICAL
    assert secret.evidence.start_line == 15


@pytest.mark.asyncio
async def test_osv_adapter_parsing_fixture():
    """Verify OSVScannerAdapter parses dependency vulnerability outputs."""
    mock_osv_json = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {
                            "name": "urllib3",
                            "version": "1.26.4",
                            "ecosystem": "PyPI"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-q2x7-8rv6-6q7h",
                                "summary": "urllib3 Proxy-Authorization Header Injection",
                                "aliases": ["CVE-2023-43804"],
                                "database_specific": {"severity": "HIGH"}
                            }
                        ]
                    }
                ]
            }
        ]
    }

    adapter = OSVScannerAdapter()
    findings = adapter.parse_output(json.dumps(mock_osv_json), repo_dir="/tmp/sample_repo")

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "osv-scanner"
    assert f.rule_id == "GHSA-q2x7-8rv6-6q7h"
    assert f.severity == Severity.HIGH
    assert f.category == "dependency"
    assert f.evidence.file_path == "requirements.txt"
    assert "urllib3==1.26.4" in f.evidence.code_snippet


@pytest.mark.asyncio
async def test_scanner_unavailable_handling():
    """Verify that when a tool binary is not installed in PATH, scan() returns UNAVAILABLE without crashing."""
    adapter = SemgrepAdapter()
    with patch.object(adapter, "is_available", return_value=False):
        result = await adapter.scan("/tmp/nonexistent_repo")

    assert result.status == ToolStatus.UNAVAILABLE
    assert result.tool == "semgrep"
    assert len(result.findings) == 0
    assert "not installed or not in PATH" in result.error_message


@pytest.mark.asyncio
async def test_scanner_disabled_handling():
    """Verify that disabled scanner returns DISABLED status without executing."""
    adapter = TrivyAdapter()
    with patch.object(type(adapter), "is_enabled", new_callable=lambda: False):
        result = await adapter.scan("/tmp/nonexistent_repo")

    assert result.status == ToolStatus.DISABLED
    assert result.tool == "trivy"
    assert len(result.findings) == 0
