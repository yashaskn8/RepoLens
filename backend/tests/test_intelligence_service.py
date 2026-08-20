"""Unit tests for RepositoryIntelligenceService orchestration."""

import os
import tempfile
from unittest.mock import AsyncMock, patch
import pytest

from app.analysis.base import BaseScannerAdapter
from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.analysis.service import RepositoryIntelligenceService
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence


@pytest.mark.asyncio
async def test_intelligence_service_orchestration():
    """Verify that analyze_repository orchestrates manifest parsing and concurrent scanner execution."""
    with tempfile.TemporaryDirectory(prefix="intel_service_test_") as tmp_dir:
        # Create a sample python file
        with open(os.path.join(tmp_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write("def compute(x):\n    return x * 2\n")

        # Mock scanner adapters
        mock_semgrep = AsyncMock(spec=BaseScannerAdapter)
        mock_semgrep.tool_name = "semgrep"
        mock_semgrep.scan.return_value = ScannerResult(
            tool="semgrep",
            status=ToolStatus.COMPLETED,
            findings=[
                StaticFinding(
                    tool="semgrep",
                    rule_id="test.rule",
                    title="Test Rule",
                    description="Test issue",
                    severity=Severity.MEDIUM,
                    evidence=Evidence(file_path="app.py", start_line=1, end_line=2),
                )
            ],
        )

        mock_trivy = AsyncMock(spec=BaseScannerAdapter)
        mock_trivy.tool_name = "trivy"
        mock_trivy.scan.return_value = ScannerResult(
            tool="trivy",
            status=ToolStatus.UNAVAILABLE,
            error_message="trivy not found",
        )

        service = RepositoryIntelligenceService(scanner_adapters=[mock_semgrep, mock_trivy])
        evidence_store = await service.analyze_repository(
            repo_dir=tmp_dir,
            repository_url="https://github.com/org/test-repo",
            commit_hash="1234567890abcdef",
            branch="main",
        )

        assert evidence_store.manifest.repository_url == "https://github.com/org/test-repo"
        assert evidence_store.manifest.total_files == 1
        assert len(evidence_store.all_findings) == 1
        assert evidence_store.all_findings[0].tool == "semgrep"
        assert evidence_store.scanner_results["trivy"].status == ToolStatus.UNAVAILABLE

        # Verify symbols extracted in manifest
        symbols = evidence_store.get_symbols(file_path="app.py")
        assert len(symbols) == 1
        assert symbols[0].name == "compute"
