"""Unit tests for scanner completeness and empty JSON stdout handling."""

import asyncio
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.analysis.adapters.osv import OSVScannerAdapter
from app.analysis.adapters.semgrep import SemgrepAdapter
from app.analysis.adapters.trivy import TrivyAdapter
from app.analysis.base import BaseScannerAdapter, ScannerOutputError
from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.patching.schemas import CheckStatus, PatchProposal, VerificationCheckItem
from app.patching.verification import PatchVerificationService
from app.planning.schemas import FixPlan
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


@pytest.mark.asyncio
async def test_semgrep_empty_stdout_returns_invalid_output():
    """Verify that Semgrep returning exit code 0 + empty stdout returns ToolStatus.INVALID_OUTPUT."""
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (0, "   \n  ", "")
            result = await adapter.scan(tmpdir)
            assert result.status == ToolStatus.INVALID_OUTPUT
            assert "empty/blank stdout" in result.error_message


@pytest.mark.asyncio
async def test_trivy_empty_stdout_returns_invalid_output():
    """Verify that Trivy returning exit code 0 + empty stdout returns ToolStatus.INVALID_OUTPUT."""
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = TrivyAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (0, "", "")
            result = await adapter.scan(tmpdir)
            assert result.status == ToolStatus.INVALID_OUTPUT
            assert "empty/blank stdout" in result.error_message


@pytest.mark.asyncio
async def test_osv_empty_stdout_returns_invalid_output():
    """Verify that OSV-Scanner returning exit code 0 + empty stdout returns ToolStatus.INVALID_OUTPUT."""
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = OSVScannerAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (0, "", "")
            result = await adapter.scan(tmpdir)
            assert result.status == ToolStatus.INVALID_OUTPUT
            assert "empty/blank stdout" in result.error_message


@pytest.mark.asyncio
async def test_semgrep_valid_empty_results_json_returns_completed_zero_findings():
    """Verify that Semgrep returning valid JSON with empty results returns COMPLETED with 0 findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = SemgrepAdapter()
        with patch.object(adapter, "is_available", return_value=True), \
             patch.object(adapter, "_execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (0, '{"results": [], "errors": []}', "")
            result = await adapter.scan(tmpdir)
            assert result.status == ToolStatus.COMPLETED
            assert len(result.findings) == 0
