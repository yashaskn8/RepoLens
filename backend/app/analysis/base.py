"""Abstract base adapter for deterministic analysis tools (Semgrep, Trivy, OSV-Scanner)."""

from abc import ABC, abstractmethod
import asyncio
import os
import shutil
import subprocess
import time
from typing import List, Optional, Tuple

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.core.config import get_settings
from app.schemas.enums import Severity


class BaseScannerAdapter(ABC):
    """Abstract interface and safe command execution base for deterministic scanners."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of the scanner tool."""
        pass

    @property
    @abstractmethod
    def tool_path(self) -> str:
        """Configured executable path or name."""
        pass

    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if scanner is enabled in settings."""
        pass

    def is_available(self) -> bool:
        """Check if the scanner executable is available on the host PATH."""
        return shutil.which(self.tool_path) is not None

    def _normalize_severity(self, raw_severity: Optional[str]) -> Severity:
        """Normalize tool-specific severity string to canonical Severity enum."""
        if not raw_severity:
            return Severity.INFO

        s = raw_severity.strip().upper()
        if s in ("CRITICAL", "FATAL"):
            return Severity.CRITICAL
        elif s in ("HIGH", "ERROR"):
            return Severity.HIGH
        elif s in ("MEDIUM", "MODERATE", "WARNING", "WARN"):
            return Severity.MEDIUM
        elif s in ("LOW", "NOTE"):
            return Severity.LOW
        elif s in ("INFO", "INFORMATIONAL", "UNKNOWN"):
            return Severity.INFO
        return Severity.INFO

    async def _execute_command(
        self,
        cmd: List[str],
        cwd: str,
        timeout_seconds: Optional[int] = None,
    ) -> Tuple[int, str, str]:
        """Execute a fixed command with shell=False in a separate thread, enforcing timeout."""
        settings = get_settings()
        timeout = timeout_seconds or settings.SCANNER_TIMEOUT_SECONDS

        def _run() -> Tuple[int, str, str]:
            res = subprocess.run(
                cmd,
                cwd=cwd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return res.returncode, res.stdout, res.stderr

        return await asyncio.to_thread(_run)

    @abstractmethod
    def parse_output(self, raw_json_str: str, repo_dir: str) -> List[StaticFinding]:
        """Parse tool JSON output into canonical StaticFinding items."""
        pass

    async def scan(self, repo_dir: str) -> ScannerResult:
        """Execute scanner on repository directory and return structured ScannerResult."""
        if not self.is_enabled:
            return ScannerResult(
                tool=self.tool_name,
                status=ToolStatus.DISABLED,
                error_message=f"{self.tool_name} is disabled in configuration.",
            )

        if not self.is_available():
            return ScannerResult(
                tool=self.tool_name,
                status=ToolStatus.UNAVAILABLE,
                error_message=f"Executable '{self.tool_path}' is not installed or not in PATH.",
            )

        start_time = time.perf_counter()
        try:
            cmd = self._build_command(repo_dir)
            returncode, stdout, stderr = await self._execute_command(cmd, cwd=repo_dir)
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0

            # Some tools (e.g. semgrep / trivy) return non-zero returncodes when findings are detected
            # We attempt parsing stdout if output is present
            findings = self.parse_output(stdout, repo_dir) if stdout.strip() else []

            return ScannerResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings,
                execution_time_ms=execution_time_ms,
            )

        except asyncio.TimeoutError:
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            return ScannerResult(
                tool=self.tool_name,
                status=ToolStatus.TIMEOUT,
                error_message=f"{self.tool_name} execution timed out.",
                execution_time_ms=execution_time_ms,
            )
        except Exception as exc:
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            return ScannerResult(
                tool=self.tool_name,
                status=ToolStatus.FAILED,
                error_message=f"Failed to execute {self.tool_name}: {str(exc)}",
                execution_time_ms=execution_time_ms,
            )

    @abstractmethod
    def _build_command(self, repo_dir: str) -> List[str]:
        """Construct safe command line arguments array with shell=False."""
        pass
