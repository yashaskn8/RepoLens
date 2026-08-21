"""Abstract base adapter for deterministic analysis tools (Semgrep, Trivy, OSV-Scanner)."""

from abc import ABC, abstractmethod
import asyncio
import os
import shutil
import subprocess
import time
from typing import FrozenSet, List, Optional, Tuple

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus, _MAX_DIAGNOSTIC_STDERR_CHARS
from app.core.config import get_settings
from app.schemas.enums import Severity


class ScannerOutputError(Exception):
    """Raised when scanner stdout cannot be parsed into expected machine-readable format."""

    def __init__(self, tool: str, reason: str):
        self.tool = tool
        self.reason = reason
        super().__init__(f"{tool}: {reason}")


def _bound_stderr(stderr: Optional[str]) -> Optional[str]:
    """Truncate stderr to bounded length, stripping trailing whitespace."""
    if not stderr or not stderr.strip():
        return None
    bounded = stderr.strip()[:_MAX_DIAGNOSTIC_STDERR_CHARS]
    if len(stderr.strip()) > _MAX_DIAGNOSTIC_STDERR_CHARS:
        bounded += "\n... [truncated]"
    return bounded


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

    @property
    def _accepted_exit_codes(self) -> FrozenSet[int]:
        """Exit codes that indicate the scanner process completed normally.

        Default is {0}. Concrete adapters (e.g. Semgrep, OSV) override to specify
        their custom exit codes (such as 1 for findings present).
        Any exit code NOT in this set is treated as a tool failure.
        """
        return frozenset({0})

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
        """Execute a fixed command with shell=False in a separate thread, enforcing timeout.

        Raises subprocess.TimeoutExpired on timeout (NOT asyncio.TimeoutError).
        """
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
        """Parse tool JSON output into canonical StaticFinding items.

        MUST raise ScannerOutputError if the output cannot be parsed into
        the expected machine-readable format (e.g. invalid JSON, wrong schema).
        Returning an empty list is valid only when the output is well-formed
        but contains no findings.
        """
        pass

    @property
    def requires_structured_output(self) -> bool:
        """Indicate whether this scanner produces structured machine-readable JSON output.

        When True, empty or whitespace-only stdout with an accepted exit code is treated
        as ToolStatus.INVALID_OUTPUT rather than clean zero findings.
        """
        return True

    async def scan(self, repo_dir: str) -> ScannerResult:
        """Execute scanner on repository directory and return structured ScannerResult.

        A result is COMPLETED only when:
        - the process completed under a known-valid exit code; AND
        - expected machine-readable output was successfully parsed.
        """
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
            bounded_stderr = _bound_stderr(stderr)

            # --- Exit code validation ---
            if returncode not in self._accepted_exit_codes:
                return ScannerResult(
                    tool=self.tool_name,
                    status=ToolStatus.FAILED,
                    error_message=(
                        f"{self.tool_name} exited with unexpected code {returncode}. "
                        f"Accepted codes: {sorted(self._accepted_exit_codes)}."
                    ),
                    execution_time_ms=execution_time_ms,
                    diagnostic_stderr=bounded_stderr,
                )

            # --- Parse output ---
            if not stdout.strip():
                if self.requires_structured_output:
                    return ScannerResult(
                        tool=self.tool_name,
                        status=ToolStatus.INVALID_OUTPUT,
                        error_message=f"{self.tool_name} returned empty/blank stdout when valid JSON output was required.",
                        execution_time_ms=execution_time_ms,
                        diagnostic_stderr=bounded_stderr,
                    )
                findings: List[StaticFinding] = []
            else:
                # parse_output raises ScannerOutputError on invalid format
                findings = self.parse_output(stdout, repo_dir)

            return ScannerResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings,
                execution_time_ms=execution_time_ms,
                diagnostic_stderr=bounded_stderr,
            )

        except subprocess.TimeoutExpired:
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            return ScannerResult(
                tool=self.tool_name,
                status=ToolStatus.TIMEOUT,
                error_message=f"{self.tool_name} execution timed out.",
                execution_time_ms=execution_time_ms,
            )

        except ScannerOutputError as exc:
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            return ScannerResult(
                tool=self.tool_name,
                status=ToolStatus.INVALID_OUTPUT,
                error_message=f"Failed to parse {self.tool_name} output: {exc.reason}",
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
