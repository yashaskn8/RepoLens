"""Semgrep deterministic static analysis adapter."""

import json
import os
from typing import FrozenSet, List
from app.analysis.base import BaseScannerAdapter, ScannerOutputError
from app.analysis.schemas import StaticFinding
from app.core.config import get_settings
from app.schemas.evidence import Evidence


class SemgrepAdapter(BaseScannerAdapter):
    """Adapter for Semgrep SAST scanner.

    Exit code semantics:
      0 — scan completed (no findings, or findings present without --error)
      1 — findings present (when --error flag is used; we don't use --error,
          but accept 1 defensively since some configs enable it)
      ≥2 — fatal error (invalid config, internal crash, etc.)
    """

    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def tool_path(self) -> str:
        return get_settings().SEMGREP_PATH

    @property
    def is_enabled(self) -> bool:
        return get_settings().SEMGREP_ENABLED

    @property
    def _accepted_exit_codes(self) -> FrozenSet[int]:
        return frozenset({0, 1})

    def _build_command(self, repo_dir: str) -> List[str]:
        return [
            self.tool_path,
            "--json",
            "--config",
            "auto",
            "--quiet",
            "--no-git-ignore",
            "--metrics=off",
            "--disable-version-check",
            repo_dir,
        ]

    def parse_output(self, raw_json_str: str, repo_dir: str) -> List[StaticFinding]:
        """Parse Semgrep JSON output into canonical StaticFinding objects.

        Raises ScannerOutputError if JSON is malformed or missing expected structure.
        """
        findings: List[StaticFinding] = []
        if not raw_json_str or not raw_json_str.strip():
            return findings

        try:
            data = json.loads(raw_json_str)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ScannerOutputError(self.tool_name, f"Invalid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ScannerOutputError(self.tool_name, f"Expected JSON object, got {type(data).__name__}")

        results = data.get("results", [])
        for item in results:
            try:
                check_id = item.get("check_id", "unknown-rule")
                raw_path = item.get("path", "")
                rel_path = os.path.relpath(raw_path, repo_dir).replace("\\", "/") if os.path.isabs(raw_path) else raw_path.replace("\\", "/")

                start_line = item.get("start", {}).get("line")
                end_line = item.get("end", {}).get("line")
                extra = item.get("extra", {})

                message = extra.get("message", "Semgrep rule match")
                raw_severity = extra.get("severity")
                lines_snippet = extra.get("lines")
                metadata = extra.get("metadata", {})

                category = metadata.get("category", "sast")
                confidence = metadata.get("confidence")

                evidence = Evidence(
                    file_path=rel_path,
                    start_line=start_line,
                    end_line=end_line,
                    code_snippet=lines_snippet,
                    context_notes=message,
                )

                findings.append(
                    StaticFinding(
                        tool=self.tool_name,
                        rule_id=check_id,
                        title=check_id.split(".")[-1].replace("-", " ").title() if "." in check_id else check_id,
                        description=message,
                        severity=self._normalize_severity(raw_severity),
                        category=category,
                        evidence=evidence,
                        mitigation=metadata.get("fix") or metadata.get("remediation"),
                        confidence=confidence.upper() if confidence else None,
                        raw_details={"check_id": check_id, "metadata": metadata},
                    )
                )
            except Exception:
                continue

        return findings
