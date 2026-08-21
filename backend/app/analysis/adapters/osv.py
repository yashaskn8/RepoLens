"""OSV-Scanner deterministic dependency vulnerability analysis adapter."""

import json
import os
from typing import FrozenSet, List
from app.analysis.base import BaseScannerAdapter, ScannerOutputError
from app.analysis.schemas import StaticFinding
from app.core.config import get_settings
from app.schemas.evidence import Evidence


class OSVScannerAdapter(BaseScannerAdapter):
    """Adapter for Google OSV-Scanner open source vulnerability scanner.

    Exit code semantics:
      0 — no vulnerabilities found
      1 — vulnerabilities found
      ≥2 — fatal error (e.g. invalid args, network failure, internal crash)
    """

    @property
    def tool_name(self) -> str:
        return "osv-scanner"

    @property
    def tool_path(self) -> str:
        return get_settings().OSV_SCANNER_PATH

    @property
    def is_enabled(self) -> bool:
        return get_settings().OSV_SCANNER_ENABLED

    @property
    def _accepted_exit_codes(self) -> FrozenSet[int]:
        return frozenset({0, 1})

    def _build_command(self, repo_dir: str) -> List[str]:
        return [
            self.tool_path,
            "--json",
            "-r",
            repo_dir,
        ]

    def parse_output(self, raw_json_str: str, repo_dir: str) -> List[StaticFinding]:
        """Parse OSV-Scanner JSON output into canonical StaticFinding objects.

        Raises ScannerOutputError if JSON is malformed or has unexpected structure.
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
        for entry in results:
            source_info = entry.get("source", {})
            raw_path = source_info.get("path", "")
            rel_path = os.path.relpath(raw_path, repo_dir).replace("\\", "/") if os.path.isabs(raw_path) else raw_path.replace("\\", "/")

            for pkg_entry in entry.get("packages", []):
                pkg = pkg_entry.get("package", {})
                pkg_name = pkg.get("name", "package")
                pkg_ver = pkg.get("version", "unknown")
                ecosystem = pkg.get("ecosystem", "")

                for vuln in pkg_entry.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "UNKNOWN-OSV")
                    summary = vuln.get("summary") or vuln.get("details", "")
                    title = f"{vuln_id} in {pkg_name}@{pkg_ver}"
                    aliases = vuln.get("aliases", [])

                    # Parse severity from database_specific or CVSS
                    raw_sev = "MEDIUM"
                    if isinstance(vuln.get("database_specific"), dict):
                        raw_sev = vuln["database_specific"].get("severity", raw_sev)

                    evidence = Evidence(
                        file_path=rel_path,
                        code_snippet=f"{pkg_name}=={pkg_ver} ({ecosystem})",
                        context_notes=f"Vulnerable package {pkg_name} version {pkg_ver}. Aliases: {', '.join(aliases) if aliases else 'None'}",
                    )

                    findings.append(
                        StaticFinding(
                            tool=self.tool_name,
                            rule_id=vuln_id,
                            title=title,
                            description=summary or f"Vulnerability {vuln_id} affects {pkg_name}.",
                            severity=self._normalize_severity(str(raw_sev)),
                            category="dependency",
                            evidence=evidence,
                            mitigation=f"Upgrade dependency {pkg_name} to a non-vulnerable release.",
                            raw_details={"ecosystem": ecosystem, "aliases": aliases},
                        )
                    )

        return findings
