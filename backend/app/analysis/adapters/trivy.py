"""Trivy deterministic security and vulnerability analysis adapter."""

import json
import os
from typing import FrozenSet, List
from app.analysis.base import BaseScannerAdapter, ScannerOutputError
from app.analysis.schemas import StaticFinding
from app.core.config import get_settings
from app.schemas.evidence import Evidence


class TrivyAdapter(BaseScannerAdapter):
    """Adapter for Trivy filesystem scanner (vulnerabilities, misconfigurations, secrets).

    Exit code semantics:
      0 — scan completed successfully (findings may or may not be present)
      We do NOT use --exit-code, so Trivy returns 0 in both cases.
      Any non-zero exit code indicates a real tool error.
    """

    @property
    def tool_name(self) -> str:
        return "trivy"

    @property
    def tool_path(self) -> str:
        return get_settings().TRIVY_PATH

    @property
    def is_enabled(self) -> bool:
        return get_settings().TRIVY_ENABLED

    @property
    def _accepted_exit_codes(self) -> FrozenSet[int]:
        return frozenset({0})

    def _build_command(self, repo_dir: str) -> List[str]:
        return [
            self.tool_path,
            "fs",
            "--format",
            "json",
            "--quiet",
            repo_dir,
        ]

    def parse_output(self, raw_json_str: str, repo_dir: str) -> List[StaticFinding]:
        """Parse Trivy JSON output into canonical StaticFinding objects.

        Raises ScannerOutputError if JSON is malformed or has unexpected structure.
        """
        findings: List[StaticFinding] = []
        if not raw_json_str or not raw_json_str.strip():
            return findings

        try:
            data = json.loads(raw_json_str)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ScannerOutputError(self.tool_name, f"Invalid JSON: {exc}") from exc

        # Trivy output may be a dict with "Results" or a list of result objects
        if isinstance(data, dict):
            results = data.get("Results", [])
        elif isinstance(data, list):
            results = data
        else:
            raise ScannerOutputError(self.tool_name, f"Expected JSON object or array, got {type(data).__name__}")

        for target_res in results:
            raw_target = target_res.get("Target", "repository")
            rel_target = os.path.relpath(raw_target, repo_dir).replace("\\", "/") if os.path.isabs(raw_target) else raw_target.replace("\\", "/")

            # 1. Process Vulnerabilities
            for vuln in target_res.get("Vulnerabilities", []):
                vuln_id = vuln.get("VulnerabilityID", "UNKNOWN-CVE")
                pkg_name = vuln.get("PkgName", "package")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")
                title = vuln.get("Title") or f"{vuln_id} in {pkg_name} {installed_ver}"
                desc = vuln.get("Description") or f"Vulnerability {vuln_id} detected in {pkg_name} ({installed_ver})."
                raw_sev = vuln.get("Severity")
                primary_url = vuln.get("PrimaryURL")

                mitigation = f"Upgrade {pkg_name} to version {fixed_ver}" if fixed_ver else None
                if primary_url:
                    mitigation = f"{mitigation} (Ref: {primary_url})" if mitigation else f"Reference: {primary_url}"

                evidence = Evidence(
                    file_path=rel_target,
                    start_line=None,
                    end_line=None,
                    code_snippet=f"{pkg_name}=={installed_ver}",
                    context_notes=f"Installed version: {installed_ver}, Fixed version: {fixed_ver or 'N/A'}",
                )

                findings.append(
                    StaticFinding(
                        tool=self.tool_name,
                        rule_id=vuln_id,
                        title=title,
                        description=desc,
                        severity=self._normalize_severity(raw_sev),
                        category="vulnerability",
                        evidence=evidence,
                        mitigation=mitigation,
                        raw_details={"pkg_name": pkg_name, "installed": installed_ver, "fixed": fixed_ver},
                    )
                )

            # 2. Process Secrets
            for secret in target_res.get("Secrets", []):
                rule_id = secret.get("RuleID", "exposed-secret")
                title = secret.get("Title", f"Exposed Secret: {rule_id}")
                raw_sev = secret.get("Severity", "CRITICAL")
                start_line = secret.get("StartLine")
                end_line = secret.get("EndLine")
                code_lines = secret.get("Code", {}).get("Lines", [])
                snippet = "\n".join([line.get("Content", "") for line in code_lines]) if code_lines else secret.get("Match")

                evidence = Evidence(
                    file_path=rel_target,
                    start_line=start_line,
                    end_line=end_line,
                    code_snippet=snippet,
                    context_notes="Hardcoded secret or credential token detected.",
                )

                findings.append(
                    StaticFinding(
                        tool=self.tool_name,
                        rule_id=rule_id,
                        title=title,
                        description="Hardcoded credential or private secret key found in source code.",
                        severity=self._normalize_severity(raw_sev),
                        category="secret",
                        evidence=evidence,
                        mitigation="Revoke the credential immediately and migrate to secure environment variables or secret management.",
                        raw_details={"rule_id": rule_id},
                    )
                )

            # 3. Process Misconfigurations
            for misconf in target_res.get("Misconfigurations", []):
                rule_id = misconf.get("ID", "misconfiguration")
                title = misconf.get("Title", f"Misconfiguration: {rule_id}")
                desc = misconf.get("Description") or misconf.get("Message", "")
                raw_sev = misconf.get("Severity")
                resolution = misconf.get("Resolution")

                evidence = Evidence(
                    file_path=rel_target,
                    context_notes=misconf.get("Message", "Infrastructure misconfiguration"),
                )

                findings.append(
                    StaticFinding(
                        tool=self.tool_name,
                        rule_id=rule_id,
                        title=title,
                        description=desc,
                        severity=self._normalize_severity(raw_sev),
                        category="misconfiguration",
                        evidence=evidence,
                        mitigation=resolution,
                        raw_details={"id": rule_id},
                    )
                )

        return findings
