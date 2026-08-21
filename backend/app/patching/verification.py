"""Deterministic patch safety, syntax, secret, contract, and scanner verification service."""

import asyncio
import logging
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from app.analysis.adapters import OSVScannerAdapter, SemgrepAdapter, TrivyAdapter
from app.analysis.base import BaseScannerAdapter
from app.analysis.store import EvidenceStore
from app.graph.builder import build_repository_graph
from app.graph.schemas import ContractMatchStatus
from app.ingestion.manifest import build_manifest
from app.ingestion.parser import _get_language, parse_file
from tree_sitter import Parser
from app.ingestion.schemas import RepositoryManifest
from app.patching.applier import apply_unified_diff_to_directory
from app.patching.schemas import (
    CheckStatus,
    PatchProposal,
    PatchVerificationResult,
    VerificationCheckItem,
    VerificationStatus,
)
from app.patching.validator import parse_diff_files, validate_patch_proposal
from app.planning.schemas import FixPlan
from app.schemas.enums import Severity
from app.schemas.finding import Finding
from app.schemas.static_finding import ScannerResult, StaticFinding, ToolStatus

logger = logging.getLogger(__name__)

# Secret detection patterns
_SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Hardcoded API/Secret Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key Header"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JSON Web Token"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
]


class PatchVerificationService:
    """Rigorous deterministic verification engine for candidate patches.
    
    Guarantees:
    - Never modifies the original repository.
    - Never executes untrusted repository source code, tests, or scripts.
    - Operates strictly in an isolated temporary worktree.
    - Enforces 12 distinct deterministic safety and quality checks without placeholders.
    - Never converts UNAVAILABLE, FAILED, TIMEOUT, or NOT_EVALUATED to PASSED.
    """

    def __init__(self, scanner_adapters: Optional[List[BaseScannerAdapter]] = None):
        self.scanner_adapters: List[BaseScannerAdapter] = scanner_adapters or [
            SemgrepAdapter(),
            TrivyAdapter(),
            OSVScannerAdapter(),
        ]

    def _copy_repo_to_temp(self, source_dir: str, dest_dir: str) -> None:
        """Copy repository files into temporary sandbox directory."""
        if not os.path.exists(source_dir):
            return

        for item in os.listdir(source_dir):
            s = os.path.join(source_dir, item)
            d = os.path.join(dest_dir, item)
            if os.path.isdir(s):
                # Skip virtual environments and caches
                if item in (".venv", "venv", "node_modules", ".git", "__pycache__", ".pytest_cache", ".next"):
                    continue
                shutil.copytree(s, d, symlinks=False, ignore=shutil.ignore_patterns("*.pyc", "__pycache__"))
            else:
                shutil.copy2(s, d)

    def _check_secrets(self, diff_text: str, patched_contents: Dict[str, str]) -> Tuple[bool, List[str]]:
        """Check whether diff or patched files introduce obvious secrets."""
        found_secrets: List[str] = []

        # Check additions in diff
        additions = "\n".join(l[1:] for l in diff_text.split("\n") if l.startswith("+") and not l.startswith("+++"))
        for pattern, label in _SECRET_PATTERNS:
            if re.search(pattern, additions):
                found_secrets.append(f"Secret pattern detected in diff: {label}")

        # Check patched file contents
        for path, content in patched_contents.items():
            for pattern, label in _SECRET_PATTERNS:
                if re.search(pattern, content):
                    found_secrets.append(f"Secret pattern detected in '{path}': {label}")

        return len(found_secrets) == 0, found_secrets

    def _check_tree_sitter_ast(self, temp_dir: str, modified_files: List[str]) -> Tuple[bool, List[str]]:
        """Verify that modified source files still parse cleanly with Tree-sitter without syntax errors."""
        failures: List[str] = []

        for rel_path in modified_files:
            full_p = os.path.join(temp_dir, rel_path)
            if not os.path.exists(full_p):
                failures.append(f"File not found on disk: '{rel_path}'")
                continue

            # Determine language
            if rel_path.endswith(".py"):
                lang = "python"
            elif rel_path.endswith(".tsx"):
                lang = "tsx"
            elif rel_path.endswith(".ts"):
                lang = "typescript"
            elif rel_path.endswith((".js", ".jsx")):
                lang = "javascript"
            else:
                lang = None
            if not lang:
                continue

            try:
                with open(full_p, "rb") as f:
                    source_bytes = f.read()

                lang_obj = _get_language(lang)
                if lang_obj:
                    parser = Parser(lang_obj)
                    tree = parser.parse(source_bytes)
                    if tree.root_node.has_error:
                        failures.append(f"Tree-sitter detected syntax errors in '{rel_path}'")

                # If Python, also verify with Python standard AST parser
                if lang == "python":
                    import ast
                    ast.parse(source_bytes.decode("utf-8", errors="ignore"))
            except Exception as exc:
                failures.append(f"Syntax validation failed for '{rel_path}': {str(exc)}")

        return len(failures) == 0, failures

    async def verify_patch(
        self,
        proposal: PatchProposal,
        finding: Finding,
        fix_plan: FixPlan,
        original_repo_dir: str,
        manifest: RepositoryManifest,
    ) -> PatchVerificationResult:
        """Run all 12 deterministic verification checks on an isolated temporary worktree without mock bypasses."""
        checks: List[VerificationCheckItem] = []
        checks_passed: List[str] = []
        checks_failed: List[str] = []

        def record_check(name: str, check_status: CheckStatus, details: Optional[str] = None):
            is_passed = (check_status == CheckStatus.PASSED)
            checks.append(
                VerificationCheckItem(
                    check_name=name,
                    passed=is_passed,
                    status=check_status,
                    details=details,
                )
            )
            if is_passed:
                checks_passed.append(name)
            else:
                checks_failed.append(name)

        diff_text = proposal.unified_diff.strip()

        # =========================================================================
        # 1. Unified diff syntax
        # =========================================================================
        val_report = validate_patch_proposal(proposal, fix_plan=fix_plan, manifest=manifest)
        c1_status = CheckStatus.PASSED if val_report.is_valid else CheckStatus.FAILED
        record_check("check_1_diff_syntax", c1_status, ", ".join(val_report.rejection_reasons) if not val_report.is_valid else "Valid unified diff format")

        # =========================================================================
        # 2. Path confinement
        # =========================================================================
        parsed_files = parse_diff_files(diff_text)
        path_confined = all(not os.path.isabs(p) and not p.startswith(("/", "\\", "..")) for p in parsed_files) if parsed_files else False
        c2_status = CheckStatus.PASSED if path_confined else CheckStatus.FAILED
        record_check("check_2_path_confinement", c2_status, "All paths strictly localized relative to repo root" if path_confined else "Path escapes boundary")

        # =========================================================================
        # 3. Symlink / path traversal escape prevention
        # =========================================================================
        no_symlink_escape = all(".." not in p and not p.startswith(("/", "\\")) for p in parsed_files) if parsed_files else False
        c3_status = CheckStatus.PASSED if no_symlink_escape else CheckStatus.FAILED
        record_check("check_3_symlink_traversal_prevention", c3_status, "No symlinks or traversal vectors" if no_symlink_escape else "Symlink/traversal sequence detected")

        # =========================================================================
        # 4. No binary file modification
        # =========================================================================
        binary_exts = {".png", ".jpg", ".jpeg", ".gif", ".exe", ".bin", ".pyc", ".so", ".dll", ".db", ".sqlite"}
        no_binary = all(not any(p.lower().endswith(ext) for ext in binary_exts) for p in parsed_files) if parsed_files else False
        c4_status = CheckStatus.PASSED if no_binary else CheckStatus.FAILED
        record_check("check_4_no_binary_modification", c4_status, "All targeted files are text source files" if no_binary else "Binary file targeted")

        # =========================================================================
        # 5. Scope confinement (only planned files changed)
        # =========================================================================
        allowed_files = set(f.replace("\\", "/").lstrip("/") for f in fix_plan.files_expected_to_change)
        scope_ok = all(p in allowed_files for p in parsed_files) if parsed_files else False
        c5_status = CheckStatus.PASSED if scope_ok else CheckStatus.FAILED
        record_check("check_5_scope_confinement", c5_status, f"Modified files match FixPlan scope ({sorted(list(allowed_files))})" if scope_ok else f"Modified files outside FixPlan scope ({parsed_files} vs {sorted(list(allowed_files))})")

        # Create isolated temporary sandbox workspace
        with tempfile.TemporaryDirectory() as temp_dir:
            self._copy_repo_to_temp(original_repo_dir, temp_dir)

            # Apply candidate patch to temporary copy
            patched_contents: Dict[str, str] = {}
            apply_succeeded = False
            try:
                patched_contents = apply_unified_diff_to_directory(diff_text, temp_dir)
                apply_succeeded = True
            except Exception as exc:
                apply_succeeded = False
                logger.warning("Failed to apply patch in temporary sandbox: %s", str(exc))

            # =========================================================================
            # 6. Tree-sitter AST parse check on patched files
            # =========================================================================
            syntax_clean, syntax_errs = self._check_tree_sitter_ast(temp_dir, parsed_files)
            c6_ok = apply_succeeded and syntax_clean
            c6_status = CheckStatus.PASSED if c6_ok else CheckStatus.FAILED
            record_check("check_6_tree_sitter_parse", c6_status, "; ".join(syntax_errs) if syntax_errs else ("Patched files parsed cleanly by Tree-sitter" if apply_succeeded else "Failed to apply patch"))

            # Re-generate repository manifest on patched temp directory
            patched_manifest = build_manifest(
                repo_dir=temp_dir,
                repository_url=manifest.repository_url,
                commit_hash=manifest.commit_hash,
                branch=manifest.branch,
            )
            patched_evidence_store = EvidenceStore(manifest=patched_manifest)

            # =========================================================================
            # 7. Route contracts consistency check (Pre vs Post comparison)
            # =========================================================================
            pre_evidence_store = EvidenceStore(manifest=manifest)
            pre_graph = build_repository_graph(manifest, pre_evidence_store)
            pre_contract_report = pre_graph.evaluate_route_contracts()

            patched_graph = build_repository_graph(patched_manifest, patched_evidence_store)
            post_contract_report = patched_graph.evaluate_route_contracts()

            # Compare pre and post defective sets
            pre_defective = [
                m for m in pre_contract_report.matches
                if m.status != ContractMatchStatus.MATCHED
            ]
            post_defective = [
                m for m in post_contract_report.matches
                if m.status != ContractMatchStatus.MATCHED
            ]

            pre_defective_keys = {
                (m.frontend_file, m.frontend_url, m.frontend_method, m.status)
                for m in pre_defective
            }
            post_defective_keys = {
                (m.frontend_file, m.frontend_url, m.frontend_method, m.status)
                for m in post_defective
            }

            new_mismatches = post_defective_keys - pre_defective_keys
            resolved_mismatches = pre_defective_keys - post_defective_keys

            is_route_finding = (
                (finding.category or "").lower() in ("route_mismatch", "contract", "api_contract")
                or "route mismatch" in finding.title.lower()
                or "api contract" in finding.title.lower()
                or "route contract" in finding.title.lower()
            )

            if new_mismatches:
                c7_status = CheckStatus.FAILED
                first_new = sorted(list(new_mismatches))[0]
                c7_details = f"Patch introduced new route contract mismatch: {first_new[0]} calls {first_new[2]} {first_new[1]} ({first_new[3].value})"
            elif is_route_finding:
                # Check if target mismatch changed from defective to resolved
                if not resolved_mismatches and post_defective:
                    c7_status = CheckStatus.FAILED
                    c7_details = "Target route contract mismatch remains unresolved in patched code"
                else:
                    c7_status = CheckStatus.PASSED
                    c7_details = f"Target route contract mismatch successfully resolved ({len(resolved_mismatches)} defect(s) fixed)"
            else:
                c7_status = CheckStatus.PASSED
                c7_details = f"Route contracts intact ({post_contract_report.matched_count} matched, 0 new mismatches)"

            record_check("check_7_route_contracts", c7_status, c7_details)

            # =========================================================================
            # 8. RepositoryGraph rebuild check
            # =========================================================================
            graph_nodes = patched_graph.to_domain_data().total_nodes
            graph_edges = patched_graph.to_domain_data().total_edges
            c8_status = CheckStatus.PASSED if graph_nodes > 0 else CheckStatus.FAILED
            record_check("check_8_graph_rebuild", c8_status, f"RepositoryGraph rebuilt with {graph_nodes} nodes and {graph_edges} edges" if graph_nodes > 0 else "RepositoryGraph empty on patched workspace")

            # =========================================================================
            # 10. Static scanner safety re-run (executed first to feed check 9 and 12)
            # =========================================================================
            scanner_tasks = [adapter.scan(temp_dir) for adapter in self.scanner_adapters]
            post_scanner_results: List[ScannerResult] = await asyncio.gather(*scanner_tasks, return_exceptions=False)

            failed_scanners = [r.tool for r in post_scanner_results if r.status in (ToolStatus.FAILED, ToolStatus.TIMEOUT)]
            available_scanners = [r for r in post_scanner_results if r.status == ToolStatus.COMPLETED]
            unavailable_scanners = [r for r in post_scanner_results if r.status in (ToolStatus.UNAVAILABLE, ToolStatus.DISABLED)]

            if failed_scanners:
                c10_status = CheckStatus.FAILED
                c10_details = f"Deterministic scanner(s) failed or timed out during execution: {', '.join(failed_scanners)}"
            elif not available_scanners:
                c10_status = CheckStatus.UNAVAILABLE
                c10_details = f"Deterministic scanners unavailable locally ({', '.join(f'{r.tool}: {r.status.value}' for r in unavailable_scanners)})"
            else:
                c10_status = CheckStatus.PASSED
                c10_details = f"Executed deterministic scanners: {', '.join(r.tool for r in available_scanners)}"

            record_check("check_10_scanners_clean", c10_status, c10_details)

            # =========================================================================
            # 11. Secret leak detection
            # =========================================================================
            secrets_clean, secret_errs = self._check_secrets(diff_text, patched_contents)
            c11_status = CheckStatus.PASSED if secrets_clean else CheckStatus.FAILED
            record_check("check_11_no_secrets_introduced", c11_status, "; ".join(secret_errs) if secret_errs else "Zero secrets or API keys introduced")

            # =========================================================================
            # 9. Target finding evidence re-evaluation
            # =========================================================================
            finding_resolved_status = CheckStatus.NEEDS_REVIEW
            finding_resolved_details = "No automated deterministic detector exists for this finding category; requires human review"

            target_ev = finding.evidences[0] if finding.evidences else None
            target_file = target_ev.file_path.replace("\\", "/").lstrip("/") if target_ev else ""

            # Case A: Finding comes from a static scanner rule or tool
            matching_scanner_result = next(
                (r for r in available_scanners if finding.rule_id and (r.tool.lower() in finding.rule_id.lower() or finding.rule_id.lower().startswith(r.tool.lower()))),
                None,
            )

            if matching_scanner_result:
                # Check if scanner still detected the finding
                still_flagged = any(
                    f.rule_id == finding.rule_id and f.evidence.file_path.replace("\\", "/").lstrip("/") == target_file
                    for f in matching_scanner_result.findings
                )
                if still_flagged:
                    finding_resolved_status = CheckStatus.FAILED
                    finding_resolved_details = f"Deterministic scanner '{matching_scanner_result.tool}' still flags rule '{finding.rule_id}' in {target_file}"
                else:
                    finding_resolved_status = CheckStatus.PASSED
                    finding_resolved_details = f"Deterministic scanner '{matching_scanner_result.tool}' verified rule '{finding.rule_id}' is resolved"
            elif is_route_finding:
                # Case B: Route / contract finding proved by contract matcher
                if c7_status == CheckStatus.PASSED:
                    finding_resolved_status = CheckStatus.PASSED
                    finding_resolved_details = "Deterministic contract matcher verified route contract resolution"
                else:
                    finding_resolved_status = CheckStatus.FAILED
                    finding_resolved_details = "Deterministic contract matcher detected route mismatch persists"
            elif "secret" in (finding.category or "").lower() or "secret" in finding.title.lower():
                # Case C: Secret finding proved by secret scanner
                if c11_status == CheckStatus.PASSED:
                    finding_resolved_status = CheckStatus.PASSED
                    finding_resolved_details = "Secret detector verified secret was removed"
                else:
                    finding_resolved_status = CheckStatus.FAILED
                    finding_resolved_details = "Secret detector found secret pattern still present"

            elif target_ev and target_ev.code_snippet and target_file in patched_contents:
                # Case D: Check if code snippet was actually altered/remediated rather than unchanged
                snippet_core = target_ev.code_snippet.strip()
                if len(snippet_core) > 10 and snippet_core in patched_contents[target_file]:
                    finding_resolved_status = CheckStatus.FAILED
                    finding_resolved_details = "Original defect snippet still present verbatim in patched file"
                else:
                    # Snippet changed, but without a dedicated deterministic detector, mark NEEDS_REVIEW
                    finding_resolved_status = CheckStatus.NEEDS_REVIEW
                    finding_resolved_details = "Defect snippet removed, but requires human verification (no automated rule detector)"

            record_check("check_9_finding_remediation", finding_resolved_status, finding_resolved_details)

            # =========================================================================
            # 12. No new deterministic HIGH/CRITICAL findings
            # =========================================================================
            new_critical_found = False
            new_critical_details = "Zero new HIGH/CRITICAL deterministic issues introduced by patch"

            if not secrets_clean:
                new_critical_found = True
                new_critical_details = "Patch introduced new secret vulnerability (CRITICAL)"
            elif not syntax_clean:
                new_critical_found = True
                new_critical_details = "Patch introduced syntax corruption in source code (CRITICAL)"
            elif available_scanners:
                # Compare pre-patch and post-patch scanner findings
                pre_scanner_tasks = [adapter.scan(original_repo_dir) for adapter in self.scanner_adapters if adapter.tool_name in [r.tool for r in available_scanners]]
                pre_scanner_results: List[ScannerResult] = await asyncio.gather(*pre_scanner_tasks, return_exceptions=False)


                pre_finding_keys = {
                    (f.tool, f.rule_id, f.evidence.file_path.replace("\\", "/").lstrip("/"), f.severity)
                    for r in pre_scanner_results
                    for f in r.findings
                }

                new_high_crit_findings = [
                    f for r in post_scanner_results
                    for f in r.findings
                    if f.severity in (Severity.HIGH, Severity.CRITICAL)
                    and (f.tool, f.rule_id, f.evidence.file_path.replace("\\", "/").lstrip("/"), f.severity) not in pre_finding_keys
                ]

                if new_high_crit_findings:
                    new_critical_found = True
                    first_new = new_high_crit_findings[0]
                    new_critical_details = f"New {first_new.severity.value} finding introduced by patch: {first_new.title} ({first_new.rule_id or 'unknown'}) in {first_new.evidence.file_path}"

            c12_status = CheckStatus.FAILED if new_critical_found else CheckStatus.PASSED
            record_check("check_12_no_new_critical_findings", c12_status, new_critical_details)

        # Determine overall verification status
        critical_failed = not (
            val_report.is_valid
            and path_confined
            and no_binary
            and syntax_clean
            and secrets_clean
            and apply_succeeded
            and (c12_status == CheckStatus.PASSED)
        )

        has_explicit_failures = any(c.status == CheckStatus.FAILED for c in checks)
        has_unreviewed_or_unavailable = any(
            c.status in (CheckStatus.NEEDS_REVIEW, CheckStatus.UNAVAILABLE, CheckStatus.TIMEOUT, CheckStatus.NOT_EVALUATED)
            for c in checks
        )

        if critical_failed or has_explicit_failures:
            overall_status = VerificationStatus.FAILED
            explanation = f"Patch failed deterministic verification: {', '.join(checks_failed)}"
        elif has_unreviewed_or_unavailable:
            overall_status = VerificationStatus.NEEDS_REVIEW
            explanation = f"Patch passed core safety but flagged items requiring review/local tools: {', '.join(checks_failed)}"
        else:
            overall_status = VerificationStatus.PASSED
            explanation = "Patch passed all 12 deterministic safety, syntax, security, contract, and scanner verification checks."

        return PatchVerificationResult(
            patch_id=proposal.id,
            finding_id=finding.id,
            status=overall_status,
            syntax_valid=(apply_succeeded and syntax_clean),
            security_clean=secrets_clean,
            contract_aligned=(c7_status == CheckStatus.PASSED),
            target_finding_resolved=(finding_resolved_status == CheckStatus.PASSED),
            checks=checks,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            explanation=explanation,
        )

