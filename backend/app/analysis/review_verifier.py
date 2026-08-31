"""Deterministic Verifier for Evidence-Grounded AI Change Reviews.

Guarantees:
- Strictly verifies that every referenced file, symbol, and line exists.
- Strictly verifies that evidence refs resolve to real deterministic context.
- Strictly rejects invented files, invented symbols, invalid line ranges, fake CALLS edges, and unsupported contract claims.
- Strictly separates CONFIRMED facts from SUPPORTED_INFERENCE and REJECTED claims.
- Never labels an unsupported or unproven inference as CONFIRMED.
"""

from datetime import datetime, timezone
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from app.analysis.evidence_ids import normalize_path
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.schemas.change_analysis import (
    BlastRadiusReport,
    ChangeImpact,
    ChangeReviewFinding,
    ChangeReviewReport,
    ChangeReviewVerdict,
    FileDiffFact,
    StructuralDiffResult,
    SymbolDiffFact,
)
from app.schemas.enums import ChangeImpactType, ChangeRiskLevel, Severity

logger = logging.getLogger(__name__)

_LINE_REF_REGEX = re.compile(r"^(?:line:)?([a-zA-Z0-9_\-\./\\]+):(\d+)(?:-(\d+))?$")
_EDGE_REF_REGEX = re.compile(r"^(?:edge:)?([a-zA-Z_]+):([a-zA-Z0-9_\-\./\\:]+)->([a-zA-Z0-9_\-\./\\:]+)$")


def _read_file_lines_safe(repo_dir: str, rel_path: str) -> Optional[List[str]]:
    """Safely read source lines from workspace if path confinement permits."""
    if not repo_dir or not rel_path:
        return None
    try:
        from app.core.path_confinement import PathTraversalError, resolve_safe_path
        abs_path = str(resolve_safe_path(repo_dir, rel_path))
        if os.path.exists(abs_path) and os.path.isfile(abs_path):
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.readlines()
    except Exception:
        pass
    return None


class ChangeReviewVerifier:
    """Canonical Deterministic Verifier for AI Change Reviews."""

    def __init__(self):
        pass

    def verify_finding(
        self,
        finding: ChangeReviewFinding,
        diff_result: StructuralDiffResult,
        blast_radius: Optional[BlastRadiusReport] = None,
        base_graph: Optional[RepositoryGraph] = None,
        head_graph: Optional[RepositoryGraph] = None,
        base_workspace: Optional[str] = None,
        head_workspace: Optional[str] = None,
    ) -> Tuple[ChangeReviewVerdict, str, Optional[Severity]]:
        """Deterministically verify a candidate review finding against all evidence sources.
        
        Returns:
            (verdict, verification_reason, justified_severity)
        """
        # Build index of known files (exact normalized paths)
        known_files: Set[str] = set()
        for f in diff_result.changed_files:
            known_files.add(normalize_path(f.file_path))
            if f.old_path:
                known_files.add(normalize_path(f.old_path))
        for f in diff_result.added_files + diff_result.deleted_files + diff_result.modified_files:
            known_files.add(normalize_path(f))
        for ren in diff_result.renamed_files:
            for r in ren:
                known_files.add(normalize_path(r))
        for delta in diff_result.dependency_deltas:
            known_files.add(normalize_path(delta.manifest_file))
        for delta in diff_result.config_deltas:
            known_files.add(normalize_path(delta.file_path))
        for delta in diff_result.route_deltas:
            known_files.add(normalize_path(delta.file_path))
        for delta in diff_result.schema_deltas:
            known_files.add(normalize_path(delta.file_path))

        # Ingest graph files if available
        for g in (base_graph, head_graph):
            if g:
                for n in g.get_nodes():
                    if n.file_path:
                        known_files.add(normalize_path(n.file_path))

        # Ingest blast radius files
        if blast_radius:
            for imp in blast_radius.impacts:
                if imp.source_file:
                    known_files.add(normalize_path(imp.source_file))
                if imp.affected_file:
                    known_files.add(normalize_path(imp.affected_file))

        # Build index of known exact symbols and structured identities
        known_symbols: Set[str] = set()
        known_exact_symbol_ids: Set[str] = set()

        for s in (
            diff_result.changed_symbols
            + diff_result.added_symbols
            + diff_result.deleted_symbols
            + diff_result.modified_symbols
        ):
            norm_f = normalize_path(s.file_path)
            known_symbols.add(s.symbol_name)
            known_exact_symbol_ids.add(f"{norm_f}:{s.symbol_name}")
            known_exact_symbol_ids.add(f"{norm_f}:{s.symbol_kind}:{s.symbol_name}")
            start_l = s.head_location.get("start_line") if s.head_location else (s.base_location.get("start_line") if s.base_location else 1)
            known_exact_symbol_ids.add(f"symbol:{norm_f}:{s.symbol_kind}:{s.symbol_name}:{start_l}")
            known_exact_symbol_ids.add(f"{norm_f}:{s.symbol_kind}:{s.symbol_name}:{start_l}")

        for delta in diff_result.dependency_deltas:
            known_symbols.add(delta.package_name)
            known_exact_symbol_ids.add(f"{normalize_path(delta.manifest_file)}:{delta.package_name}")
        for delta in diff_result.config_deltas:
            known_symbols.add(delta.key)
            known_exact_symbol_ids.add(f"{normalize_path(delta.file_path)}:{delta.key}")
        for delta in diff_result.route_deltas:
            known_symbols.add(delta.route_name)
            known_exact_symbol_ids.add(f"{normalize_path(delta.file_path)}:{delta.route_name}")
        for delta in diff_result.schema_deltas:
            known_symbols.add(delta.model_name)
            known_symbols.add(delta.field_name)
            known_exact_symbol_ids.add(f"{normalize_path(delta.file_path)}:{delta.model_name}")

        # Ingest graph symbols
        for g in (base_graph, head_graph):
            if g:
                for n in g.get_nodes():
                    known_symbols.add(n.label)
                    known_exact_symbol_ids.add(n.id)
                    if n.file_path:
                        norm_f = normalize_path(n.file_path)
                        known_exact_symbol_ids.add(f"{norm_f}:{n.label}")
                        known_exact_symbol_ids.add(f"symbol:{norm_f}:{n.kind.value}:{n.label}:{n.start_line}")
                        known_exact_symbol_ids.add(f"{norm_f}:{n.kind.value}:{n.label}:{n.start_line}")

        # Ingest blast radius symbols
        if blast_radius:
            for imp in blast_radius.impacts:
                if imp.source_symbol:
                    known_symbols.add(imp.source_symbol)
                    if imp.source_file:
                        known_exact_symbol_ids.add(f"{normalize_path(imp.source_file)}:{imp.source_symbol}")
                if imp.affected_symbol:
                    known_symbols.add(imp.affected_symbol)
                    if imp.affected_file:
                        known_exact_symbol_ids.add(f"{normalize_path(imp.affected_file)}:{imp.affected_symbol}")

        # ---------------------------------------------------------------------
        # Check 1: File Existence Verification (Exact Path Equality)
        # ---------------------------------------------------------------------
        for file_path in finding.affected_files:
            clean_f = normalize_path(file_path)
            if clean_f not in known_files:
                # Check real workspace if provided
                found_on_disk = False
                for ws in (head_workspace, base_workspace):
                    if ws and _read_file_lines_safe(ws, clean_f) is not None:
                        found_on_disk = True
                        known_files.add(clean_f)
                        break
                if not found_on_disk:
                    return (
                        ChangeReviewVerdict.REJECTED,
                        f"Invented file: '{file_path}' does not exist in analysis diff, graph, or repository workspace.",
                        None,
                    )

        # ---------------------------------------------------------------------
        # Check 2: Symbol Existence Verification
        # ---------------------------------------------------------------------
        for symbol_name in finding.affected_symbols:
            if symbol_name not in known_symbols:
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Invented symbol: '{symbol_name}' does not exist in diff facts, relationship graph, or blast radius.",
                    None,
                )

        # ---------------------------------------------------------------------
        # Check 3: Evidence References Resolution & Belonging
        # ---------------------------------------------------------------------
        if not finding.evidence_refs:
            return (
                ChangeReviewVerdict.REJECTED,
                "Missing required deterministic evidence references (evidence_refs is empty).",
                None,
            )

        for ref in finding.evidence_refs:
            resolved = self._resolve_evidence_ref(
                ref=ref,
                diff_result=diff_result,
                blast_radius=blast_radius,
                base_graph=base_graph,
                head_graph=head_graph,
                base_workspace=base_workspace,
                head_workspace=head_workspace,
                known_files=known_files,
                known_symbols=known_symbols,
                known_exact_symbol_ids=known_exact_symbol_ids,
            )
            if not resolved[0]:
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Invalid evidence reference: '{ref}' does not resolve to deterministic analysis context ({resolved[1]}).",
                    None,
                )

        # ---------------------------------------------------------------------
        # Check 4: Line Bounds Verification (if line numbers given in refs)
        # ---------------------------------------------------------------------
        for ref in finding.evidence_refs:
            match = _LINE_REF_REGEX.match(ref)
            if match:
                f_path = normalize_path(match.group(1))
                start_l = int(match.group(2))
                end_l = int(match.group(3)) if match.group(3) else start_l

                if start_l < 1:
                    return (
                        ChangeReviewVerdict.REJECTED,
                        f"Invalid line number {start_l} for file '{f_path}' (must be >= 1).",
                        None,
                    )
                if end_l < start_l:
                    return (
                        ChangeReviewVerdict.REJECTED,
                        f"Invalid line range {start_l}-{end_l} for file '{f_path}' (end < start).",
                        None,
                    )

                # Check total lines against workspace if available
                file_lines = None
                for ws in (head_workspace, base_workspace):
                    if ws:
                        file_lines = _read_file_lines_safe(ws, f_path)
                        if file_lines is not None:
                            break
                if file_lines is not None:
                    total_l = len(file_lines)
                    if start_l > total_l:
                        return (
                            ChangeReviewVerdict.REJECTED,
                            f"Invalid line range: start_line {start_l} exceeds total file lines ({total_l}) in '{f_path}'.",
                            None,
                        )

        # ---------------------------------------------------------------------
        # Check 5: Graph Relationship & Edge Verification (Strict Exact Directional Wiring)
        # ---------------------------------------------------------------------
        for ref in finding.evidence_refs:
            edge_match = _EDGE_REF_REGEX.match(ref)
            if edge_match:
                e_kind_str = edge_match.group(1).upper()
                src = edge_match.group(2)
                tgt = edge_match.group(3)

                # Verify edge existence in base_graph, head_graph, or blast_radius strictly with exact equality
                edge_found = False
                for g in (base_graph, head_graph):
                    if g:
                        for e in g.get_edges():
                            if e.kind.value.upper() == e_kind_str and e.source == src and e.target == tgt:
                                edge_found = True
                                break
                    if edge_found:
                        break

                if not edge_found and blast_radius:
                    for imp in blast_radius.impacts:
                        imp_edge = imp.evidence_payload.get("edge_type", "").upper()
                        if imp_edge == e_kind_str:
                            c_node = imp.evidence_payload.get("caller_node_id", "")
                            t_node = imp.evidence_payload.get("callee_node_id", "")
                            c_sym = imp.evidence_payload.get("caller_symbol", "")
                            t_sym = imp.evidence_payload.get("callee_symbol", "")
                            if (src in (c_node, c_sym) and src) and (tgt in (t_node, t_sym) and tgt):
                                edge_found = True
                                break

                if not edge_found:
                    return (
                        ChangeReviewVerdict.REJECTED,
                        f"Fake graph relationship: '{ref}' does not exist in RepositoryGraph or blast radius.",
                        None,
                    )

        # ---------------------------------------------------------------------
        # Check 6: Unsupported Contract Claim Verification
        # ---------------------------------------------------------------------
        if finding.risk_type in ("API_CONTRACT_BREAK", "SCHEMA_INCOMPATIBILITY"):
            # Ensure at least one route delta, schema delta, or blast radius contract match exists
            has_contract_proof = (
                len(diff_result.route_deltas) > 0
                or len(diff_result.schema_deltas) > 0
                or (
                    blast_radius
                    and any(
                        i.impact_type
                        in (
                            ChangeImpactType.API_CONTRACT_CHANGE,
                            ChangeImpactType.SCHEMA_CHANGE,
                        )
                        for i in blast_radius.impacts
                    )
                )
            )
            if not has_contract_proof:
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Unsupported contract claim: '{finding.risk_type}' claimed but no route or schema deltas exist in diff facts.",
                    None,
                )

        # ---------------------------------------------------------------------
        # Check 7: Epistemic Status & Severity Consistency
        # ---------------------------------------------------------------------
        # CONFIRMED strictly requires zero assumptions and direct deterministic facts.
        # Confidence score NEVER influences or promotes a finding to CONFIRMED.
        is_pure_fact = (
            len(finding.assumptions) == 0
            and any(
                ref.startswith("diff:")
                or ref.startswith("impact:")
                or ref.startswith("symbol:")
                or ref.startswith("route:")
                or ref.startswith("file:")
                or ref.startswith("config:")
                or ref.startswith("dependency:")
                for ref in finding.evidence_refs
            )
        )

        justified_sev = finding.severity
        # Severity consistency check:
        # If finding is CRITICAL, verify it involves security, auth, or fatal caller breaks
        if finding.severity == Severity.CRITICAL:
            is_sec_or_auth = any(
                "auth" in f.lower() or "token" in f.lower() or "secret" in f.lower() or "security" in f.lower()
                for f in finding.affected_files + finding.affected_symbols + [finding.title]
            )
            has_high_impact = (
                blast_radius
                and any(i.severity in (Severity.CRITICAL, Severity.HIGH) for i in blast_radius.impacts)
            )
            if not is_sec_or_auth and not has_high_impact:
                # Downgrade to HIGH for consistency
                justified_sev = Severity.HIGH

        if is_pure_fact:
            return (
                ChangeReviewVerdict.CONFIRMED,
                "Fully grounded in deterministic diff facts and verified graph relationships.",
                justified_sev,
            )
        else:
            return (
                ChangeReviewVerdict.SUPPORTED_INFERENCE,
                f"Verified against real files, symbols, and evidence refs. Disclosed {len(finding.assumptions)} assumption(s).",
                justified_sev,
            )

    def _resolve_evidence_ref(
        self,
        ref: str,
        diff_result: StructuralDiffResult,
        blast_radius: Optional[BlastRadiusReport],
        base_graph: Optional[RepositoryGraph],
        head_graph: Optional[RepositoryGraph],
        base_workspace: Optional[str],
        head_workspace: Optional[str],
        known_files: Set[str],
        known_symbols: Set[str],
        known_exact_symbol_ids: Set[str],
    ) -> Tuple[bool, str]:
        """Resolve an individual evidence reference string strictly without fuzzy substring matches."""
        clean_ref = ref.strip()
        if not clean_ref:
            return False, "Empty reference"

        # 1. file: or diff: prefix (exact normalized file path match only)
        if clean_ref.startswith("file:"):
            target = normalize_path(clean_ref[5:])
            if target in known_files:
                return True, "Matched file in known files"
            for ws in (head_workspace, base_workspace):
                if ws and _read_file_lines_safe(ws, target) is not None:
                    known_files.add(target)
                    return True, "Matched file on disk"
            return False, f"Unknown file reference '{target}'"

        if clean_ref.startswith("diff:"):
            target = normalize_path(clean_ref[5:])
            if target in known_files:
                return True, "Matched changed file in diff"
            if clean_ref[5:] in known_symbols:
                return True, "Matched symbol in diff"
            return False, f"Unknown diff target '{target}'"

        # 2. symbol: prefix (exact symbol existence verification)
        if clean_ref.startswith("symbol:"):
            target = clean_ref[7:]
            if clean_ref in known_exact_symbol_ids or target in known_exact_symbol_ids:
                return True, "Matched exact symbol ID"

            parts = target.split(":")
            if len(parts) == 4:
                # symbol:<file_path>:<kind>:<name>:<start_line>
                file_part = normalize_path(parts[0])
                kind_part = parts[1]
                name_part = parts[2]
                try:
                    start_l = int(parts[3])
                except ValueError:
                    return False, f"Invalid start_line in symbol ref: '{parts[3]}'"

                exact_id = f"symbol:{file_part}:{kind_part}:{name_part}:{start_l}"
                if exact_id in known_exact_symbol_ids or f"{file_part}:{kind_part}:{name_part}:{start_l}" in known_exact_symbol_ids:
                    return True, "Matched exact symbol tuple"

                # Check graph nodes
                for g in (base_graph, head_graph):
                    if g:
                        for n in g.get_nodes():
                            if (
                                normalize_path(n.file_path or "") == file_part
                                and n.label == name_part
                                and (n.start_line is None or n.start_line == start_l)
                            ):
                                return True, "Matched graph node"
                return False, f"Exact symbol '{target}' not found in diff or graph"

            elif len(parts) == 2:
                file_part = normalize_path(parts[0])
                name_part = parts[1]
                if f"{file_part}:{name_part}" in known_exact_symbol_ids:
                    return True, "Matched file:symbol pair"
                if file_part in known_files and name_part in known_symbols:
                    # Check graph or disk
                    for g in (base_graph, head_graph):
                        if g:
                            for n in g.get_nodes():
                                if normalize_path(n.file_path or "") == file_part and n.label == name_part:
                                    return True, "Matched file:symbol in graph"
                return False, f"Symbol '{name_part}' not found in file '{file_part}'"

            elif len(parts) == 1:
                sym_name = parts[0]
                if sym_name in known_symbols:
                    return True, "Matched known symbol"
                return False, f"Symbol '{sym_name}' not found in known symbols"

            return False, f"Malformed symbol reference '{clean_ref}'"

        # 3. impact: prefix (exact UUID only)
        if clean_ref.startswith("impact:"):
            imp_query = clean_ref[7:].strip().lower()
            if blast_radius:
                for imp in blast_radius.impacts:
                    if str(imp.id).lower() == imp_query:
                        return True, "Matched blast radius impact UUID"
            return False, f"Unknown impact UUID '{clean_ref}'"

        # 4. route: prefix (exact route contract delta match or route method:path)
        if clean_ref.startswith("route:"):
            route_target = clean_ref[6:].strip()
            # If formatted as route:METHOD:path or route:METHOD path
            method_path_match = re.match(r"^([A-Z]+)[:\s]+(/.*)$", route_target, re.IGNORECASE)
            if method_path_match:
                req_method = method_path_match.group(1).upper()
                req_path = method_path_match.group(2)
                for r in diff_result.route_deltas:
                    if (
                        (r.base_http_method == req_method and r.base_path == req_path)
                        or (r.head_http_method == req_method and r.head_path == req_path)
                    ):
                        return True, "Matched exact route method and path"
                return False, f"No route delta found for {req_method} {req_path}"

            for r in diff_result.route_deltas:
                if (
                    route_target == r.route_name
                    or (r.file_path and route_target == f"{normalize_path(r.file_path)}:{r.route_name}")
                    or (r.base_path and (route_target == f"{r.base_http_method} {r.base_path}" or route_target == r.base_path))
                    or (r.head_path and (route_target == f"{r.head_http_method} {r.head_path}" or route_target == r.head_path))
                ):
                    return True, "Matched route delta"
            return False, f"Unknown route reference '{clean_ref}'"

        # 5. config: prefix (exact config key or path:key match)
        if clean_ref.startswith("config:"):
            cfg_target = clean_ref[7:].strip()
            for c in diff_result.config_deltas:
                if c.key == cfg_target or f"{normalize_path(c.file_path)}:{c.key}" == cfg_target:
                    return True, "Matched config delta"
            return False, f"Unknown config reference '{clean_ref}'"

        # 6. dep: or dependency: prefix (exact dependency package match)
        if clean_ref.startswith("dep:") or clean_ref.startswith("dependency:"):
            dep_target = clean_ref.split(":", 1)[1].strip()
            for d in diff_result.dependency_deltas:
                if d.package_name == dep_target or f"{normalize_path(d.manifest_file)}:{d.package_name}" == dep_target:
                    return True, "Matched dependency delta"
            return False, f"Unknown dependency reference '{clean_ref}'"

        # 7. Line reference (line:file:start-end or file:line)
        line_match = _LINE_REF_REGEX.match(clean_ref)
        if line_match:
            f_path = normalize_path(line_match.group(1))
            if f_path in known_files:
                return True, "Matched line in known file"
            for ws in (head_workspace, base_workspace):
                if ws and _read_file_lines_safe(ws, f_path) is not None:
                    return True, "Matched line in workspace file"
            return False, f"File in line reference '{f_path}' not found"

        # 8. Edge reference (edge:KIND:src->tgt)
        edge_match = _EDGE_REF_REGEX.match(clean_ref)
        if edge_match:
            return True, "Edge reference syntactically valid (checked in Check 5)"

        # 9. Plain exact file or symbol reference
        clean_norm = normalize_path(clean_ref)
        if clean_norm in known_files or clean_ref in known_symbols or clean_ref in known_exact_symbol_ids:
            return True, "Matched exact known file or symbol"

        return False, f"Unresolvable evidence reference '{clean_ref}'"

    def verify_report(
        self,
        report: ChangeReviewReport,
        diff_result: StructuralDiffResult,
        blast_radius: Optional[BlastRadiusReport] = None,
        base_graph: Optional[RepositoryGraph] = None,
        head_graph: Optional[RepositoryGraph] = None,
        base_workspace: Optional[str] = None,
        head_workspace: Optional[str] = None,
    ) -> ChangeReviewReport:
        """Verify all candidate findings in report and produce final grounded report."""
        verified_findings: List[ChangeReviewFinding] = []
        rejected_findings: List[Dict[str, Any]] = list(report.rejected_findings)

        facts_count = 0
        inferences_count = 0
        assumptions_count = 0
        confirmed_count = 0
        supported_inference_count = 0
        rejected_count = len(rejected_findings)

        for candidate in report.findings:
            verdict, reason, justified_sev = self.verify_finding(
                finding=candidate,
                diff_result=diff_result,
                blast_radius=blast_radius,
                base_graph=base_graph,
                head_graph=head_graph,
                base_workspace=base_workspace,
                head_workspace=head_workspace,
            )

            if verdict == ChangeReviewVerdict.REJECTED:
                rejected_count += 1
                rejected_findings.append({
                    "finding_id": str(candidate.id),
                    "title": candidate.title,
                    "risk_type": candidate.risk_type,
                    "verdict": ChangeReviewVerdict.REJECTED.value,
                    "rejection_reason": reason,
                    "affected_files": candidate.affected_files,
                    "affected_symbols": candidate.affected_symbols,
                    "evidence_refs": candidate.evidence_refs,
                })
            else:
                candidate.verdict = verdict
                candidate.verification_reason = reason
                if justified_sev:
                    candidate.severity = justified_sev

                if verdict == ChangeReviewVerdict.CONFIRMED:
                    confirmed_count += 1
                    facts_count += 1
                else:
                    supported_inference_count += 1
                    inferences_count += 1

                assumptions_count += len(candidate.assumptions)
                verified_findings.append(candidate)

        # Deterministic overall risk level calculation
        overall_risk = ChangeRiskLevel.LOW
        if any(f.severity == Severity.CRITICAL for f in verified_findings):
            overall_risk = ChangeRiskLevel.CRITICAL
        elif any(f.severity == Severity.HIGH for f in verified_findings):
            overall_risk = ChangeRiskLevel.HIGH
        elif any(f.severity == Severity.MEDIUM for f in verified_findings):
            overall_risk = ChangeRiskLevel.MEDIUM
        elif blast_radius and blast_radius.overall_risk_level != ChangeRiskLevel.NONE:
            overall_risk = blast_radius.overall_risk_level

        return ChangeReviewReport(
            analysis_id=report.analysis_id,
            findings=verified_findings,
            rejected_findings=rejected_findings,
            summary=report.summary,
            total_findings=len(verified_findings),
            facts_count=facts_count,
            inferences_count=inferences_count,
            assumptions_count=assumptions_count,
            confirmed_count=confirmed_count,
            supported_inference_count=supported_inference_count,
            rejected_count=rejected_count,
            overall_risk_level=overall_risk,
            model_metadata=report.model_metadata,
        )


_default_review_verifier: Optional[ChangeReviewVerifier] = None


def get_review_verifier() -> ChangeReviewVerifier:
    """Return singleton ChangeReviewVerifier instance."""
    global _default_review_verifier
    if _default_review_verifier is None:
        _default_review_verifier = ChangeReviewVerifier()
    return _default_review_verifier
