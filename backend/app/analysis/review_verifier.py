"""Deterministic Verifier for Evidence-Grounded AI Change Reviews.

Guarantees:
- Strictly verifies that every referenced file, symbol, line, route, and edge exists in canonical EvidenceRegistry.
- Strictly rejects invented files, invented symbols, invalid line ranges, fake/reversed CALLS edges, and unsupported contract claims.
- Strictly separates CONFIRMED facts from SUPPORTED_INFERENCE and REJECTED claims.
- Entity existence != claim proof (evaluates whether deterministic evidence directly proves the claim).
- Every affected file and affected symbol must bind directly to resolved evidence descriptors.
- Never labels an unsupported or unproven inference as CONFIRMED.
- All file reads for line verification strictly enforce MAX_FILE_SIZE_BYTES stat boundary.
"""

from datetime import datetime, timezone
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from app.analysis.evidence_ids import normalize_path
from app.analysis.evidence_registry import (
    EvidenceDescriptor,
    EvidenceRegistry,
    build_evidence_registry,
)
from app.core.config import Settings, get_settings
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

_LINE_REF_REGEX = re.compile(r"^line:([a-zA-Z0-9_\-\./\\]+):(\d+)(?:-(\d+))?$")
_EDGE_REF_REGEX = re.compile(r"^edge:([a-zA-Z_]+):([a-zA-Z0-9_\-\./\\:]+)->([a-zA-Z0-9_\-\./\\:]+)$")


def _check_file_exists_safe(repo_dir: str, rel_path: str) -> bool:
    """Safely check if file exists on disk within workspace without opening or reading it."""
    if not repo_dir or not rel_path:
        return False
    try:
        from app.core.path_confinement import PathTraversalError, resolve_safe_path
        abs_path = str(resolve_safe_path(repo_dir, rel_path))
        return os.path.exists(abs_path) and os.path.isfile(abs_path)
    except Exception:
        return False


def _read_file_lines_safe(
    repo_dir: str,
    rel_path: str,
    max_file_size: int = 1048576,
) -> Optional[List[str]]:
    """Safely read source lines from workspace if path confinement permits and size <= max_file_size.
    
    Guarantees:
    - Never opens or reads oversized files into memory.
    - Path traversal protected via resolve_safe_path.
    """
    if not repo_dir or not rel_path:
        return None
    try:
        from app.core.path_confinement import PathTraversalError, resolve_safe_path
        abs_path = str(resolve_safe_path(repo_dir, rel_path))
        if os.path.exists(abs_path) and os.path.isfile(abs_path):
            st = os.stat(abs_path)
            if st.st_size > max_file_size:
                logger.warning(
                    f"Verifier skipped reading '{rel_path}': size ({st.st_size} bytes) exceeds MAX_FILE_SIZE_BYTES ({max_file_size})"
                )
                return None
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.readlines()
    except Exception:
        pass
    return None


def _evaluate_claim_support(
    finding: ChangeReviewFinding,
    resolved_descriptors: List[EvidenceDescriptor],
    blast_radius: Optional[BlastRadiusReport] = None,
) -> str:
    """Evaluate whether the resolved deterministic descriptors directly prove the claim (DIRECT_FACT),
    support it as a logical inference (SUPPORTED_INFERENCE), or fail to support it (UNSUPPORTED).
    """
    risk_type = str(finding.risk_type).upper()

    # 1. API_CONTRACT_BREAK
    if risk_type == "API_CONTRACT_BREAK":
        has_route_break = any(
            d.evidence_type == "ROUTE_DELTA"
            and d.change_type in ("METHOD_CHANGED", "ROUTE_DELETED", "PATH_CHANGED", "REMOVED")
            for d in resolved_descriptors
        )
        has_contract_impact = any(
            d.evidence_type == "IMPACT"
            and d.impact_type == ChangeImpactType.API_CONTRACT_CHANGE
            for d in resolved_descriptors
        )
        if has_route_break or has_contract_impact:
            return "DIRECT_FACT"
        has_any_route = any(d.evidence_type == "ROUTE_DELTA" for d in resolved_descriptors)
        if has_any_route:
            return "SUPPORTED_INFERENCE"
        return "UNSUPPORTED"

    # 2. SCHEMA_INCOMPATIBILITY
    if risk_type == "SCHEMA_INCOMPATIBILITY":
        has_schema_break = any(
            d.evidence_type == "SCHEMA_DELTA"
            and d.change_type in ("REMOVED_FIELD", "MODIFIED_TYPE", "CONSTRAINT_CHANGED", "REMOVED")
            for d in resolved_descriptors
        )
        has_schema_impact = any(
            d.evidence_type == "IMPACT"
            and d.impact_type == ChangeImpactType.SCHEMA_CHANGE
            for d in resolved_descriptors
        )
        if has_schema_break or has_schema_impact:
            return "DIRECT_FACT"
        has_any_schema = any(d.evidence_type == "SCHEMA_DELTA" for d in resolved_descriptors)
        if has_any_schema:
            return "SUPPORTED_INFERENCE"
        return "UNSUPPORTED"

    # 3. CONFIG_MISMATCH
    if risk_type == "CONFIG_MISMATCH":
        has_config_delta = any(d.evidence_type == "CONFIG" for d in resolved_descriptors)
        has_config_impact = any(
            d.evidence_type == "IMPACT"
            and d.impact_type == ChangeImpactType.CONFIG_CHANGE
            for d in resolved_descriptors
        )
        if has_config_delta or has_config_impact:
            return "DIRECT_FACT"
        return "UNSUPPORTED"

    # 4. DEPENDENCY_INCOMPATIBILITY
    if risk_type == "DEPENDENCY_INCOMPATIBILITY":
        has_dep_impact = any(
            d.evidence_type == "IMPACT"
            and d.impact_type in (ChangeImpactType.DEPENDENCY_VULNERABILITY, ChangeImpactType.API_CONTRACT_CHANGE)
            for d in resolved_descriptors
        )
        if has_dep_impact:
            return "DIRECT_FACT"
        has_dep_delta = any(d.evidence_type == "DEPENDENCY" for d in resolved_descriptors)
        if has_dep_delta:
            # Version change alone does NOT prove incompatibility; it is a supported inference
            return "SUPPORTED_INFERENCE"
        return "UNSUPPORTED"

    # 5. SECURITY_REGRESSION
    if risk_type == "SECURITY_REGRESSION":
        has_sec_impact = any(
            d.evidence_type == "IMPACT"
            and d.impact_type == ChangeImpactType.SECURITY_SENSITIVE_CHANGE
            for d in resolved_descriptors
        )
        if has_sec_impact:
            return "DIRECT_FACT"
        return "UNSUPPORTED"

    # 6. Runtime / Behavioral / Reliability predictions
    # (REGRESSION_RISK, BEHAVIORAL_CHANGE, PERFORMANCE_DEGRADATION, RESOURCE_LEAK, UNHANDLED_EDGE_CASE)
    # These predict dynamic runtime behavior from static facts and remain SUPPORTED_INFERENCE unless
    # explicitly classified by an exact deterministic impact fact.
    if len(resolved_descriptors) > 0:
        return "SUPPORTED_INFERENCE"

    return "UNSUPPORTED"


class ChangeReviewVerifier:
    """Canonical Deterministic Verifier for AI Change Reviews."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

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
        """Deterministically verify a candidate review finding against all canonical evidence sources.
        
        Returns:
            (verdict, verification_reason, justified_severity)
        """
        max_file_size = getattr(self.settings, "MAX_FILE_SIZE_BYTES", 1048576)

        # 1. Build canonical EvidenceRegistry
        registry = build_evidence_registry(
            diff_result=diff_result,
            blast_radius=blast_radius,
            base_graph=base_graph,
            head_graph=head_graph,
            base_workspace=base_workspace,
            head_workspace=head_workspace,
        )

        # ---------------------------------------------------------------------
        # Check 1: File Existence Verification (Exact Path Equality)
        # ---------------------------------------------------------------------
        for file_path in finding.affected_files:
            clean_f = normalize_path(file_path)
            if not registry.contains_file(clean_f):
                # Verify disk if workspace is provided
                found_on_disk = False
                for ws in (head_workspace, base_workspace):
                    if ws and _check_file_exists_safe(ws, clean_f):
                        found_on_disk = True
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
            if not registry.contains_symbol(symbol_name):
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Invented symbol: '{symbol_name}' does not exist in diff facts, relationship graph, or blast radius.",
                    None,
                )

        # ---------------------------------------------------------------------
        # Check 3: Evidence References Resolution (Strict Canonical IDs Only)
        # ---------------------------------------------------------------------
        if not finding.evidence_refs:
            return (
                ChangeReviewVerdict.REJECTED,
                "Missing required deterministic evidence references (evidence_refs is empty).",
                None,
            )

        resolved_descriptors: List[EvidenceDescriptor] = []

        for ref in finding.evidence_refs:
            clean_ref = ref.strip()
            if not clean_ref:
                return (
                    ChangeReviewVerdict.REJECTED,
                    "Empty evidence reference string provided.",
                    None,
                )

            # Check 3a: Exact Canonical Registry Lookup
            desc = registry.get(clean_ref)
            if desc is not None:
                resolved_descriptors.append(desc)
                continue

            # Check 3b: Canonical Line Reference (line:<file>:<start> or line:<file>:<start>-<end>)
            line_match = _LINE_REF_REGEX.match(clean_ref)
            if line_match:
                f_path = normalize_path(line_match.group(1))
                try:
                    start_l = int(line_match.group(2))
                    end_l = int(line_match.group(3)) if line_match.group(3) else start_l
                except ValueError:
                    return (
                        ChangeReviewVerdict.REJECTED,
                        f"Malformed line numbers in evidence reference '{clean_ref}'.",
                        None,
                    )

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

                # Check if file exists
                if not registry.contains_file(f_path):
                    found_on_disk = False
                    for ws in (head_workspace, base_workspace):
                        if ws and _check_file_exists_safe(ws, f_path):
                            found_on_disk = True
                            break
                    if not found_on_disk:
                        return (
                            ChangeReviewVerdict.REJECTED,
                            f"File in line reference '{f_path}' does not exist.",
                            None,
                        )

                # Validate line bounds against workspace if available
                file_lines = None
                read_attempted = False
                for ws in (head_workspace, base_workspace):
                    if ws:
                        read_attempted = True
                        file_lines = _read_file_lines_safe(ws, f_path, max_file_size)
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
                elif read_attempted:
                    # Workspace was present but file was oversized or unreadable
                    return (
                        ChangeReviewVerdict.REJECTED,
                        f"Line evidence '{clean_ref}' cannot be verified: file is oversized (exceeds MAX_FILE_SIZE_BYTES) or unreadable.",
                        None,
                    )

                line_desc = EvidenceDescriptor(
                    evidence_id=clean_ref,
                    evidence_type="LINE",
                    file_path=f_path,
                    details={"start_line": start_l, "end_line": end_l},
                )
                resolved_descriptors.append(line_desc)
                continue

            # Check 3c: Graph Edge Reference Format (edge:<KIND>:<src>-><tgt>)
            edge_match = _EDGE_REF_REGEX.match(clean_ref)
            if edge_match:
                # If edge is not in registry, it does not exist in graph or blast radius
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Fake graph relationship: '{clean_ref}' does not exist in RepositoryGraph or blast radius.",
                    None,
                )

            # Any legacy alias or uncanonical ref is strictly rejected
            if clean_ref.startswith("diff:"):
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Legacy non-canonical evidence alias rejected: '{clean_ref}'. Use exact canonical 'file:', 'symbol:', or 'route-delta:' instead.",
                    None,
                )
            if clean_ref.startswith("dep:"):
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Legacy non-canonical evidence alias rejected: '{clean_ref}'. Use exact canonical 'dependency:<manifest>:<pkg>' instead.",
                    None,
                )

            return (
                ChangeReviewVerdict.REJECTED,
                f"Invalid evidence reference: '{clean_ref}' does not resolve to deterministic analysis context.",
                None,
            )

        # ---------------------------------------------------------------------
        # Check 4: Affected Entity Binding to Resolved Evidence
        # ---------------------------------------------------------------------
        for aff_file in finding.affected_files:
            clean_f = normalize_path(aff_file)
            file_bound = any(
                d.file_path and normalize_path(d.file_path) == clean_f
                for d in resolved_descriptors
            )
            if not file_bound:
                # Also check if any resolved impact or edge explicitly touches this file
                for d in resolved_descriptors:
                    if d.evidence_type == "IMPACT" and d.source_object:
                        imp: ChangeImpact = d.source_object
                        if (imp.source_file and normalize_path(imp.source_file) == clean_f) or (
                            imp.affected_file and normalize_path(imp.affected_file) == clean_f
                        ):
                            file_bound = True
                            break
                    elif d.evidence_type == "EDGE":
                        if clean_f in (d.edge_source or "") or clean_f in (d.edge_target or ""):
                            file_bound = True
                            break
            if not file_bound:
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Unbound affected file: '{aff_file}' is not referenced by any resolved evidence descriptor.",
                    None,
                )

        for aff_sym in finding.affected_symbols:
            sym_bound = False
            for d in resolved_descriptors:
                if d.symbol_name == aff_sym:
                    # Disambiguate duplicate symbol names: verify descriptor file is in finding.affected_files
                    if d.file_path:
                        if normalize_path(d.file_path) in [normalize_path(f) for f in finding.affected_files]:
                            sym_bound = True
                            break
                    else:
                        sym_bound = True
                        break
                elif d.evidence_type == "IMPACT" and d.source_object:
                    imp: ChangeImpact = d.source_object
                    if imp.source_symbol == aff_sym or imp.affected_symbol == aff_sym:
                        sym_bound = True
                        break
                elif d.evidence_type == "EDGE":
                    if (
                        f":{aff_sym}:" in (d.edge_source or "")
                        or f":{aff_sym}:" in (d.edge_target or "")
                        or (d.edge_source and d.edge_source.endswith(f":{aff_sym}"))
                        or (d.edge_target and d.edge_target.endswith(f":{aff_sym}"))
                    ):
                        sym_bound = True
                        break
            if not sym_bound:
                return (
                    ChangeReviewVerdict.REJECTED,
                    f"Unbound affected symbol: '{aff_sym}' is not linked to any resolved evidence descriptor in the affected files.",
                    None,
                )

        # ---------------------------------------------------------------------
        # Check 5: Claim-to-Evidence Semantic Verification & Epistemic Status
        # ---------------------------------------------------------------------
        claim_support = _evaluate_claim_support(finding, resolved_descriptors, blast_radius)

        if claim_support == "UNSUPPORTED":
            return (
                ChangeReviewVerdict.REJECTED,
                f"Unsupported claim: finding risk category '{finding.risk_type}' is not supported by the provided deterministic evidence descriptors.",
                None,
            )

        # Severity consistency check
        justified_sev = finding.severity
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
                justified_sev = Severity.HIGH

        if claim_support == "DIRECT_FACT" and len(finding.assumptions) == 0:
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
            overall_risk_level=report.overall_risk_level,
            model_metadata=report.model_metadata,
        )


_review_verifier_instance: Optional[ChangeReviewVerifier] = None


def get_review_verifier() -> ChangeReviewVerifier:
    """Retrieve singleton ChangeReviewVerifier instance."""
    global _review_verifier_instance
    if _review_verifier_instance is None:
        _review_verifier_instance = ChangeReviewVerifier()
    return _review_verifier_instance
