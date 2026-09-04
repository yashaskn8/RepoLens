"""Canonical ScanReportService for building, securing, and rendering evidence-grounded reports."""

from datetime import datetime, timezone
import html
import json
import logging
import re
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.delivery import DeliveryModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import DeliveryStatus
from app.schemas.report import (
    ReportAnalysisScope,
    ReportDelivery,
    ReportEvidence,
    ReportFinding,
    ReportPatch,
    ReportScannerCoverage,
    ReportSummary,
    ReportWorkflowEvent,
    ScanReport,
)
from app.schemas.telemetry import ScanTelemetry
from app.security.redaction import redact_secrets
from app.services.finding_grounding import is_canonical_confirmed_finding

logger = logging.getLogger(__name__)

# Canonical secret redaction alias
_redact_secrets = redact_secrets


def _attestation_fields(notes: Any) -> dict[str, Any]:
    """Project only machine-verifiable fields from grounding notes."""
    if not isinstance(notes, str):
        return {}
    try:
        value = json.loads(notes)
    except (TypeError, ValueError):
        return {}
    if not isinstance(value, dict) or value.get("schema_version") != "repository-evidence/1.0":
        return {}
    fields = {
        "commit_sha": value.get("commit_sha"),
        "file_sha256": value.get("file_sha256"),
        "snippet_sha256": value.get("snippet_sha256"),
    }
    if (
        not isinstance(fields["commit_sha"], str)
        or not re.fullmatch(r"[0-9a-fA-F]{40}", fields["commit_sha"])
        or not isinstance(fields["file_sha256"], str)
        or not re.fullmatch(r"[0-9a-fA-F]{64}", fields["file_sha256"])
        or not isinstance(fields["snippet_sha256"], str)
        or not re.fullmatch(r"[0-9a-fA-F]{64}", fields["snippet_sha256"])
    ):
        return {}
    return fields


def _normalize_count(value: Any) -> Optional[int]:
    """Safely normalize a metadata value to an integer count.

    Handles the canonical shapes persisted by LLMRouter:
    - None -> None (no recorded metric)
    - int -> that count
    - list/tuple -> len(value) (e.g. fallbacks_attempted stores a list of error records)
    - other invalid value -> None (ignore safely, do not crash)
    """
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple)):
        return len(value)
    # Unsupported type — do not crash, do not fabricate
    return None


def _safe_nonnegative_int(value: Any) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, normalized)


def _finding_provenance(metadata: Any) -> dict[str, Any]:
    """Read provenance from both legacy and structured model metadata."""
    if not isinstance(metadata, dict):
        return {}
    direct = metadata.get("provenance")
    if isinstance(direct, dict):
        return direct
    extra = metadata.get("extra_metadata")
    if isinstance(extra, dict) and isinstance(extra.get("provenance"), dict):
        return extra["provenance"]
    return {}


from app.security.markdown import (
    escape_markdown_text,
    escape_table_cell,
    safe_fenced_block,
    safe_inline_code,
)

# Canonical aliases for internal references
_escape_markdown_text = escape_markdown_text
_escape_table_cell = escape_table_cell
_safe_inline_code = safe_inline_code
_safe_fenced_block = safe_fenced_block


class ScanReportService:
    """Service to assemble comprehensive evidence reports and render them as Markdown or JSON."""

    @staticmethod
    def build_scan_report(db: Session, scan_id: str) -> Optional[ScanReport]:
        """Assemble structured, evidence-grounded ScanReport from database models."""
        scan = db.query(ScanModel).filter(ScanModel.id == str(scan_id)).first()
        if not scan:
            return None

        all_finding_models = db.query(FindingModel).filter(FindingModel.scan_id == str(scan_id)).all()
        all_patch_models = db.query(PatchModel).filter(PatchModel.scan_id == str(scan_id)).all()
        all_delivery_models = db.query(DeliveryModel).filter(DeliveryModel.scan_id == str(scan_id)).all()
        canonical_finding_models = [
            finding
            for finding in all_finding_models
            if is_canonical_confirmed_finding(
                finding,
                expected_commit_sha=scan.commit_hash or "__missing_commit__",
            )
        ]
        canonical_finding_ids = {finding.id for finding in canonical_finding_models}
        delivered_patch_ids = {delivery.patch_id for delivery in all_delivery_models}
        delivered_finding_ids = {
            patch.finding_id
            for patch in all_patch_models
            if patch.id in delivered_patch_ids
        }
        # A persisted delivery is an authoritative audit event even when its
        # legacy/synthetic finding lacks deterministic evidence. Project that
        # finding as explicitly unverified, but never count it as canonical or
        # let it elevate a model hypothesis into verified truth.
        delivery_audit_finding_ids = {
            finding.id
            for finding in all_finding_models
            if finding.id in delivered_finding_ids
            and finding.id not in canonical_finding_ids
            and str(finding.verification_verdict or "").upper() == "CONFIRMED"
        }
        finding_models = [
            finding
            for finding in all_finding_models
            if finding.id in canonical_finding_ids or finding.id in delivery_audit_finding_ids
        ]
        meta = scan.model_metadata or {}
        verification_summary = meta.get("verification_summary") if isinstance(meta, dict) else {}
        recorded_excluded = (
            verification_summary.get("excluded_noncanonical_findings", 0)
            if isinstance(verification_summary, dict)
            else 0
        )
        if not isinstance(recorded_excluded, int) or isinstance(recorded_excluded, bool):
            recorded_excluded = 0
        excluded_noncanonical_findings = max(0, recorded_excluded) + (
            len(all_finding_models) - len(canonical_finding_models)
        )
        patch_models = [
            patch
            for patch in all_patch_models
            if patch.finding_id in canonical_finding_ids or patch.id in delivered_patch_ids
        ]
        report_patch_ids = {patch.id for patch in patch_models}
        delivery_models = [
            delivery for delivery in all_delivery_models if delivery.patch_id in report_patch_ids
        ]
        event_models = (
            db.query(WorkflowEventModel)
            .filter(WorkflowEventModel.scan_id == str(scan_id))
            .order_by(WorkflowEventModel.id.asc())
            .all()
        )

        # Index deliveries by patch_id
        deliveries_by_patch: Dict[str, List[ReportDelivery]] = {}
        for dm in delivery_models:
            rd = ReportDelivery(
                delivery_id=dm.id,
                status=dm.status,
                provider=dm.provider,
                repository=f"{dm.repository_owner}/{dm.repository_name}",
                base_branch=dm.base_branch,
                scanned_base_sha=dm.scanned_base_sha,
                observed_base_sha=dm.observed_base_sha,
                head_branch=dm.head_branch,
                head_sha=dm.head_sha,
                pr_number=dm.pr_number,
                pr_url=dm.pr_url,
                failure_code=dm.failure_code,
                completed_at=dm.completed_at,
            )
            deliveries_by_patch.setdefault(dm.patch_id, []).append(rd)

        # Index patches by finding_id with secret-sanitized content
        patches_by_finding: Dict[str, List[ReportPatch]] = {}
        for pm in patch_models:
            rp = ReportPatch(
                id=pm.id,
                finding_id=pm.finding_id,
                plan_id=pm.plan_id,
                parent_patch_id=pm.parent_patch_id,
                revision_number=pm.revision_number or 0,
                status=pm.status,
                machine_verdict=pm.machine_verdict,
                unified_diff=_redact_secrets(pm.unified_diff),
                files_modified=pm.files_modified or [],
                explanation=_redact_secrets(pm.explanation),
                expected_behavior_change=_redact_secrets(pm.expected_behavior_change),
                approved_by=pm.approved_by,
                approved_at=pm.approved_at,
                rejected_reason=_redact_secrets(pm.rejected_reason) if pm.rejected_reason else None,
                user_feedback=_redact_secrets(pm.user_feedback) if pm.user_feedback else None,
                deliveries=deliveries_by_patch.get(pm.id, []),
                created_at=pm.created_at,
            )
            patches_by_finding.setdefault(pm.finding_id, []).append(rp)

        # Build findings list with secret-sanitized content
        report_findings: List[ReportFinding] = []
        for fm in finding_models:
            provenance = _finding_provenance(fm.model_metadata)
            evidences = []
            for em in fm.evidences:
                attestation = _attestation_fields(em.context_notes)
                evidences.append(
                    ReportEvidence(
                        id=em.id,
                        file_path=em.file_path,
                        start_line=em.start_line,
                        end_line=em.end_line,
                        code_snippet=_redact_secrets(em.code_snippet) if em.code_snippet else None,
                        context_notes=_redact_secrets(em.context_notes) if em.context_notes else None,
                        verification_status=(
                            "VERIFIED_SOURCE_BYTES" if attestation else "UNVERIFIED"
                        ),
                        **attestation,
                    )
                )
            rf = ReportFinding(
                id=fm.id,
                title=_redact_secrets(fm.title),
                description=_redact_secrets(fm.description),
                severity=fm.severity,
                status=fm.status,
                rule_id=fm.rule_id,
                category=fm.category,
                mitigation_guidance=_redact_secrets(fm.mitigation_guidance) if fm.mitigation_guidance else None,
                verification_verdict=fm.verification_verdict,
                verification_reason=_redact_secrets(fm.verification_reason) if fm.verification_reason else None,
                source_tool=fm.source_tool,
                detector_id=fm.detector_id,
                grounding_status=(
                    "GROUNDED" if fm.id in canonical_finding_ids else "DELIVERY_AUDIT_UNVERIFIED"
                ),
                evidences=evidences,
                patches=patches_by_finding.get(fm.id, []),
                created_at=fm.created_at,
                claim_class=(
                    "VERIFIED_REUSED_FINDING"
                    if provenance.get("reuse_type") in {"exact", "incremental"}
                    else ("VERIFIED_FINDING" if fm.id in canonical_finding_ids else "LIMITATION")
                ),
                provenance=provenance,
            )
            report_findings.append(rf)

        # Build summary metrics
        summary = ReportSummary(
            total_findings=len(canonical_finding_models),
            critical_findings=sum(1 for f in canonical_finding_models if f.severity == "CRITICAL"),
            high_findings=sum(1 for f in canonical_finding_models if f.severity == "HIGH"),
            medium_findings=sum(1 for f in canonical_finding_models if f.severity == "MEDIUM"),
            low_findings=sum(1 for f in canonical_finding_models if f.severity == "LOW"),
            confirmed_findings=sum(1 for f in canonical_finding_models if f.verification_verdict == "CONFIRMED"),
            excluded_noncanonical_findings=excluded_noncanonical_findings,
            total_patches=len(patch_models),
            approved_patches=sum(1 for p in patch_models if p.status == "APPROVED"),
            rejected_patches=sum(1 for p in patch_models if p.status == "REJECTED"),
            revised_patches=sum(1 for p in patch_models if (p.revision_number or 0) > 0),
            total_deliveries=len(delivery_models),
            pull_requests_created=sum(1 for d in delivery_models if d.status == DeliveryStatus.PR_CREATED.value),
            deliveries_blocked=sum(1 for d in delivery_models if d.status == DeliveryStatus.BLOCKED.value),
            delivery_failures=sum(1 for d in delivery_models if d.status == DeliveryStatus.FAILED.value),
        )

        # Build events audit trail
        events_audit = [
            ReportWorkflowEvent(
                id=e.id,
                event_type=e.event_type,
                stage=e.stage,
                tool_name=e.tool_name,
                message=_redact_secrets(e.message) if e.message else None,
                created_at=e.created_at,
            )
            for e in event_models
        ]

        req_branch = meta.get("requested_branch") if isinstance(meta, dict) else None
        res_branch = meta.get("resolved_branch_or_ref") if isinstance(meta, dict) else None
        arch_overview = _redact_secrets(meta.get("architecture_overview")) if isinstance(meta, dict) and meta.get("architecture_overview") else None
        languages = meta.get("languages") if isinstance(meta, dict) and isinstance(meta.get("languages"), dict) else {}
        frameworks = meta.get("frameworks") if isinstance(meta, dict) and isinstance(meta.get("frameworks"), list) else []

        # Analysis scope
        scope_meta = meta.get("analysis_scope") or meta.get("scope") or {}
        analysis_scope: Optional[ReportAnalysisScope] = None
        if isinstance(scope_meta, dict) and scope_meta:
            analysis_scope = ReportAnalysisScope(
                truncated=bool(scope_meta.get("truncated", False)),
                reason=_redact_secrets(scope_meta.get("reason")) if scope_meta.get("reason") else None,
                files_processed=scope_meta.get("files_processed", 0),
                source_bytes_processed=scope_meta.get("source_bytes_processed", 0),
                total_observed_files=scope_meta.get("total_observed_files", 0),
                total_observed_bytes=scope_meta.get("total_observed_bytes", 0),
            )

        # Scanner coverage
        scanner_coverage: List[ReportScannerCoverage] = []
        raw_scanners = meta.get("scanner_coverage") or meta.get("scanners") or []
        if isinstance(raw_scanners, list) and raw_scanners:
            for sc in raw_scanners:
                if isinstance(sc, dict):
                    raw_reason = sc.get("failure_reason") or sc.get("error_category")
                    safe_reason = _redact_secrets(str(raw_reason))[:512] if raw_reason is not None else None
                    raw_tool = sc.get("tool") or sc.get("scanner") or "unknown"
                    safe_tool = _redact_secrets(str(raw_tool))[:128]
                    scanner_coverage.append(
                        ReportScannerCoverage(
                            tool=safe_tool,
                            status=str(sc.get("status") or "UNKNOWN"),
                            findings_count=_safe_nonnegative_int(sc.get("findings_count", 0)),
                            execution_time_ms=sc.get("execution_time_ms"),
                            failure_reason=safe_reason,
                        )
                    )
        else:
            tool_events = [e for e in event_models if e.event_type in ("TOOL_COMPLETED", "TOOL_FAILED", "TOOL_UNAVAILABLE") and e.tool_name]
            seen_tools = set()
            for te in tool_events:
                if te.tool_name not in seen_tools:
                    seen_tools.add(te.tool_name)
                    st = "COMPLETED" if te.event_type == "TOOL_COMPLETED" else ("UNAVAILABLE" if te.event_type == "TOOL_UNAVAILABLE" else "FAILED")
                    fc = _safe_nonnegative_int((te.metadata_payload or {}).get("findings_count", 0))
                    et = (te.metadata_payload or {}).get("execution_time_ms")
                    raw_reason = (te.metadata_payload or {}).get("reason") or (te.metadata_payload or {}).get("status")
                    safe_reason = _redact_secrets(str(raw_reason))[:512] if raw_reason is not None and st != "COMPLETED" else None
                    scanner_coverage.append(
                        ReportScannerCoverage(
                            tool=_redact_secrets(str(te.tool_name))[:128],
                            status=st,
                            findings_count=fc,
                            execution_time_ms=et,
                            failure_reason=safe_reason,
                        )
                    )

        graph_coverage = meta.get("graph_coverage") if isinstance(meta.get("graph_coverage"), dict) else {}
        route_contract_coverage = meta.get("route_contract_coverage") if isinstance(meta.get("route_contract_coverage"), dict) else {}
        ai_admission = meta.get("ai_admission") if isinstance(meta.get("ai_admission"), dict) else {}
        ai_economy = meta.get("ai_cloud_budget") if isinstance(meta.get("ai_cloud_budget"), dict) else {}
        uncertainty: list[str] = []
        if any(str(row.status).upper() in {"UNAVAILABLE", "FAILED", "TIMEOUT", "INVALID_OUTPUT"} for row in scanner_coverage):
            uncertainty.append("One or more deterministic scanners were unavailable or failed; zero findings is not inferred.")
        if graph_coverage.get("status") == "PARTIAL":
            uncertainty.append("Repository graph coverage is partial; unresolved relationships remain unanalyzed.")
        elif graph_coverage.get("status") == "UNAVAILABLE":
            uncertainty.append("Repository graph extraction was unavailable; architecture relationships were not analyzed.")
        if not scanner_coverage:
            uncertainty.append("Deterministic scanner coverage was not recorded; zero findings is not inferred.")
        if isinstance(meta, dict) and meta.get("source_evidence_available") is False:
            uncertainty.append("Source evidence was unavailable; model-derived absence claims are not made.")
        if excluded_noncanonical_findings:
            uncertainty.append(f"{excluded_noncanonical_findings} candidate finding(s) were excluded from canonical verified results.")

        return ScanReport(
            scan_id=scan.id,
            repository_url=scan.repository_url,
            requested_branch=req_branch,
            resolved_branch=res_branch or scan.branch,
            commit_sha=scan.commit_hash,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            architecture_overview=arch_overview,
            languages=languages,
            frameworks=frameworks,
            analysis_scope=analysis_scope,
            scanner_coverage=scanner_coverage,
            summary=summary,
            findings=report_findings,
            events_audit_trail=events_audit,
            analysis_version=(meta.get("analysis_authority_fingerprint") or meta.get("analysis_version")),
            graph_coverage=graph_coverage,
            route_contract_coverage=route_contract_coverage,
            ai_admission=ai_admission,
            ai_economy=ai_economy,
            uncertainty=uncertainty,
        )

    @staticmethod
    def render_markdown(report: ScanReport) -> str:
        """Render a full GFM Markdown report with tables, evidence snippets, diffs, and audit trail."""
        lines: List[str] = []

        # Title & Metadata Header
        lines.append("# RepoLens Evidence & Intelligence Report")
        lines.append("")
        lines.append(f"**Scan ID**: {_safe_inline_code(report.scan_id)}  ")
        lines.append(f"**Repository**: [{report.repository_url}]({report.repository_url})  ")
        lines.append(f"**Commit SHA**: {_safe_inline_code(report.commit_sha or 'N/A')}  ")
        lines.append(f"**Branch**: {_safe_inline_code(report.resolved_branch or report.requested_branch or 'default')}  ")
        lines.append(f"**Status**: {_safe_inline_code(report.status)}  ")
        lines.append(f"**Generated At**: {_safe_inline_code(datetime.now(timezone.utc).isoformat())}  ")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Truth and economy metadata are deterministic projections, never AI
        # narrative.  Empty values remain explicitly absent.
        lines.append("## Analysis Truth & Economy")
        lines.append("")
        lines.append(f"- **Truth Contract**: {_escape_markdown_text(report.truth_contract)}")
        if report.analysis_version:
            lines.append(f"- **Analysis Authority**: {_safe_inline_code(report.analysis_version)}")
        if report.graph_coverage:
            lines.append(f"- **Graph Coverage**: {_escape_markdown_text(json.dumps(report.graph_coverage, sort_keys=True))}")
        if report.ai_economy:
            lines.append(f"- **Cloud Budget**: {_escape_markdown_text(json.dumps(report.ai_economy, sort_keys=True))}")
        if report.ai_admission:
            decisions = ", ".join(
                f"{name}={value.get('decision', 'UNKNOWN')}"
                for name, value in sorted(report.ai_admission.items())
                if isinstance(value, dict)
            )
            if decisions:
                lines.append(f"- **AI Admission**: {_escape_markdown_text(decisions)}")
        if report.uncertainty:
            lines.append("- **Limitations**:")
            lines.extend(f"  - {_escape_markdown_text(item)}" for item in report.uncertainty)
        lines.append("")

        # Executive Summary Table
        lines.append("## Executive Summary")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("| :--- | :--- |")
        lines.append(f"| **Total Canonical Findings** | {report.summary.total_findings} |")
        lines.append(f"| 🔴 Critical Severity | {report.summary.critical_findings} |")
        lines.append(f"| 🟠 High Severity | {report.summary.high_findings} |")
        lines.append(f"| 🟡 Medium Severity | {report.summary.medium_findings} |")
        lines.append(f"| 🔵 Low Severity | {report.summary.low_findings} |")
        lines.append(f"| ✅ Confirmed Grounded Findings | {report.summary.confirmed_findings} |")
        if report.summary.excluded_noncanonical_findings > 0:
            lines.append(
                f"| ⚠️ Excluded Unverified / Ungrounded Candidates | "
                f"{report.summary.excluded_noncanonical_findings} |"
            )
        lines.append(f"| 🛡️ Total Generated Patches | {report.summary.total_patches} |")
        lines.append(f"| 👤 Approved Patches | {report.summary.approved_patches} |")
        lines.append(f"| ❌ Rejected Patches | {report.summary.rejected_patches} |")
        lines.append(f"| 🔄 Child Revisions | {report.summary.revised_patches} |")
        lines.append(f"| 🚀 GitHub PRs Created | {report.summary.pull_requests_created} |")
        if report.summary.deliveries_blocked > 0:
            lines.append(f"| ⚠️ Blocked Deliveries (Base Drift) | {report.summary.deliveries_blocked} |")
        lines.append("")

        # Analysis Scope & Ingestion Coverage
        if report.analysis_scope:
            lines.append("## Analysis Scope & Ingestion Boundary")
            lines.append("")
            trunc_label = "**YES** ⚠️" if report.analysis_scope.truncated else "NO (Full Analysis)"
            lines.append(f"- **Analysis Truncated**: {trunc_label}")
            if report.analysis_scope.truncated and report.analysis_scope.reason:
                lines.append(f"- **Truncation Reason**: {_escape_markdown_text(report.analysis_scope.reason)}")
            lines.append(f"- **Files Processed**: {report.analysis_scope.files_processed} / {report.analysis_scope.total_observed_files} observed")
            lines.append(f"- **Source Bytes Processed**: {report.analysis_scope.source_bytes_processed:,} / {report.analysis_scope.total_observed_bytes:,} observed bytes")
            lines.append("")

        # Deterministic Scanner Coverage Table
        if report.scanner_coverage:
            lines.append(f"## Deterministic Scanner Coverage ({len(report.scanner_coverage)} tools)")
            lines.append("")
            lines.append("| Scanner | Status | Findings | Execution Time | Notes |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for sc in report.scanner_coverage:
                exec_time = f"{sc.execution_time_ms}ms" if sc.execution_time_ms is not None else "-"
                notes = _escape_table_cell(sc.failure_reason) if sc.failure_reason else "-"
                lines.append(f"| {_escape_table_cell(sc.tool)} | {_safe_inline_code(sc.status)} | {sc.findings_count} | {exec_time} | {notes} |")
            lines.append("")

        # Repository Architecture & Stack
        if report.architecture_overview or report.languages or report.frameworks:
            lines.append("## Repository Architecture & Stack")
            lines.append("")
            if report.architecture_overview:
                lines.append(f"{_escape_markdown_text(report.architecture_overview)}")
                lines.append("")
            if report.languages:
                lang_str = ", ".join(f"`{k}` ({v} files)" for k, v in report.languages.items())
                lines.append(f"**Languages Detected**: {lang_str}  ")
            if report.frameworks:
                fw_str = ", ".join(f"`{f}`" for f in report.frameworks)
                lines.append(f"**Frameworks Detected**: {fw_str}  ")
            lines.append("")

        # Detailed Findings & Evidences
        lines.append(f"## Findings & Delivery Audit ({len(report.findings)})")
        lines.append("")
        if not report.findings:
            lines.append("*No confirmed findings were produced within the executed analysis coverage.*")
            if report.uncertainty:
                lines.append("*This is not a claim that the repository is secure; see Analysis Truth & Economy for coverage limitations.*")
            lines.append("")
        else:
            for idx, f in enumerate(report.findings, start=1):
                escaped_title = _escape_markdown_text(f.title)
                lines.append(f"### {idx}. [{f.severity}] {escaped_title}")
                lines.append("")
                lines.append(f"- **Finding ID**: {_safe_inline_code(f.id)}")
                lines.append(f"- **Category**: {_safe_inline_code(f.category or 'General')}")
                if f.grounding_status != "GROUNDED":
                    lines.append(
                        "- **Grounding**: Delivery audit only; this finding is excluded from canonical verified counts."
                    )
                if f.rule_id:
                    lines.append(f"- **Rule ID**: {_safe_inline_code(f.rule_id)}")
                if f.source_tool:
                    lines.append(f"- **Detector / Source**: {_safe_inline_code(f.source_tool)} ({_safe_inline_code(f.detector_id or 'default')})")
                lines.append(f"- **Verdict**: {_safe_inline_code(f.verification_verdict or 'N/A')}")
                lines.append(f"- **Truth Class**: {_safe_inline_code(f.claim_class)}")
                if f.provenance:
                    lines.append(f"- **Provenance**: {_escape_markdown_text(json.dumps(f.provenance, sort_keys=True))}")
                if f.verification_reason:
                    lines.append(f"- **Verdict Reason**: {_escape_markdown_text(f.verification_reason)}")
                lines.append("")
                lines.append("**Description**:")
                lines.append(f"{_escape_markdown_text(f.description)}")
                lines.append("")

                if f.mitigation_guidance:
                    lines.append("**Mitigation Guidance**:")
                    lines.append(f"{_escape_markdown_text(f.mitigation_guidance)}")
                    lines.append("")

                # Grounded Evidences
                if f.evidences:
                    lines.append(f"**Source Evidences** ({len(f.evidences)}):")
                    lines.append("")
                    for ev in f.evidences:
                        lines.append(f"📁 {_safe_inline_code(ev.file_path)} (lines {ev.start_line or '?'}-{ev.end_line or '?'})")
                        if ev.context_notes:
                            lines.append(f"> {_escape_markdown_text(ev.context_notes)}")
                        if ev.code_snippet:
                            lines.append(_safe_fenced_block(ev.code_snippet))
                        lines.append("")

                # Associated Patches
                if f.patches:
                    lines.append(f"**Generated Remediation Patches** ({len(f.patches)}):")
                    lines.append("")
                    for p in f.patches:
                        rev_label = f" (Revision #{p.revision_number})" if p.revision_number > 0 else ""
                        lines.append(f"#### Patch {_safe_inline_code(p.id[:8])}{rev_label} — Status: {_safe_inline_code(p.status)}")
                        lines.append(f"- **Machine Sandbox Verdict**: {_safe_inline_code(p.machine_verdict or 'N/A')}")
                        if p.approved_by:
                            lines.append(f"- **Approved By**: {_safe_inline_code(p.approved_by)} at {_safe_inline_code(str(p.approved_at))}")
                        if p.rejected_reason:
                            lines.append(f"- **Rejected Reason**: {_escape_markdown_text(p.rejected_reason)}")
                        if p.user_feedback:
                            lines.append(f"- **Human Feedback**: {_escape_markdown_text(p.user_feedback)}")
                        if p.deliveries:
                            lines.append(f"- **GitHub Delivery**: {len(p.deliveries)} delivery record(s)")
                            for d in p.deliveries:
                                pr_str = f" [PR #{d.pr_number}]({d.pr_url})" if d.pr_number and d.pr_url else ""
                                lines.append(f"  - Status: {_safe_inline_code(d.status)}{pr_str} (Branch: {_safe_inline_code(d.head_branch or 'N/A')})")
                        lines.append(f"- **Explanation**: {_escape_markdown_text(p.explanation)}")
                        lines.append(f"- **Files Modified**: {', '.join(_safe_inline_code(fm) for fm in p.files_modified)}")
                        lines.append("")
                        lines.append(_safe_fenced_block(p.unified_diff, "diff"))
                        lines.append("")

                lines.append("---")
                lines.append("")

        # Chronological Audit Trail Table
        lines.append(f"## Workflow Audit Trail ({len(report.events_audit_trail)} events)")
        lines.append("")
        if not report.events_audit_trail:
            lines.append("*No durable workflow events recorded.*")
        else:
            lines.append("| ID | Timestamp | Event Type | Stage / Tool | Message |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for e in report.events_audit_trail:
                st = e.stage or e.tool_name or "-"
                lines.append(f"| {_safe_inline_code(str(e.id))} | {_escape_table_cell(e.created_at.strftime('%H:%M:%S'))} | {_safe_inline_code(e.event_type)} | {_escape_table_cell(st)} | {_escape_table_cell(e.message)} |")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def build_scan_telemetry(db: Session, scan_id: str) -> Optional[ScanTelemetry]:
        """Assemble typed ScanTelemetry from canonical database models without fabricating metrics."""
        scan = db.query(ScanModel).filter(ScanModel.id == str(scan_id)).first()
        if not scan:
            return None

        finding_models = db.query(FindingModel).filter(FindingModel.scan_id == str(scan_id)).all()
        patch_models = db.query(PatchModel).filter(PatchModel.scan_id == str(scan_id)).all()
        event_models = (
            db.query(WorkflowEventModel)
            .filter(WorkflowEventModel.scan_id == str(scan_id))
            .order_by(WorkflowEventModel.id.asc())
            .all()
        )

        # Duration
        total_duration_ms: Optional[int] = None
        if scan.created_at and scan.completed_at and scan.status in ("COMPLETED", "FAILED"):
            total_duration_ms = max(0, int((scan.completed_at - scan.created_at).total_seconds() * 1000))

        # Events and stages
        event_count = len(event_models)
        stages_seen = set()
        for e in event_models:
            if e.stage:
                stages_seen.add(e.stage)
            elif e.event_type in ("STAGE_STARTED", "STAGE_COMPLETED"):
                st = (e.metadata_payload or {}).get("stage")
                if st:
                    stages_seen.add(st)
        stage_count = len(stages_seen)

        # Tool outcomes from events & scan metadata
        tools_completed = 0
        tools_failed = 0
        tools_unavailable = 0

        for e in event_models:
            if e.event_type == "TOOL_COMPLETED":
                tools_completed += 1
            elif e.event_type == "TOOL_FAILED":
                tools_failed += 1
            elif e.event_type == "TOOL_UNAVAILABLE":
                tools_unavailable += 1

        scan_meta = scan.model_metadata or {}
        scanner_coverage = scan_meta.get("scanner_coverage") or scan_meta.get("scanners") or []
        if isinstance(scanner_coverage, list) and (tools_completed == 0 and tools_failed == 0 and tools_unavailable == 0):
            for sc in scanner_coverage:
                if isinstance(sc, dict):
                    st = (sc.get("status") or "").upper()
                    if st == "COMPLETED":
                        tools_completed += 1
                    elif st in ("FAILED", "INVALID_OUTPUT", "TIMEOUT"):
                        tools_failed += 1
                    elif st == "UNAVAILABLE":
                        tools_unavailable += 1

        # LLM metrics (aggregate ONLY if present, otherwise None)
        llm_calls = 0
        llm_retries = 0
        provider_fallbacks = 0
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0

        has_llm_metrics = False
        has_token_metrics = False
        has_retry_metrics = False

        meta_sources = [scan_meta]
        for f in finding_models:
            if f.model_metadata and isinstance(f.model_metadata, dict):
                meta_sources.append(f.model_metadata)
        for p in patch_models:
            if p.model_metadata and isinstance(p.model_metadata, dict):
                meta_sources.append(p.model_metadata)
        for e in event_models:
            if e.metadata_payload and isinstance(e.metadata_payload, dict):
                meta_sources.append(e.metadata_payload)

        for src in meta_sources:
            if "prompt_tokens" in src or "completion_tokens" in src or "total_tokens" in src:
                has_token_metrics = True
                prompt_tokens += src.get("prompt_tokens") or 0
                completion_tokens += src.get("completion_tokens") or 0
                total_tokens += src.get("total_tokens") or 0
            if "retry_count" in src or "retries" in src or "llm_retries" in src:
                has_retry_metrics = True
                raw_retry = src.get("retry_count") or src.get("retries") or src.get("llm_retries")
                normalized = _normalize_count(raw_retry)
                if normalized is not None:
                    llm_retries += normalized
            if "fallbacks_attempted" in src or "provider_fallbacks" in src:
                has_retry_metrics = True
                # fallbacks_attempted is canonically a list of error records from LLMRouter
                raw_fb = src.get("fallbacks_attempted")
                raw_pf = src.get("provider_fallbacks")
                fb_count = _normalize_count(raw_fb)
                pf_count = _normalize_count(raw_pf)
                if fb_count is not None:
                    provider_fallbacks += fb_count
                elif pf_count is not None:
                    provider_fallbacks += pf_count
            if "llm_calls" in src or "calls" in src:
                has_llm_metrics = True
                raw_calls = src.get("llm_calls") or src.get("calls")
                normalized_calls = _normalize_count(raw_calls)
                if normalized_calls is not None:
                    llm_calls += normalized_calls

        final_prompt_tokens = prompt_tokens if has_token_metrics else None
        final_completion_tokens = completion_tokens if has_token_metrics else None
        final_total_tokens = (total_tokens or (prompt_tokens + completion_tokens)) if has_token_metrics else None

        final_llm_retries = llm_retries if has_retry_metrics else None
        final_provider_fallbacks = provider_fallbacks if has_retry_metrics else None
        # Do NOT fabricate llm_calls=1 merely because token/retry metadata exists.
        # If an exact call count was not recorded, it remains None.
        final_llm_calls = llm_calls if has_llm_metrics else None

        # Finding verdict counts — uses verification_verdict (CONFIRMED/POSSIBLE/REJECTED),
        # NOT lifecycle status (OPEN/RESOLVED/FALSE_POSITIVE/SUPPRESSED).
        confirmed_findings = sum(1 for f in finding_models if f.verification_verdict == "CONFIRMED")
        possible_findings = sum(1 for f in finding_models if f.verification_verdict == "POSSIBLE")
        rejected_findings = sum(1 for f in finding_models if f.verification_verdict == "REJECTED")

        # Patch counts
        patches_generated = len(patch_models)
        patches_verified = sum(1 for p in patch_models if p.status in ("VERIFIED", "APPROVED") or p.machine_verdict == "PASSED")
        patches_needing_review = sum(1 for p in patch_models if p.status == "NEEDS_REVIEW" or p.machine_verdict == "NEEDS_REVIEW")
        patches_approved = sum(1 for p in patch_models if p.status == "APPROVED")
        patches_rejected = sum(1 for p in patch_models if p.status == "REJECTED" or p.machine_verdict == "REJECTED")

        # Delivery metrics derived authoritatively from DeliveryModel
        delivery_models = db.query(DeliveryModel).filter(DeliveryModel.scan_id == str(scan_id)).all()
        deliveries_requested = len(delivery_models)
        deliveries_blocked = sum(1 for d in delivery_models if d.status == DeliveryStatus.BLOCKED.value)
        pull_requests_created = sum(1 for d in delivery_models if d.status == DeliveryStatus.PR_CREATED.value)
        delivery_failures = sum(1 for d in delivery_models if d.status == DeliveryStatus.FAILED.value)

        # Analysis scope & truncation
        scope_data = scan_meta.get("analysis_scope") or scan_meta.get("scope") or {}
        analysis_truncated = bool(scope_data.get("truncated", False)) if isinstance(scope_data, dict) else False
        analysis_truncation_reason = scope_data.get("reason") if isinstance(scope_data, dict) else None

        return ScanTelemetry(
            scan_id=str(scan.id),
            commit_sha=scan.commit_hash,
            status=scan.status,
            total_duration_ms=total_duration_ms,
            event_count=event_count,
            stage_count=stage_count,
            tools_completed=tools_completed,
            tools_failed=tools_failed,
            tools_unavailable=tools_unavailable,
            llm_calls=final_llm_calls,
            llm_retries=final_llm_retries,
            provider_fallbacks=final_provider_fallbacks,
            prompt_tokens=final_prompt_tokens,
            completion_tokens=final_completion_tokens,
            total_tokens=final_total_tokens,
            confirmed_findings=confirmed_findings,
            possible_findings=possible_findings,
            rejected_findings=rejected_findings,
            patches_generated=patches_generated,
            patches_verified=patches_verified,
            patches_needing_review=patches_needing_review,
            patches_approved=patches_approved,
            patches_rejected=patches_rejected,
            deliveries_requested=deliveries_requested,
            deliveries_blocked=deliveries_blocked,
            pull_requests_created=pull_requests_created,
            delivery_failures=delivery_failures,
            analysis_truncated=analysis_truncated,
            analysis_truncation_reason=analysis_truncation_reason,
        )
