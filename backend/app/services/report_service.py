"""Canonical ScanReportService for building and rendering evidence-grounded reports."""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.report import (
    ReportEvidence,
    ReportFinding,
    ReportPatch,
    ReportSummary,
    ReportWorkflowEvent,
    ScanReport,
)

logger = logging.getLogger(__name__)


class ScanReportService:
    """Service to assemble comprehensive evidence reports and render them as Markdown or JSON."""

    @staticmethod
    def build_scan_report(db: Session, scan_id: str) -> Optional[ScanReport]:
        """Assemble structured, evidence-grounded ScanReport from database models."""
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

        # Index patches by finding_id
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
                unified_diff=pm.unified_diff,
                files_modified=pm.files_modified or [],
                explanation=pm.explanation,
                expected_behavior_change=pm.expected_behavior_change,
                approved_by=pm.approved_by,
                approved_at=pm.approved_at,
                rejected_reason=pm.rejected_reason,
                user_feedback=pm.user_feedback,
                created_at=pm.created_at,
            )
            patches_by_finding.setdefault(pm.finding_id, []).append(rp)

        # Build findings list
        report_findings: List[ReportFinding] = []
        for fm in finding_models:
            evidences = [
                ReportEvidence(
                    id=em.id,
                    file_path=em.file_path,
                    start_line=em.start_line,
                    end_line=em.end_line,
                    code_snippet=em.code_snippet,
                    context_notes=em.context_notes,
                )
                for em in fm.evidences
            ]
            rf = ReportFinding(
                id=fm.id,
                title=fm.title,
                description=fm.description,
                severity=fm.severity,
                status=fm.status,
                rule_id=fm.rule_id,
                category=fm.category,
                mitigation_guidance=fm.mitigation_guidance,
                verification_verdict=fm.verification_verdict,
                verification_reason=fm.verification_reason,
                source_tool=fm.source_tool,
                detector_id=fm.detector_id,
                evidences=evidences,
                patches=patches_by_finding.get(fm.id, []),
                created_at=fm.created_at,
            )
            report_findings.append(rf)

        # Build summary metrics
        summary = ReportSummary(
            total_findings=len(report_findings),
            critical_findings=sum(1 for f in report_findings if f.severity == "CRITICAL"),
            high_findings=sum(1 for f in report_findings if f.severity == "HIGH"),
            medium_findings=sum(1 for f in report_findings if f.severity == "MEDIUM"),
            low_findings=sum(1 for f in report_findings if f.severity == "LOW"),
            confirmed_findings=sum(1 for f in report_findings if f.verification_verdict == "CONFIRMED"),
            total_patches=len(patch_models),
            approved_patches=sum(1 for p in patch_models if p.status == "APPROVED"),
            rejected_patches=sum(1 for p in patch_models if p.status == "REJECTED"),
            revised_patches=sum(1 for p in patch_models if (p.revision_number or 0) > 0),
        )

        # Build events audit trail
        events_audit = [
            ReportWorkflowEvent(
                id=e.id,
                event_type=e.event_type,
                stage=e.stage,
                tool_name=e.tool_name,
                message=e.message,
                created_at=e.created_at,
            )
            for e in event_models
        ]

        meta = scan.model_metadata or {}
        req_branch = meta.get("requested_branch") if isinstance(meta, dict) else None
        res_branch = meta.get("resolved_branch_or_ref") if isinstance(meta, dict) else None
        arch_overview = meta.get("architecture_overview") if isinstance(meta, dict) else None
        languages = meta.get("languages") if isinstance(meta, dict) and isinstance(meta.get("languages"), dict) else {}
        frameworks = meta.get("frameworks") if isinstance(meta, dict) and isinstance(meta.get("frameworks"), list) else []

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
            summary=summary,
            findings=report_findings,
            events_audit_trail=events_audit,
        )

    @staticmethod
    def render_markdown(report: ScanReport) -> str:
        """Render a full GFM Markdown report with tables, evidence snippets, diffs, and audit trail."""
        lines: List[str] = []

        # Title & Metadata Header
        lines.append(f"# RepoLens Evidence & Intelligence Report")
        lines.append(f"")
        lines.append(f"**Scan ID**: `{report.scan_id}`  ")
        lines.append(f"**Repository**: [{report.repository_url}]({report.repository_url})  ")
        lines.append(f"**Commit SHA**: `{report.commit_sha or 'N/A'}`  ")
        lines.append(f"**Branch**: `{report.resolved_branch or report.requested_branch or 'default'}`  ")
        lines.append(f"**Status**: `{report.status}`  ")
        lines.append(f"**Generated At**: `{datetime.now(timezone.utc).isoformat()}`  ")
        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

        # Executive Summary Table
        lines.append(f"## Executive Summary")
        lines.append(f"")
        lines.append(f"| Metric | Count |")
        lines.append(f"| :--- | :--- |")
        lines.append(f"| **Total Findings** | {report.summary.total_findings} |")
        lines.append(f"| 🔴 Critical Severity | {report.summary.critical_findings} |")
        lines.append(f"| 🟠 High Severity | {report.summary.high_findings} |")
        lines.append(f"| 🟡 Medium Severity | {report.summary.medium_findings} |")
        lines.append(f"| 🔵 Low Severity | {report.summary.low_findings} |")
        lines.append(f"| ✅ Confirmed Grounded Findings | {report.summary.confirmed_findings} |")
        lines.append(f"| 🛡️ Total Generated Patches | {report.summary.total_patches} |")
        lines.append(f"| 👤 Approved Patches | {report.summary.approved_patches} |")
        lines.append(f"| ❌ Rejected Patches | {report.summary.rejected_patches} |")
        lines.append(f"| 🔄 Child Revisions | {report.summary.revised_patches} |")
        lines.append(f"")

        # Repository Architecture & Stack
        if report.architecture_overview or report.languages or report.frameworks:
            lines.append(f"## Repository Architecture & Stack")
            lines.append(f"")
            if report.architecture_overview:
                lines.append(f"{report.architecture_overview}")
                lines.append(f"")
            if report.languages:
                lang_str = ", ".join(f"`{k}` ({v} files)" for k, v in report.languages.items())
                lines.append(f"**Languages Detected**: {lang_str}  ")
            if report.frameworks:
                fw_str = ", ".join(f"`{f}`" for f in report.frameworks)
                lines.append(f"**Frameworks Detected**: {fw_str}  ")
            lines.append(f"")

        # Detailed Findings & Evidences
        lines.append(f"## Verified Grounded Findings ({len(report.findings)})")
        lines.append(f"")
        if not report.findings:
            lines.append(f"*No security or architectural findings were identified in this scan.*")
            lines.append(f"")
        else:
            for idx, f in enumerate(report.findings, start=1):
                lines.append(f"### {idx}. [{f.severity}] {f.title}")
                lines.append(f"")
                lines.append(f"- **Finding ID**: `{f.id}`")
                lines.append(f"- **Category**: `{f.category or 'General'}`")
                if f.rule_id:
                    lines.append(f"- **Rule ID**: `{f.rule_id}`")
                if f.source_tool:
                    lines.append(f"- **Detector / Source**: `{f.source_tool}` (`{f.detector_id or 'default'}`)")
                lines.append(f"- **Verdict**: `{f.verification_verdict or 'N/A'}`")
                if f.verification_reason:
                    lines.append(f"- **Verdict Reason**: {f.verification_reason}")
                lines.append(f"")
                lines.append(f"**Description**:")
                lines.append(f"{f.description}")
                lines.append(f"")

                if f.mitigation_guidance:
                    lines.append(f"**Mitigation Guidance**:")
                    lines.append(f"{f.mitigation_guidance}")
                    lines.append(f"")

                # Grounded Evidences
                if f.evidences:
                    lines.append(f"**Source Evidences** ({len(f.evidences)}):")
                    lines.append(f"")
                    for ev in f.evidences:
                        lines.append(f"📁 **`{ev.file_path}`** (lines {ev.start_line or '?'}-{ev.end_line or '?'})")
                        if ev.context_notes:
                            lines.append(f"> {ev.context_notes}")
                        if ev.code_snippet:
                            lines.append(f"```")
                            lines.append(f"{ev.code_snippet}")
                            lines.append(f"```")
                        lines.append(f"")

                # Associated Patches
                if f.patches:
                    lines.append(f"**Generated Remediation Patches** ({len(f.patches)}):")
                    lines.append(f"")
                    for p in f.patches:
                        rev_label = f" (Revision #{p.revision_number})" if p.revision_number > 0 else ""
                        lines.append(f"#### Patch `{p.id[:8]}`{rev_label} — Status: `{p.status}`")
                        lines.append(f"- **Machine Sandbox Verdict**: `{p.machine_verdict or 'N/A'}`")
                        if p.approved_by:
                            lines.append(f"- **Approved By**: `{p.approved_by}` at `{p.approved_at}`")
                        if p.rejected_reason:
                            lines.append(f"- **Rejected Reason**: `{p.rejected_reason}`")
                        if p.user_feedback:
                            lines.append(f"- **Human Feedback**: `{p.user_feedback}`")
                        lines.append(f"- **Explanation**: {p.explanation}")
                        lines.append(f"- **Files Modified**: {', '.join(f'`{fm}`' for fm in p.files_modified)}")
                        lines.append(f"")
                        lines.append(f"```diff")
                        lines.append(f"{p.unified_diff}")
                        lines.append(f"```")
                        lines.append(f"")

                lines.append(f"---")
                lines.append(f"")

        # Chronological Audit Trail
        lines.append(f"## Workflow Audit Trail ({len(report.events_audit_trail)} events)")
        lines.append(f"")
        if not report.events_audit_trail:
            lines.append(f"*No durable workflow events recorded.*")
        else:
            lines.append(f"| ID | Timestamp | Event Type | Stage / Tool | Message |")
            lines.append(f"| :--- | :--- | :--- | :--- | :--- |")
            for e in report.events_audit_trail:
                st = e.stage or e.tool_name or "-"
                msg = e.message.replace("|", "\\|") if e.message else "-"
                lines.append(f"| `{e.id}` | {e.created_at.strftime('%H:%M:%S')} | `{e.event_type}` | `{st}` | {msg} |")
        lines.append(f"")

        return "\n".join(lines)
