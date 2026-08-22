"""Phase 4 Observability, Streaming, Evidence Reporting, and Operational Telemetry Release Gate."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.report_service import ScanReportService
from app.services.workflow_event_service import WorkflowEventService


def test_phase4_end_to_end_observability_and_release_gate(client: TestClient, db_session: Session):
    """Full End-to-End Release Gate for Phase 4."""
    scan_id = uuid4()
    start_time = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
    end_time = datetime(2026, 8, 22, 12, 0, 10, tzinfo=timezone.utc)

    # 1. Create Scan Record with Scope and Scanner Coverage Metadata
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/fastapi/fastapi",
        branch="main",
        commit_hash="abcdef1234567890abcdef1234567890abcdef12",
        status=ScanStatus.COMPLETED.value,
        created_at=start_time,
        completed_at=end_time,
        model_metadata={
            "requested_branch": "main",
            "resolved_branch_or_ref": "main",
            "architecture_overview": "Modern async web framework for building APIs with Python",
            "languages": {"Python": 145},
            "frameworks": ["FastAPI", "Starlette", "Pydantic"],
            "analysis_scope": {
                "truncated": False,
                "files_processed": 145,
                "source_bytes_processed": 500000,
                "total_observed_files": 145,
                "total_observed_bytes": 500000,
            },
            "scanner_coverage": [
                {
                    "tool": "semgrep",
                    "status": "COMPLETED",
                    "findings_count": 1,
                    "execution_time_ms": 320,
                },
                {
                    "tool": "trivy",
                    "status": "UNAVAILABLE",
                    "findings_count": 0,
                    "failure_reason": "Trivy not found in runner PATH",
                },
            ],
            "prompt_tokens": 1200,
            "completion_tokens": 450,
            "total_tokens": 1650,
            "llm_calls": 2,
        },
    )
    db_session.add(scan)

    # 2. Add Grounded Finding
    finding_id = uuid4()
    finding = FindingModel(
        id=str(finding_id),
        scan_id=str(scan_id),
        title="Path Traversal in StaticFiles",
        description="Improper sanitization of relative paths allow directory escape",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        rule_id="python.fastapi.security.path-traversal",
        category="security",
        mitigation_guidance="Use os.path.realpath and verify prefix against allowed root",
        verification_verdict=VerificationVerdict.CONFIRMED.value,
        verification_reason="Reproducible in mock environment with test payload",
        source_tool="semgrep",
        detector_id="semgrep-py-pathtraversal",
    )
    db_session.add(finding)

    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=str(finding_id),
        file_path="fastapi/staticfiles.py",
        start_line=50,
        end_line=55,
        code_snippet="full_path = os.path.join(self.directory, path)",
        context_notes="Direct path concatenation without boundary check",
    )
    db_session.add(evidence)

    # 3. Add Candidate Remediation Patch
    patch_id = uuid4()
    patch = PatchModel(
        id=str(patch_id),
        finding_id=str(finding_id),
        scan_id=str(scan_id),
        status=PatchStatus.NEEDS_REVIEW.value,
        machine_verdict="PASSED",
        unified_diff="--- a/fastapi/staticfiles.py\n+++ b/fastapi/staticfiles.py\n@@ -50,1 +50,3 @@\n-full_path = os.path.join(self.directory, path)\n+resolved = os.path.realpath(os.path.join(self.directory, path))\n+if not resolved.startswith(os.path.realpath(self.directory)):\n+    raise HTTPException(404)\n",
        files_modified=["fastapi/staticfiles.py"],
        explanation="Guards file retrieval within root directory",
        expected_behavior_change="Rejects path traversal sequences",
        revision_number=0,
    )
    db_session.add(patch)

    # 4. Emit Sequential Workflow Events
    events_to_emit = [
        (WorkflowEventType.SCAN_CREATED, None, "Scan registered in system"),
        (WorkflowEventType.STAGE_STARTED, "intelligence_analysis", "Intelligence stage started"),
        (WorkflowEventType.TOOL_COMPLETED, "intelligence_analysis", "Semgrep completed with 1 finding"),
        (WorkflowEventType.TOOL_UNAVAILABLE, "intelligence_analysis", "Trivy unavailable"),
        (WorkflowEventType.STAGE_COMPLETED, "intelligence_analysis", "Intelligence stage completed"),
        (WorkflowEventType.STAGE_STARTED, "multi_agent_workflow", "Multi-agent LangGraph workflow started"),
        (WorkflowEventType.STAGE_COMPLETED, "multi_agent_workflow", "Multi-agent analysis finished"),
        (WorkflowEventType.SCAN_COMPLETED, None, "Scan completed successfully"),
    ]

    for evt_type, stage, msg in events_to_emit:
        WorkflowEventService.emit(
            db=db_session,
            event=WorkflowEventCreate(
                event_type=evt_type,
                scan_id=scan_id,
                stage=stage,
                tool_name="semgrep" if evt_type == WorkflowEventType.TOOL_COMPLETED else ("trivy" if evt_type == WorkflowEventType.TOOL_UNAVAILABLE else None),
                message=msg,
            ),
        )
    db_session.commit()

    # 5. Verify Event Replay Querying (after_id)
    all_events = WorkflowEventService.list_for_scan(db=db_session, scan_id=str(scan_id))
    assert len(all_events) == 8

    # Replay strictly after the 4th event
    pivot_id = all_events[3].id
    replayed = WorkflowEventService.list_after_id(db=db_session, scan_id=str(scan_id), after_id=pivot_id)
    assert len(replayed) == 4
    assert [e.id for e in replayed] == [e.id for e in all_events[4:]]

    # 6. Verify Scan-Specific Telemetry
    resp_telem = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp_telem.status_code == 200
    telem = resp_telem.json()
    assert telem["scan_id"] == str(scan_id)
    assert telem["status"] == "COMPLETED"
    assert telem["total_duration_ms"] == 10000
    assert telem["event_count"] == 8
    assert telem["tools_completed"] == 1
    assert telem["tools_unavailable"] == 1
    assert telem["llm_calls"] == 2
    assert telem["total_tokens"] == 1650
    assert telem["confirmed_findings"] == 1
    assert telem["patches_generated"] == 1

    # 7. Verify Markdown & JSON Report Integrity
    resp_md = client.get(f"/api/v1/scans/{scan_id}/report/markdown")
    assert resp_md.status_code == 200
    md_content = resp_md.text
    assert "# RepoLens Evidence & Intelligence Report" in md_content
    assert "## Analysis Scope & Ingestion Boundary" in md_content
    assert "**Analysis Truncated**: NO (Full Analysis)" in md_content
    assert "## Deterministic Scanner Coverage" in md_content
    assert "Path Traversal in StaticFiles" in md_content
    assert "```diff" in md_content
    assert "## Workflow Audit Trail" in md_content

    resp_json = client.get(f"/api/v1/scans/{scan_id}/report/json")
    assert resp_json.status_code == 200
    report_json = resp_json.json()
    assert report_json["summary"]["total_findings"] == 1
    assert report_json["analysis_scope"]["truncated"] is False
    assert len(report_json["scanner_coverage"]) == 2

    # 8. Verify Human Approval Audit Atomicity
    resp_approve = client.post(
        f"/api/v1/patches/{patch_id}/approve",
        json={"approved_by": "sec-lead", "notes": "Verified fix"},
    )
    assert resp_approve.status_code == 200
    assert resp_approve.json()["status"] == "APPROVED"

    # Verify audit events were recorded
    patch_events = WorkflowEventService.list_for_patch(db=db_session, patch_id=str(patch_id))
    event_types = [e.event_type for e in patch_events]
    assert "HUMAN_APPROVED" in event_types
    assert "PATCH_APPROVED" in event_types
