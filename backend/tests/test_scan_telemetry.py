"""Comprehensive tests for scan-specific telemetry endpoint and aggregation service."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import PatchStatus, ScanStatus, Severity
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.report_service import ScanReportService
from app.services.workflow_event_service import WorkflowEventService


def test_scan_telemetry_unknown_scan_returns_404(client: TestClient):
    """Verify requesting telemetry for non-existent scan ID returns 404."""
    random_id = uuid4()
    resp = client.get(f"/api/v1/scans/{random_id}/telemetry")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_scan_telemetry_completed_scan_aggregation(client: TestClient, db_session: Session):
    """Verify telemetry correctly aggregates completed scan metrics without fabricating missing values."""
    scan_id = str(uuid4())
    start_time = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    end_time = datetime(2026, 8, 22, 10, 0, 5, 500000, tzinfo=timezone.utc)

    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/repo-telemetry",
        commit_hash="abcd1234ef567890",
        status=ScanStatus.COMPLETED.value,
        created_at=start_time,
        completed_at=end_time,
        model_metadata={
            "analysis_scope": {
                "truncated": False,
                "files_processed": 42,
                "total_observed_files": 42,
            }
        },
    )
    db_session.add(scan)

    # Add findings with various statuses
    f1 = FindingModel(
        id=str(uuid4()),
        scan_id=scan_id,
        title="SQL Injection",
        description="Concat in query",
        severity=Severity.HIGH.value,
        status="CONFIRMED",
    )
    f2 = FindingModel(
        id=str(uuid4()),
        scan_id=scan_id,
        title="Potential XSS",
        description="Unescaped output",
        severity=Severity.MEDIUM.value,
        status="POSSIBLE",
    )
    f3 = FindingModel(
        id=str(uuid4()),
        scan_id=scan_id,
        title="False Alarm",
        description="Benign test code",
        severity=Severity.LOW.value,
        status="REJECTED",
    )
    db_session.add_all([f1, f2, f3])

    # Add patches with various statuses
    p1 = PatchModel(
        id=str(uuid4()),
        finding_id=f1.id,
        scan_id=scan_id,
        status=PatchStatus.APPROVED.value,
        machine_verdict="PASSED",
        unified_diff="--- a\n+++ b\n",
        files_modified=["app/db.py"],
        explanation="Parameterized query",
        expected_behavior_change="Fix",
        revision_number=0,
    )
    p2 = PatchModel(
        id=str(uuid4()),
        finding_id=f2.id,
        scan_id=scan_id,
        status=PatchStatus.NEEDS_REVIEW.value,
        machine_verdict="NEEDS_REVIEW",
        unified_diff="--- a\n+++ b\n",
        files_modified=["app/views.py"],
        explanation="HTML escape",
        expected_behavior_change="Fix",
        revision_number=0,
    )
    db_session.add_all([p1, p2])

    # Add workflow events with tool outcomes
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=UUID(scan_id),
            message="Scan registered",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.STAGE_STARTED,
            scan_id=UUID(scan_id),
            stage="intelligence_analysis",
            message="Analysis started",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.TOOL_COMPLETED,
            scan_id=UUID(scan_id),
            tool_name="semgrep",
            message="Semgrep completed with findings",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.TOOL_UNAVAILABLE,
            scan_id=UUID(scan_id),
            tool_name="trivy",
            message="Trivy binary not found on host",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.TOOL_FAILED,
            scan_id=UUID(scan_id),
            tool_name="osv",
            message="OSV scanner returned invalid output",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_COMPLETED,
            scan_id=UUID(scan_id),
            message="Scan completed successfully",
        ),
    )
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    assert data["scan_id"] == scan_id
    assert data["commit_sha"] == "abcd1234ef567890"
    assert data["status"] == "COMPLETED"
    assert data["total_duration_ms"] == 5500

    assert data["event_count"] == 6
    assert data["stage_count"] >= 1

    assert data["tools_completed"] == 1
    assert data["tools_unavailable"] == 1
    assert data["tools_failed"] == 1

    assert data["confirmed_findings"] == 1
    assert data["possible_findings"] == 1
    assert data["rejected_findings"] == 1

    assert data["patches_generated"] == 2
    assert data["patches_approved"] == 1
    assert data["patches_needing_review"] == 1
    assert data["patches_rejected"] == 0

    assert data["analysis_truncated"] is False
    assert data["analysis_truncation_reason"] is None

    # Verify unrecorded LLM metrics remain null rather than fabricated 0
    assert data["llm_retries"] is None
    assert data["provider_fallbacks"] is None
    assert data["prompt_tokens"] is None
    assert data["completion_tokens"] is None
    assert data["total_tokens"] is None


def test_scan_telemetry_failed_scan_and_truncation(client: TestClient, db_session: Session):
    """Verify telemetry handles failed scans and truncated analysis metadata."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/huge-repo",
        commit_hash="fedcba9876543210",
        status=ScanStatus.FAILED.value,
        created_at=datetime(2026, 8, 22, 11, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 8, 22, 11, 0, 2, tzinfo=timezone.utc),
        model_metadata={
            "analysis_scope": {
                "truncated": True,
                "reason": "Max file count of 1000 exceeded",
                "files_processed": 1000,
                "total_observed_files": 3400,
            }
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    assert data["scan_id"] == scan_id
    assert data["status"] == "FAILED"
    assert data["analysis_truncated"] is True
    assert data["analysis_truncation_reason"] == "Max file count of 1000 exceeded"
    assert data["event_count"] == 0
    assert data["confirmed_findings"] == 0


def test_scan_telemetry_llm_metrics_derivation(client: TestClient, db_session: Session):
    """Verify LLM retry, fallback, and token counts are aggregated when recorded in model metadata."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/llm-telemetry-repo",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "prompt_tokens": 1500,
            "completion_tokens": 450,
            "total_tokens": 1950,
            "retry_count": 2,
            "fallbacks_attempted": 1,
            "llm_calls": 3,
        },
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp.status_code == 200
    data = resp.json()

    assert data["llm_calls"] == 3
    assert data["llm_retries"] == 2
    assert data["provider_fallbacks"] == 1
    assert data["prompt_tokens"] == 1500
    assert data["completion_tokens"] == 450
    assert data["total_tokens"] == 1950
