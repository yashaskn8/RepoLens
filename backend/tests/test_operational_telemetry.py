"""Tests for Task 4F: Operational Telemetry and Health Status Endpoints."""

from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import PatchStatus, ScanStatus, Severity
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService


def test_basic_health_endpoint(client: TestClient):
    """Verify GET /health returns standard health check status."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["service"] == "RepoLens"
    assert data["version"] == "0.1.0"
    assert "database" in data
    assert "timestamp" in data


def test_detailed_telemetry_endpoint(client: TestClient, db_session: Session):
    """Verify GET /health/detailed and GET /api/v1/health/telemetry return aggregated system metrics without leaking credentials."""
    # Seed some records in the test database
    scan1 = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo-1",
        status=ScanStatus.COMPLETED.value,
    )
    scan2 = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo-2",
        status=ScanStatus.FAILED.value,
    )
    db_session.add_all([scan1, scan2])

    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan1.id,
        title="SQL Injection",
        description="Raw concatenation",
        severity=Severity.HIGH.value,
        status="OPEN",
    )
    db_session.add(finding)

    patch = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan1.id,
        status=PatchStatus.APPROVED.value,
        unified_diff="--- a\n+++ b\n",
        files_modified=["app/query.py"],
        explanation="Safe query",
        expected_behavior_change="Fix",
        revision_number=0,
    )
    db_session.add(patch)

    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=uuid4(),
            message="Test event",
        ),
    )
    db_session.commit()

    resp = client.get("/health/detailed")
    assert resp.status_code == 200
    data = resp.json()

    assert data["service"] == "RepoLens"
    assert "providers" in data
    assert len(data["providers"]) >= 4

    # Verify no raw keys in response
    resp_text = resp.text.lower()
    assert "api_key" not in resp_text or "sk-" not in resp_text

    # Verify storage checks
    assert "storage" in data
    assert "snapshot_dir" in data["storage"]
    assert "writable" in data["storage"]

    # Verify metrics aggregation
    metrics = data["metrics"]
    assert metrics["total_scans"] >= 2
    assert metrics["completed_scans"] >= 1
    assert metrics["failed_scans"] >= 1
    assert metrics["total_findings"] >= 1
    assert metrics["total_patches"] >= 1
    assert metrics["approved_patches"] >= 1
    assert metrics["total_workflow_events"] >= 1

    # Verify /api/v1/health/telemetry alias
    resp_v1 = client.get("/api/v1/health/telemetry")
    assert resp_v1.status_code == 200
    assert resp_v1.json()["service"] == "RepoLens"
