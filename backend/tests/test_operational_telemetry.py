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
    """Verify GET /health/detailed and GET /api/v1/health/telemetry return aggregated system metrics without leaking host paths, database strings, or credentials."""
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

    # Verify no credentials, host filesystem paths, or DB URLs in telemetry response text
    resp_text = resp.text
    resp_lower = resp_text.lower()
    assert "c:\\" not in resp_lower
    assert "/tmp/" not in resp_lower
    assert "/home/" not in resp_lower
    assert "repolens_checkpoints.db" not in resp_text
    assert "sqlite://" not in resp_lower
    assert "postgresql://" not in resp_lower
    assert "sk-" not in resp_text
    assert "gsk_" not in resp_text
    assert "aiza" not in resp_lower

    # Verify storage capability fields (booleans only, no host paths)
    assert "storage" in data
    assert "snapshot_storage_writable" in data["storage"]
    assert isinstance(data["storage"]["snapshot_storage_writable"], bool)
    assert "checkpointer_storage_accessible" in data["storage"]
    assert isinstance(data["storage"]["checkpointer_storage_accessible"], bool)
    assert "snapshot_dir" not in data["storage"]
    assert "checkpointer_db_path" not in data["storage"]

    # Verify metrics aggregation
    metrics = data["metrics"]
    assert metrics["total_scans"] >= 2
    assert metrics["completed_scans"] >= 1
    assert metrics["failed_scans"] >= 1
    assert metrics["total_findings"] >= 1
    assert metrics["total_patches"] >= 1
    assert metrics["approved_patches"] >= 1
    assert metrics["total_workflow_events"] >= 1

    # Verify root and API v1 routes
    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/health/telemetry").status_code == 200
    assert client.get("/health/telemetry").status_code == 200
    assert client.get("/api/v1/api/v1/health/telemetry").status_code == 404

