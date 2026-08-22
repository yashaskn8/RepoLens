"""Security and isolation tests for Phase 4 Observability, Telemetry, and Events."""

from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import ScanStatus
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService, _sanitize_metadata


def test_cross_scan_event_isolation(client: TestClient, db_session: Session):
    """Verify workflow events emitted for Scan A are strictly isolated from Scan B."""
    scan_a_id = uuid4()
    scan_b_id = uuid4()

    scan_a = ScanModel(
        id=str(scan_a_id),
        repository_url="https://github.com/org/repo-a",
        commit_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        status=ScanStatus.COMPLETED.value,
    )
    scan_b = ScanModel(
        id=str(scan_b_id),
        repository_url="https://github.com/org/repo-b",
        commit_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add_all([scan_a, scan_b])

    # Emit events for Scan A
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_a_id,
            message="Scan A created",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.STAGE_STARTED,
            scan_id=scan_a_id,
            stage="intelligence_analysis",
            message="Scan A stage started",
        ),
    )

    # Emit events for Scan B
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_b_id,
            message="Scan B created",
        ),
    )
    db_session.commit()

    # Query events for Scan A
    events_a = WorkflowEventService.list_for_scan(db=db_session, scan_id=str(scan_a_id))
    assert len(events_a) == 2
    for e in events_a:
        assert e.scan_id == str(scan_a_id)
        assert e.scan_id != str(scan_b_id)

    # Query events for Scan B
    events_b = WorkflowEventService.list_for_scan(db=db_session, scan_id=str(scan_b_id))
    assert len(events_b) == 1
    assert events_b[0].scan_id == str(scan_b_id)

    # Verify REST endpoint event list isolation via SSE stream
    resp_a = client.get(f"/api/v1/scans/{scan_a_id}/events")
    assert resp_a.status_code == 200
    assert "text/event-stream" in resp_a.headers["content-type"]
    assert str(scan_a_id) in resp_a.text
    assert str(scan_b_id) not in resp_a.text

    resp_b = client.get(f"/api/v1/scans/{scan_b_id}/events")
    assert resp_b.status_code == 200
    assert "text/event-stream" in resp_b.headers["content-type"]
    assert str(scan_b_id) in resp_b.text
    assert str(scan_a_id) not in resp_b.text


def test_recursive_metadata_secret_redaction_and_bounding():
    """Verify recursive stripping of secret fields and bounding of large values."""
    payload = {
        "safe_metric": "safe_value",
        "api_key": "sk-should-be-stripped",
        "jwt_token": "bearer-token-strip",
        "auth_header": "Basic admin:pass",
        "db_password": "supersecretpassword",
        "nested_data": {
            "oauth_token": "oauth123",
            "prompt_text": "Sensitive system prompt",
            "public_metric": 42,
        },
        "massive_log": "A" * 3000,
    }

    sanitized = _sanitize_metadata(payload)

    assert "safe_metric" in sanitized
    assert sanitized["safe_metric"] == "safe_value"

    # Verify blacklisted keys are stripped
    assert "api_key" not in sanitized
    assert "jwt_token" not in sanitized
    assert "auth_header" not in sanitized
    assert "db_password" not in sanitized

    # Verify nested dictionary sanitization
    assert "nested_data" in sanitized
    assert "oauth_token" not in sanitized["nested_data"]
    assert "prompt_text" not in sanitized["nested_data"]
    assert sanitized["nested_data"]["public_metric"] == 42

    # Verify string bounding
    assert len(sanitized["massive_log"]) <= 2048 + len("... [truncated]")
    assert "... [truncated]" in sanitized["massive_log"]


def test_operational_telemetry_host_path_leak_prevention(client: TestClient):
    """Verify health and telemetry endpoints never leak local host filesystem structures."""
    resp = client.get("/health/detailed")
    assert resp.status_code == 200
    text = resp.text

    # Assert no Windows local paths
    assert "C:\\Users\\" not in text
    assert "c:\\users\\" not in text.lower()
    # Assert no Unix home paths
    assert "/home/" not in text
    # Assert no DB path filenames
    assert ".db" not in text or "repolens_checkpoints" not in text
