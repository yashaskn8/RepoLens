"""Tests for Task 4C: Server-Sent Events (SSE) Real-Time Stream and Replay."""

import json
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import ScanStatus
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService


def test_stream_events_unknown_scan_returns_404(client: TestClient):
    """Verify requesting event stream for a non-existent scan ID returns 404 before stream begins."""
    random_id = uuid4()
    resp = client.get(f"/api/v1/scans/{random_id}/events")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_stream_events_invalid_last_event_id_returns_400(client: TestClient, db_session: Session):
    """Verify non-integer Last-Event-ID header returns 400 Bad Request."""
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.get(
        f"/api/v1/scans/{scan.id}/events",
        headers={"Last-Event-ID": "invalid-non-int"},
    )
    assert resp.status_code == 400
    assert "invalid last-event-id" in resp.json()["detail"].lower()


def test_stream_events_full_replay_for_completed_scan(client: TestClient, db_session: Session):
    """Verify connecting to a completed scan streams the complete event history in SSE format."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/test-stream",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)
    db_session.commit()

    # Pre-populate durable events
    e1 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_id,
            message="Scan created",
        ),
    )
    e2 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_STARTED,
            scan_id=scan_id,
            message="Scan started",
        ),
    )
    e3 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_COMPLETED,
            scan_id=scan_id,
            message="Scan completed",
        ),
    )
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/events")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]

    content = resp.text
    # Verify standard SSE framing: "id: ...\nevent: ...\ndata: ...\n\n"
    assert f"id: {e1.id}" in content
    assert f"event: {WorkflowEventType.SCAN_CREATED.value}" in content
    assert f"id: {e2.id}" in content
    assert f"event: {WorkflowEventType.SCAN_STARTED.value}" in content
    assert f"id: {e3.id}" in content
    assert f"event: {WorkflowEventType.SCAN_COMPLETED.value}" in content


def test_stream_events_partial_replay_with_last_event_id_header(client: TestClient, db_session: Session):
    """Verify Last-Event-ID header resumes strictly after the specified event ID."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/test-stream-resume",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)
    db_session.commit()

    e1 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_id,
            message="Scan created",
        ),
    )
    e2 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_STARTED,
            scan_id=scan_id,
            message="Scan started",
        ),
    )
    e3 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_COMPLETED,
            scan_id=scan_id,
            message="Scan completed",
        ),
    )
    db_session.commit()

    resp = client.get(
        f"/api/v1/scans/{scan_id}/events",
        headers={"Last-Event-ID": str(e1.id)},
    )
    assert resp.status_code == 200
    content = resp.text

    assert f"id: {e1.id}" not in content
    assert f"id: {e2.id}" in content
    assert f"id: {e3.id}" in content


def test_stream_events_partial_replay_with_after_id_query_param(client: TestClient, db_session: Session):
    """Verify ?after_id query parameter resumes strictly after the specified event ID."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/test-stream-query",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)
    db_session.commit()

    e1 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_id,
            message="Scan created",
        ),
    )
    e2 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_STARTED,
            scan_id=scan_id,
            message="Scan started",
        ),
    )
    db_session.commit()

    resp = client.get(f"/api/v1/scans/{scan_id}/events?after_id={e1.id}")
    assert resp.status_code == 200
    content = resp.text

    assert f"id: {e1.id}" not in content
    assert f"id: {e2.id}" in content
