"""Tests for Task 4B: Canonical WorkflowEventService and Workflow Instrumentation."""

from uuid import uuid4
import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.main import app
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService, _sanitize_metadata


def test_sanitize_metadata_removes_secrets_and_api_keys():
    """Verify _sanitize_metadata strips any secret, api_key, auth header, or raw prompt keys."""
    raw = {
        "api_key": "sk-secret123456",
        "authorization_token": "Bearer token789",
        "client_secret": "topsecret",
        "system_prompt": "You are a bot...",
        "user_password": "mypassword",
        "safe_metric": 42,
        "nested": {
            "token": "nested-secret",
            "safe_count": 5,
        },
    }
    sanitized = _sanitize_metadata(raw)
    assert "api_key" not in sanitized
    assert "authorization_token" not in sanitized
    assert "client_secret" not in sanitized
    assert "system_prompt" not in sanitized
    assert "user_password" not in sanitized
    assert sanitized["safe_metric"] == 42
    assert "token" not in sanitized["nested"]
    assert sanitized["nested"]["safe_count"] == 5


def test_emit_and_query_by_scan_and_patch(db_session: Session):
    """Verify WorkflowEventService emit, list_for_scan, list_after_id, and list_for_patch queries."""
    scan_id = uuid4()
    patch_id = uuid4()
    finding_id = uuid4()

    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/fastapi/fastapi",
        status=ScanStatus.RUNNING.value,
    )
    db_session.add(scan)
    db_session.commit()

    # Emit multiple events
    e1 = WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_id,
            message="Scan created",
            metadata_payload={"branch": "main"},
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
            event_type=WorkflowEventType.PATCH_GENERATED,
            scan_id=scan_id,
            finding_id=finding_id,
            patch_id=patch_id,
            message="Patch generated",
            metadata_payload={"files_modified": ["app/main.py"]},
        ),
    )
    db_session.commit()

    assert e1 is not None and e2 is not None and e3 is not None
    assert e1.id < e2.id < e3.id

    # Query all for scan
    scan_events = WorkflowEventService.list_for_scan(db=db_session, scan_id=str(scan_id))
    assert len(scan_events) == 3
    assert [e.event_type for e in scan_events] == ["SCAN_CREATED", "SCAN_STARTED", "PATCH_GENERATED"]

    # Query replay after_id
    replayed = WorkflowEventService.list_after_id(db=db_session, scan_id=str(scan_id), after_id=e1.id)
    assert len(replayed) == 2
    assert [e.id for e in replayed] == [e2.id, e3.id]

    # Query for patch
    patch_events = WorkflowEventService.list_for_patch(db=db_session, patch_id=str(patch_id))
    assert len(patch_events) == 1
    assert patch_events[0].id == e3.id


def test_approve_patch_emits_human_audit_event(client: TestClient, db_session: Session):
    """Verify POST /patches/{id}/approve emits HUMAN_APPROVED and PATCH_APPROVED durable events."""
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)

    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title="Command Injection",
        description="os.system call",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(finding)

    patch = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan.id,
        status=PatchStatus.VERIFIED.value,
        unified_diff="--- a/run.py\n+++ b/run.py\n",
        files_modified=["app/run.py"],
        explanation="Safe subprocess",
        expected_behavior_change="Removes shell injection",
        revision_number=0,
    )
    db_session.add(patch)
    db_session.commit()

    resp = client.post(
        f"/api/v1/patches/{patch.id}/approve",
        json={"approved_by": "security-lead", "notes": "LGTM verified"},
    )
    assert resp.status_code == 200

    # Query audit events
    events = WorkflowEventService.list_for_patch(db=db_session, patch_id=patch.id)
    types = [e.event_type for e in events]
    assert "HUMAN_APPROVED" in types
    assert "PATCH_APPROVED" in types

    human_evt = next(e for e in events if e.event_type == "HUMAN_APPROVED")
    assert human_evt.metadata_payload.get("approved_by") is not None
    assert human_evt.actor_user_id is not None
    assert human_evt.metadata_payload.get("notes") == "LGTM verified"


def test_reject_patch_emits_human_audit_event(client: TestClient, db_session: Session):
    """Verify POST /patches/{id}/reject emits HUMAN_REJECTED and PATCH_REJECTED durable events."""
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)

    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title="Path Traversal",
        description="Unvalidated path",
        severity=Severity.MEDIUM.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(finding)

    patch = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan.id,
        status=PatchStatus.VERIFIED.value,
        unified_diff="--- a/files.py\n+++ b/files.py\n",
        files_modified=["app/files.py"],
        explanation="Path check",
        expected_behavior_change="Prevents traversal",
        revision_number=0,
    )
    db_session.add(patch)
    db_session.commit()

    resp = client.post(
        f"/api/v1/patches/{patch.id}/reject",
        json={"reason": "Breaks public API contract"},
    )
    assert resp.status_code == 200

    # Query audit events
    events = WorkflowEventService.list_for_patch(db=db_session, patch_id=patch.id)
    types = [e.event_type for e in events]
    assert "HUMAN_REJECTED" in types
    assert "PATCH_REJECTED" in types

    human_evt = next(e for e in events if e.event_type == "HUMAN_REJECTED")
    assert human_evt.metadata_payload.get("reason") == "Breaks public API contract"


def test_operational_emit_error_does_not_raise(db_session: Session):
    """Verify non-critical emit failure logs a warning and returns None without raising."""
    from unittest.mock import MagicMock

    scan_id = uuid4()
    bad_event = WorkflowEventCreate(
        event_type=WorkflowEventType.TOOL_STARTED,
        scan_id=scan_id,
        tool_name="semgrep",
    )
    mock_db = MagicMock()
    mock_db.add.side_effect = RuntimeError("DB connection lost")

    # Using critical=False should not raise
    result = WorkflowEventService.emit(db=mock_db, event=bad_event, critical=False)
    assert result is None

    # Using critical=True should propagate
    with pytest.raises(RuntimeError):
        WorkflowEventService.emit(db=mock_db, event=bad_event, critical=True)
