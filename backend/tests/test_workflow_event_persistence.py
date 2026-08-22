"""Tests for Task 4A: Canonical Durable Workflow Event Model, Persistence, and Schema Contracts."""

from datetime import datetime, timezone
from uuid import uuid4
import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity
from app.schemas.workflow_event import (
    WorkflowEventBase,
    WorkflowEventCreate,
    WorkflowEventResponse,
    WorkflowEventType,
)


def _setup_scan(db: Session) -> ScanModel:
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo",
        status=ScanStatus.RUNNING.value,
        commit_hash="0123456789abcdef0123456789abcdef01234567",
    )
    db.add(scan)
    db.commit()
    return scan


def test_workflow_event_schema_validation_and_rejection():
    """Verify that WorkflowEventType enums are strictly validated and invalid types are rejected."""
    scan_id = uuid4()
    # Valid creation
    valid_event = WorkflowEventCreate(
        event_type=WorkflowEventType.SCAN_STARTED,
        scan_id=scan_id,
        message="Scan started",
        metadata_payload={"branch": "main"},
    )
    assert valid_event.event_type == WorkflowEventType.SCAN_STARTED
    assert valid_event.scan_id == scan_id

    # Invalid event type should raise ValidationError
    with pytest.raises(ValidationError):
        WorkflowEventCreate(
            event_type="INVALID_EVENT_KIND",  # type: ignore
            scan_id=scan_id,
        )


def test_workflow_event_persistence_and_reload(db_session: Session):
    """Verify that workflow events persist to database, reload cleanly, and preserve structured metadata."""
    scan = _setup_scan(db_session)

    event = WorkflowEventModel(
        event_type=WorkflowEventType.STAGE_STARTED.value,
        scan_id=scan.id,
        stage="static_analysis",
        message="Starting deterministic analysis",
        metadata_payload={"tools": ["semgrep", "trivy", "osv"]},
    )
    db_session.add(event)
    db_session.commit()

    assert event.id is not None
    assert isinstance(event.id, int)

    # Reload from DB
    reloaded = db_session.query(WorkflowEventModel).filter(WorkflowEventModel.id == event.id).first()
    assert reloaded is not None
    assert reloaded.event_type == "STAGE_STARTED"
    assert reloaded.scan_id == scan.id
    assert reloaded.finding_id is None
    assert reloaded.patch_id is None
    assert reloaded.stage == "static_analysis"
    assert reloaded.message == "Starting deterministic analysis"
    assert reloaded.metadata_payload == {"tools": ["semgrep", "trivy", "osv"]}
    assert isinstance(reloaded.created_at, datetime)


def test_workflow_event_nullable_finding_and_patch_fields(db_session: Session):
    """Verify nullable finding_id and patch_id fields behave correctly with foreign key relationships."""
    scan = _setup_scan(db_session)

    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title="SQL Injection",
        description="Vulnerable raw SQL query",
        severity=Severity.CRITICAL.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(finding)

    patch = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan.id,
        status=PatchStatus.VERIFIED.value,
        unified_diff="--- a/db.py\n+++ b/db.py\n",
        files_modified=["app/db.py"],
        explanation="Parameterized query",
        expected_behavior_change="Fixes SQL injection",
        revision_number=0,
    )
    db_session.add(patch)
    db_session.commit()

    # Event linked to finding and patch
    event = WorkflowEventModel(
        event_type=WorkflowEventType.PATCH_VERIFIED.value,
        scan_id=scan.id,
        finding_id=finding.id,
        patch_id=patch.id,
        stage="patch_verification",
        tool_name="sandbox_verifier",
        provider="nvidia",
        model_name="nemotron-3",
        message="Patch verified cleanly across 12 checks",
        metadata_payload={"checks_passed": 12, "machine_verdict": "PASSED"},
    )
    db_session.add(event)
    db_session.commit()

    reloaded = db_session.query(WorkflowEventModel).filter(WorkflowEventModel.id == event.id).first()
    assert reloaded is not None
    assert reloaded.finding_id == finding.id
    assert reloaded.patch_id == patch.id
    assert reloaded.finding.title == "SQL Injection"
    assert reloaded.patch.status == "VERIFIED"


def test_workflow_events_preserve_numeric_monotonic_ordering(db_session: Session):
    """Verify multiple events emitted sequentially receive strictly increasing integer IDs."""
    scan = _setup_scan(db_session)

    event_types = [
        WorkflowEventType.SCAN_CREATED,
        WorkflowEventType.SCAN_STARTED,
        WorkflowEventType.STAGE_STARTED,
        WorkflowEventType.TOOL_STARTED,
        WorkflowEventType.TOOL_COMPLETED,
        WorkflowEventType.STAGE_COMPLETED,
        WorkflowEventType.SCAN_COMPLETED,
    ]

    emitted_ids = []
    for et in event_types:
        evt = WorkflowEventModel(
            event_type=et.value,
            scan_id=scan.id,
            message=f"Event {et.value}",
            metadata_payload={},
        )
        db_session.add(evt)
        db_session.commit()
        emitted_ids.append(evt.id)

    # Strictly increasing sequence
    assert len(emitted_ids) == len(event_types)
    for i in range(len(emitted_ids) - 1):
        assert emitted_ids[i] < emitted_ids[i + 1]


def test_pydantic_response_serialization_from_orm(db_session: Session):
    """Verify WorkflowEventResponse serializes ORM models cleanly with proper types."""
    scan = _setup_scan(db_session)

    event = WorkflowEventModel(
        event_type=WorkflowEventType.HUMAN_APPROVED.value,
        scan_id=scan.id,
        message="Lead engineer approved patch",
        metadata_payload={"approved_by": "lead-eng"},
    )
    db_session.add(event)
    db_session.commit()

    resp = WorkflowEventResponse.model_validate(event)
    assert resp.id == event.id
    assert resp.event_type == WorkflowEventType.HUMAN_APPROVED
    assert str(resp.scan_id) == scan.id
    assert resp.message == "Lead engineer approved patch"
    assert resp.metadata_payload == {"approved_by": "lead-eng"}
    assert isinstance(resp.created_at, datetime)
