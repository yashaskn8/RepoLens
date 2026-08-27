"""Unit tests for ChangeAnalysisModel, ChangeImpactModel, and WorkflowEvent change_analysis association."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest
from sqlalchemy.orm import Session

from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import (
    ChangeAnalysisStatus,
    ChangeImpactType,
    ChangeRiskLevel,
    ImpactVerificationStatus,
    Severity,
)
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService


def test_change_analysis_model_crud_and_relationships(db_session: Session):
    """Verify ChangeAnalysisModel and ChangeImpactModel creation, query, and cascade behavior."""
    analysis_id = str(uuid4())
    base_sha = "1111111111111111111111111111111111111111"
    head_sha = "2222222222222222222222222222222222222222"

    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url="https://github.com/fastapi/fastapi",
        repository_owner="fastapi",
        repository_name="fastapi",
        base_ref="main",
        base_commit_sha=base_sha,
        head_ref="feature/v2",
        head_commit_sha=head_sha,
        status=ChangeAnalysisStatus.ANALYZING.value,
        changed_files_count=4,
        changed_symbols_count=7,
        impacted_symbols_count=15,
        risk_level=ChangeRiskLevel.HIGH.value,
        model_metadata={"analyzer_version": "1.0.0"},
    )
    db_session.add(analysis)
    db_session.commit()

    # Query back
    fetched = db_session.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id).first()
    assert fetched is not None
    assert fetched.repository_name == "fastapi"
    assert fetched.base_commit_sha == base_sha
    assert fetched.head_commit_sha == head_sha
    assert fetched.status == "ANALYZING"
    assert fetched.model_metadata["analyzer_version"] == "1.0.0"

    # Add structured impacts
    impact1 = ChangeImpactModel(
        id=str(uuid4()),
        analysis_id=analysis_id,
        impact_type=ChangeImpactType.API_CONTRACT_CHANGE.value,
        severity=Severity.HIGH.value,
        title="Removed query parameter 'limit_legacy'",
        description="Breaking API parameter change in GET /items",
        source_file="app/api/items.py",
        source_symbol="get_items",
        affected_file="frontend/src/api/itemsClient.ts",
        affected_symbol="fetchItems",
        evidence_payload={
            "parameter": "limit_legacy",
            "base_type": "Optional[int]",
            "head_type": "None",
            "breaking": True,
        },
        confidence=1.0,
        verification_status=ImpactVerificationStatus.FACT.value,
    )
    impact2 = ChangeImpactModel(
        id=str(uuid4()),
        analysis_id=analysis_id,
        impact_type=ChangeImpactType.CALLER_IMPACT.value,
        severity=Severity.MEDIUM.value,
        title="Downstream caller impact on compute_totals",
        description="Changed return tuple structure from (int, int) to NamedTuple",
        source_file="app/core/calculator.py",
        source_symbol="compute_totals",
        affected_file="app/services/billing.py",
        affected_symbol="generate_invoice",
        evidence_payload={
            "edge": "CALLS",
            "caller": "generate_invoice",
            "callee": "compute_totals",
        },
        confidence=0.95,
        verification_status=ImpactVerificationStatus.FACT.value,
    )
    db_session.add_all([impact1, impact2])
    db_session.commit()

    # Verify relationship navigation
    db_session.refresh(fetched)
    assert len(fetched.impacts) == 2
    impact_types = {imp.impact_type for imp in fetched.impacts}
    assert ChangeImpactType.API_CONTRACT_CHANGE.value in impact_types
    assert ChangeImpactType.CALLER_IMPACT.value in impact_types

    # Verify cascade deletion
    db_session.delete(fetched)
    db_session.commit()

    remaining_impacts = db_session.query(ChangeImpactModel).filter(ChangeImpactModel.analysis_id == analysis_id).all()
    assert len(remaining_impacts) == 0


def test_workflow_event_change_analysis_association(db_session: Session):
    """Verify first-class change_analysis_id on WorkflowEventModel and WorkflowEventService queries."""
    analysis_id = str(uuid4())
    base_sha = "1111111111111111111111111111111111111111"
    head_sha = "2222222222222222222222222222222222222222"

    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url="https://github.com/fastapi/fastapi",
        repository_owner="fastapi",
        repository_name="fastapi",
        base_commit_sha=base_sha,
        head_commit_sha=head_sha,
        status=ChangeAnalysisStatus.PENDING.value,
    )
    db_session.add(analysis)
    db_session.commit()

    # Emit Phase 6 stage events
    evt1 = WorkflowEventCreate(
        event_type=WorkflowEventType.CHANGE_ANALYSIS_REQUESTED,
        change_analysis_id=UUID(analysis_id),
        stage="intake",
        message=f"Change analysis requested for {base_sha[:8]}..{head_sha[:8]}",
        metadata_payload={"base_sha": base_sha, "head_sha": head_sha},
    )
    evt2 = WorkflowEventCreate(
        event_type=WorkflowEventType.CHANGE_DIFF_COMPLETED,
        change_analysis_id=UUID(analysis_id),
        stage="diffing",
        message="Syntactic and symbol diff completed across 5 files",
        metadata_payload={"changed_files_count": 5},
    )
    evt3 = WorkflowEventCreate(
        event_type=WorkflowEventType.CHANGE_ANALYSIS_COMPLETED,
        change_analysis_id=UUID(analysis_id),
        stage="completion",
        message="Change impact analysis completed successfully",
        metadata_payload={"impacts_count": 8, "risk_level": "MEDIUM"},
    )

    WorkflowEventService.emit_critical(db=db_session, event=evt1)
    WorkflowEventService.emit_critical(db=db_session, event=evt2)
    WorkflowEventService.emit_critical(db=db_session, event=evt3)
    db_session.commit()

    # Query events via service helper
    events = WorkflowEventService.list_for_change_analysis(db=db_session, change_analysis_id=analysis_id)
    assert len(events) == 3
    assert events[0].event_type == WorkflowEventType.CHANGE_ANALYSIS_REQUESTED.value
    assert events[0].change_analysis_id == analysis_id
    assert events[0].scan_id is None  # Standalone change analysis event has null scan_id
    assert events[1].event_type == WorkflowEventType.CHANGE_DIFF_COMPLETED.value
    assert events[2].event_type == WorkflowEventType.CHANGE_ANALYSIS_COMPLETED.value

    # Verify model relationship navigation
    db_session.refresh(analysis)
    assert len(analysis.events) == 3
    event_stages = [e.stage for e in analysis.events]
    assert "intake" in event_stages
    assert "diffing" in event_stages
    assert "completion" in event_stages
