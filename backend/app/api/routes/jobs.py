"""Tenant-isolated durable job resources and cancellation semantics."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, verify_csrf
from app.core.database import get_db
from app.execution.dispatcher import DurableWorkDispatcher
from app.execution.engine import DurableExecutionEngine
from app.governance.events import AuditLedger, DomainOutbox
from app.models.execution import FailureRecordModel, WorkItemModel
from app.schemas.auth import CurrentUser


router = APIRouter(prefix="/jobs", tags=["Jobs"])


class JobResource(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    work_kind: str
    resource_type: str
    resource_id: str
    state: str
    domain_outcome: str | None = None
    coverage_summary: dict[str, Any] = Field(default_factory=dict)
    outcome_detail: dict[str, Any] = Field(default_factory=dict)
    attempt_count: int
    max_attempts: int
    cancel_requested: bool
    reconciliation_required: bool
    output_artifact_id: str | None = None
    policy_snapshot_id: str
    created_at: datetime
    started_at: datetime | None = None
    terminal_at: datetime | None = None
    status_url: str
    cancel_url: str | None = None
    failures: list[dict[str, Any]] = Field(default_factory=list)


class JobCollection(BaseModel):
    items: list[JobResource]
    next_cursor: str | None = None


def _owned_job(db: Session, job_id: str, user: CurrentUser) -> WorkItemModel:
    model = db.query(WorkItemModel).filter(
        WorkItemModel.id == job_id,
        WorkItemModel.tenant_id == user.id,
    ).first()
    if model is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return model


def _resource(db: Session, model: WorkItemModel, *, include_failures: bool = True) -> JobResource:
    failures: list[dict[str, Any]] = []
    if include_failures:
        rows = db.query(FailureRecordModel).filter(
            FailureRecordModel.work_item_id == model.id,
        ).order_by(FailureRecordModel.created_at.asc()).limit(20).all()
        failures = [
            {
                "code": row.code,
                "category": row.category,
                "stage": row.stage,
                "retryable": row.retryable,
                "message": row.public_message,
                "created_at": row.created_at,
            }
            for row in rows
        ]
    terminal = model.state in {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT"}
    return JobResource(
        id=model.id,
        work_kind=model.work_kind,
        resource_type=model.resource_type,
        resource_id=model.resource_id,
        state=model.state,
        domain_outcome=model.domain_outcome,
        coverage_summary=model.coverage_summary or {},
        outcome_detail=model.outcome_detail or {},
        attempt_count=model.attempt_count,
        max_attempts=model.max_attempts,
        cancel_requested=model.cancel_requested_at is not None,
        reconciliation_required=bool(model.reconciliation_required),
        output_artifact_id=model.output_artifact_id,
        policy_snapshot_id=model.policy_snapshot_id,
        created_at=model.created_at,
        started_at=model.started_at,
        terminal_at=model.terminal_at,
        status_url=f"/api/v1/jobs/{model.id}",
        cancel_url=None if terminal else f"/api/v1/jobs/{model.id}/cancel",
        failures=failures,
    )


def _encode_cursor(model: WorkItemModel) -> str:
    value = model.created_at
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    payload = json.dumps({"created_at": value.isoformat(), "id": model.id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(value: str) -> tuple[datetime, str]:
    try:
        padded = value + "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        created_at = datetime.fromisoformat(payload["created_at"])
        return created_at, str(payload["id"])
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "INVALID_CURSOR", "message": "The pagination cursor is invalid."},
        ) from exc


@router.get("", response_model=JobCollection)
def list_jobs(
    limit: int = Query(20, ge=1, le=100),
    cursor: str | None = Query(None, max_length=512),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JobCollection:
    query = db.query(WorkItemModel).filter(WorkItemModel.tenant_id == current_user.id)
    if cursor:
        created_at, job_id = _decode_cursor(cursor)
        query = query.filter(or_(
            WorkItemModel.created_at < created_at,
            (WorkItemModel.created_at == created_at) & (WorkItemModel.id < job_id),
        ))
    rows = query.order_by(WorkItemModel.created_at.desc(), WorkItemModel.id.desc()).limit(limit + 1).all()
    has_more = len(rows) > limit
    page = rows[:limit]
    return JobCollection(
        items=[_resource(db, row, include_failures=False) for row in page],
        next_cursor=_encode_cursor(page[-1]) if has_more and page else None,
    )


@router.get("/{job_id}", response_model=JobResource)
def get_job(
    job_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JobResource:
    return _resource(db, _owned_job(db, job_id, current_user))


@router.get("/{job_id}/result")
def get_job_result(
    job_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    model = _owned_job(db, job_id, current_user)
    if model.state != "SUCCEEDED":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "JOB_NOT_COMPLETE", "message": "The job result is not ready."},
        )
    if model.work_kind not in {"RESEARCH", "FIX_PLAN", "PATCH_GENERATION"} or not model.output_artifact_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "JOB_RESULT_NOT_MATERIALIZABLE", "message": "This job has no JSON result resource."},
        )
    from app.remediation.service import RemediationExecutionService

    return RemediationExecutionService.load_result(
        db,
        tenant_id=current_user.id,
        artifact_id=model.output_artifact_id,
    )


@router.post("/{job_id}/cancel", response_model=JobResource, status_code=status.HTTP_202_ACCEPTED)
def cancel_job(
    job_id: str,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> JobResource:
    model = _owned_job(db, job_id, current_user)
    engine = DurableExecutionEngine(db, auto_commit=False)
    next_state = engine.request_cancel(
        model.id,
        tenant_id=current_user.id,
        reason="cancelled_by_user",
    )
    DomainOutbox.append(
        db,
        tenant_id=current_user.id,
        aggregate_type="WORK_ITEM",
        aggregate_id=model.id,
        event_type="WORK_CANCELLATION_REQUESTED",
        deduplication_key=f"work:{model.id}:cancel-requested",
        payload={"state": next_state.value},
    )
    AuditLedger.append(
        db,
        tenant_id=current_user.id,
        actor_id=current_user.id,
        request_id=getattr(request.state, "request_id", None),
        event_type="JOB_CANCELLATION_REQUESTED",
        resource_type="WORK_ITEM",
        resource_id=model.id,
        state_digest=model.request_digest,
        payload={"state": next_state.value},
    )
    db.commit()
    db.refresh(model)
    DurableWorkDispatcher.nudge()
    return _resource(db, model)


__all__ = ["router"]
