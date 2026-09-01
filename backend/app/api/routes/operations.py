"""Operator-only policy, audit-integrity, outbox, and telemetry controls."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.dependencies import require_operator, verify_csrf
from app.core.database import get_db
from app.governance.events import AuditLedger, DomainOutbox
from app.governance.policies import OperationalPolicy, OperationalPolicyService
from app.governance.telemetry import TelemetryRecorder
from app.models.platform import AuditEventModel, OutboxEventModel, TelemetryMetricModel
from app.schemas.auth import CurrentUser


router = APIRouter(prefix="/operations", tags=["Operations"])


class PolicyResource(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_scope: str
    version: int
    content_digest: str
    policy_payload: dict[str, Any]
    active: bool


@router.get("/policy", response_model=PolicyResource)
def get_active_policy(
    _operator: CurrentUser = Depends(require_operator),
    db: Session = Depends(get_db),
) -> PolicyResource:
    policy = OperationalPolicyService.ensure_active(db)
    db.commit()
    db.refresh(policy)
    return PolicyResource.model_validate(policy)


@router.put("/policy", response_model=PolicyResource)
def replace_active_policy(
    payload: OperationalPolicy,
    request: Request,
    operator: CurrentUser = Depends(require_operator),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> PolicyResource:
    policy = OperationalPolicyService.snapshot(db, payload, actor_id=operator.id)
    DomainOutbox.append(
        db,
        tenant_id=operator.id,
        aggregate_type="OPERATIONAL_POLICY",
        aggregate_id=policy.id,
        event_type="OPERATIONAL_POLICY_CHANGED",
        deduplication_key=f"policy:{policy.content_digest}",
        payload={"version": policy.version, "digest": policy.content_digest},
    )
    AuditLedger.append(
        db,
        tenant_id=operator.id,
        event_type="ADMINISTRATIVE_POLICY_CHANGED",
        actor_id=operator.id,
        request_id=getattr(request.state, "request_id", None),
        resource_type="OPERATIONAL_POLICY",
        resource_id=policy.id,
        state_digest=policy.content_digest,
        payload={"version": policy.version},
    )
    db.commit()
    db.refresh(policy)
    return PolicyResource.model_validate(policy)


@router.get("/audit/{tenant_id}/verify")
def verify_audit_chain(
    tenant_id: str,
    _operator: CurrentUser = Depends(require_operator),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if len(tenant_id) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "USER_INPUT_ERROR", "message": "Invalid tenant identifier."},
        )
    count = db.query(func.count(AuditEventModel.id)).filter(AuditEventModel.tenant_id == tenant_id).scalar() or 0
    return {"tenant_id": tenant_id, "valid": AuditLedger.verify(db, tenant_id), "event_count": int(count)}


@router.get("/telemetry")
def get_platform_telemetry(
    _operator: CurrentUser = Depends(require_operator),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    outbox_counts = dict(db.query(OutboxEventModel.status, func.count(OutboxEventModel.id)).group_by(
        OutboxEventModel.status
    ).all())
    return {
        "outbox": {str(key): int(value) for key, value in outbox_counts.items()},
        "audit_events": int(db.query(func.count(AuditEventModel.id)).scalar() or 0),
        "telemetry_metrics": int(db.query(func.count(TelemetryMetricModel.id)).scalar() or 0),
        "request_duration": TelemetryRecorder.aggregate(db, "request.duration"),
        "job_queue_wait": TelemetryRecorder.aggregate(db, "job.queue_wait"),
        "provider_latency": TelemetryRecorder.aggregate(db, "provider.latency"),
        "artifact_reuse": TelemetryRecorder.aggregate(db, "artifact.reuse"),
        "report_generation": TelemetryRecorder.aggregate(db, "report.generation_duration"),
    }
