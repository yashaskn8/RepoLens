"""Operator-only policy, audit-integrity, outbox, and telemetry controls."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.dependencies import require_operator, verify_csrf
from app.core.database import get_db
from app.governance.events import AuditLedger, DomainOutbox
from app.governance.policies import OperationalPolicy, OperationalPolicyService
from app.governance.telemetry import TelemetryRecorder
from app.models.platform import AuditEventModel, OutboxEventModel, TelemetryMetricModel
from app.models.artifact import ArtifactDeletionAttemptModel, ArtifactModel, ArtifactTombstoneModel
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


class ArtifactDeletionRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    reason_code: str = Field(default="OPERATOR_REQUEST", pattern=r"^[A-Z][A-Z0-9_]{0,63}$")


class TenantArtifactDeletionRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)


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
        "external_reconciliation": TelemetryRecorder.aggregate(db, "external.reconciliation"),
    }


@router.get("/artifacts/lifecycle")
def get_artifact_lifecycle_state(
    _operator: CurrentUser = Depends(require_operator),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    retention = dict(
        db.query(ArtifactModel.retention_class, func.count(ArtifactModel.id))
        .group_by(ArtifactModel.retention_class)
        .all()
    )
    tombstones = dict(
        db.query(ArtifactDeletionAttemptModel.outcome, func.count(ArtifactDeletionAttemptModel.id))
        .group_by(ArtifactDeletionAttemptModel.outcome)
        .all()
    )
    return {
        "artifacts": int(db.query(func.count(ArtifactModel.id)).scalar() or 0),
        "tombstones": int(db.query(func.count(ArtifactTombstoneModel.id)).scalar() or 0),
        "by_retention_class": {str(key): int(value) for key, value in retention.items()},
        "deletion_attempts": {str(key): int(value) for key, value in tombstones.items()},
    }


@router.post("/artifacts/reconcile")
def reconcile_artifact_lifecycle(
    request: Request,
    operator: CurrentUser = Depends(require_operator),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> dict[str, int]:
    from app.artifacts.runtime import ArtifactLifecycleRuntime

    AuditLedger.append(
        db,
        tenant_id=operator.id,
        actor_id=operator.id,
        request_id=getattr(request.state, "request_id", None),
        event_type="ARTIFACT_RECONCILIATION_TRIGGERED",
        resource_type="ARTIFACT_LIFECYCLE",
        resource_id="global",
    )
    db.commit()
    return ArtifactLifecycleRuntime.sweep_once()


@router.post("/artifacts/{artifact_id}/tombstone")
def tombstone_artifact(
    artifact_id: str,
    payload: ArtifactDeletionRequest,
    request: Request,
    operator: CurrentUser = Depends(require_operator),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from app.artifacts.lifecycle import ArtifactLifecycleService
    from app.artifacts.registry import ArtifactRegistry
    from app.artifacts.service import get_artifact_store

    registry = ArtifactRegistry(db, store=get_artifact_store())
    result = ArtifactLifecycleService(registry).request_deletion(
        tenant_id=payload.tenant_id,
        artifact_id=artifact_id,
        reason_code=payload.reason_code,
        requested_by=operator.id,
        request_id=getattr(request.state, "request_id", artifact_id),
    )
    if result.status in {"REQUESTED", "REUSED"}:
        artifact = registry.get(tenant_id=payload.tenant_id, artifact_id=artifact_id)
        DomainOutbox.append(
            db,
            tenant_id=payload.tenant_id,
            aggregate_type="ARTIFACT",
            aggregate_id=artifact_id,
            event_type="ARTIFACT_DELETION_REQUESTED",
            deduplication_key=f"artifact:{artifact_id}:operator-delete",
            payload={"reason_code": payload.reason_code},
        )
        AuditLedger.append(
            db,
            tenant_id=payload.tenant_id,
            actor_id=operator.id,
            request_id=getattr(request.state, "request_id", None),
            event_type="ARTIFACT_DELETION_REQUESTED",
            resource_type="ARTIFACT",
            resource_id=artifact_id,
            artifact_digest=artifact.content_digest,
            payload={"reason_code": payload.reason_code},
        )
    db.commit()
    return {"artifact_id": artifact_id, "status": result.status, "blocker_codes": list(result.blocker_codes)}


@router.post("/artifacts/tenant-deletion")
def request_tenant_artifact_deletion(
    payload: TenantArtifactDeletionRequest,
    request: Request,
    operator: CurrentUser = Depends(require_operator),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from app.artifacts.lifecycle import ArtifactLifecycleService
    from app.artifacts.registry import ArtifactRegistry
    from app.artifacts.service import get_artifact_store

    results = ArtifactLifecycleService(
        ArtifactRegistry(db, store=get_artifact_store())
    ).request_tenant_deletion(
        tenant_id=payload.tenant_id,
        requested_by=operator.id,
        request_id=getattr(request.state, "request_id", payload.tenant_id),
    )
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    AuditLedger.append(
        db,
        tenant_id=payload.tenant_id,
        actor_id=operator.id,
        request_id=getattr(request.state, "request_id", None),
        event_type="TENANT_ARTIFACT_DELETION_REQUESTED",
        resource_type="TENANT",
        resource_id=payload.tenant_id,
        payload={"counts": counts},
    )
    db.commit()
    return {"tenant_id": payload.tenant_id, "counts": counts, "total": len(results)}
