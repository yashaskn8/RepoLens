"""API endpoints for patch inspection, human-in-the-loop approval, rejection, and revision."""

from datetime import datetime, timezone
import hashlib
import logging
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.api.dependencies import get_current_user, verify_csrf
from app.core.database import get_db
from app.models.patch import PatchModel
from app.governance.events import AuditLedger, DomainOutbox
# Kept as a module-level compatibility seam for integrations that previously
# patched the remediation graph while calling the review endpoints directly.
# Approval/rejection authority no longer invokes it.
from app.patching.workflow_graph import build_remediation_graph  # noqa: F401
from app.schemas.auth import CurrentUser, get_user_id
from app.schemas.enums import PatchStatus, UsageOperation
from app.schemas.patch import (
    PatchRejectRequest,
    PatchResponse,
    PatchReviewRequest,
    PatchReviseRequest,
)
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.authorization_service import get_owned_patch_or_404, get_owned_scan_or_404
from app.services.quota_service import check_and_increment_quota
from app.services.workflow_event_service import WorkflowEventService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/patches", tags=["Patches"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/{patch_id}", response_model=PatchResponse)
def get_patch_by_id(
    patch_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve details, unified diff, verification report, and approval status for a specific patch."""
    patch_model = get_owned_patch_or_404(db, str(patch_id), current_user)
    return patch_model


@router.get("/scan/{scan_id}", response_model=List[PatchResponse])
def get_patches_by_scan_id(
    scan_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve all patch proposals generated for a specific scan."""
    get_owned_scan_or_404(db, str(scan_id), current_user)
    return (
        db.query(PatchModel)
        .filter(PatchModel.scan_id == str(scan_id))
        .order_by(PatchModel.created_at.desc(), PatchModel.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.post("/{patch_id}/approve", response_model=PatchResponse)
async def approve_patch(
    patch_id: str,
    payload: PatchReviewRequest,
    request: Request = None,
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
):
    """Explicit human approval endpoint for a candidate patch."""
    patch_model = get_owned_patch_or_404(db, str(patch_id), current_user)

    # Transition validation
    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot approve a patch that has been explicitly REJECTED. Generate a new revision first.",
        )

    if patch_model.status == PatchStatus.APPROVED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Patch proposal is already APPROVED.",
        )

    thread_id = patch_model.thread_id or f"remediation-{patch_model.id}"
    approved_at = _utc_now()
    approved_at_iso = approved_at.isoformat()

    patch_model.status = PatchStatus.APPROVED.value
    patch_model.approved_by = current_user.id
    patch_model.approved_at = approved_at
    if payload.notes:
        patch_model.user_feedback = payload.notes
    patch_model.thread_id = thread_id

    # Emit durable human audit events with actor attribution
    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.HUMAN_APPROVED,
            scan_id=UUID(str(patch_model.scan_id)),
            finding_id=UUID(str(patch_model.finding_id)),
            patch_id=UUID(str(patch_model.id)),
            actor_user_id=current_user.id,
            thread_id=thread_id,
            stage="human_review",
            message=f"Patch approved by user {current_user.id}",
            metadata_payload={"approved_by": current_user.id, "notes": payload.notes},
        ),
        critical=True,
    )
    state_digest = hashlib.sha256(
        f"{patch_model.id}:{patch_model.status}:{patch_model.approved_by}:{approved_at_iso}".encode("utf-8")
    ).hexdigest()
    AuditLedger.append(
        db,
        tenant_id=current_user.id,
        actor_id=current_user.id,
        request_id=getattr(getattr(request, "state", None), "request_id", None),
        event_type="HUMAN_PATCH_APPROVED",
        resource_type="PATCH",
        resource_id=str(patch_model.id),
        state_digest=state_digest,
        payload={"scan_id": str(patch_model.scan_id), "finding_id": str(patch_model.finding_id)},
    )
    DomainOutbox.append(
        db,
        tenant_id=current_user.id,
        aggregate_type="PATCH",
        aggregate_id=str(patch_model.id),
        event_type="PATCH_APPROVED",
        deduplication_key=f"patch:{patch_model.id}:approved",
        payload={"approved_by": current_user.id},
    )
    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.PATCH_APPROVED,
            scan_id=UUID(str(patch_model.scan_id)),
            finding_id=UUID(str(patch_model.finding_id)),
            patch_id=UUID(str(patch_model.id)),
            actor_user_id=current_user.id,
            thread_id=thread_id,
            stage="human_review",
            message="Patch transitioned to APPROVED status",
            metadata_payload={"approved_by": current_user.id},
        ),
        critical=True,
    )

    db.commit()
    db.refresh(patch_model)
    return patch_model


@router.post("/{patch_id}/reject", response_model=PatchResponse)
async def reject_patch(
    patch_id: str,
    payload: PatchRejectRequest,
    request: Request = None,
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
):
    """Explicit human rejection endpoint for a candidate patch."""
    patch_model = get_owned_patch_or_404(db, str(patch_id), current_user)

    # Transition validation
    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Patch proposal is already REJECTED.",
        )

    thread_id = patch_model.thread_id or f"remediation-{patch_model.id}"

    patch_model.status = PatchStatus.REJECTED.value
    patch_model.rejected_reason = payload.reason
    patch_model.thread_id = thread_id

    # Emit durable human audit events with actor attribution
    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.HUMAN_REJECTED,
            scan_id=UUID(str(patch_model.scan_id)),
            finding_id=UUID(str(patch_model.finding_id)),
            patch_id=UUID(str(patch_model.id)),
            actor_user_id=get_user_id(current_user),
            thread_id=thread_id,
            stage="human_review",
            message=f"Patch rejected: {payload.reason}",
            metadata_payload={"reason": payload.reason},
        ),
        critical=True,
    )
    state_digest = hashlib.sha256(
        f"{patch_model.id}:{patch_model.status}:{patch_model.rejected_reason}".encode("utf-8")
    ).hexdigest()
    AuditLedger.append(
        db,
        tenant_id=current_user.id,
        actor_id=current_user.id,
        request_id=getattr(getattr(request, "state", None), "request_id", None),
        event_type="HUMAN_PATCH_REJECTED",
        resource_type="PATCH",
        resource_id=str(patch_model.id),
        state_digest=state_digest,
        payload={"scan_id": str(patch_model.scan_id), "finding_id": str(patch_model.finding_id)},
    )
    DomainOutbox.append(
        db,
        tenant_id=current_user.id,
        aggregate_type="PATCH",
        aggregate_id=str(patch_model.id),
        event_type="PATCH_REJECTED",
        deduplication_key=f"patch:{patch_model.id}:rejected",
        payload={"rejected_by": current_user.id},
    )
    WorkflowEventService.emit(
        db=db,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.PATCH_REJECTED,
            scan_id=UUID(str(patch_model.scan_id)),
            finding_id=UUID(str(patch_model.finding_id)),
            patch_id=UUID(str(patch_model.id)),
            actor_user_id=get_user_id(current_user),
            thread_id=thread_id,
            stage="human_review",
            message="Patch transitioned to REJECTED status",
            metadata_payload={"reason": payload.reason},
        ),
        critical=True,
    )

    db.commit()
    db.refresh(patch_model)

    return patch_model


@router.post("/{patch_id}/revise", response_model=PatchResponse)
async def request_patch_revision(
    patch_id: str,
    payload: PatchReviseRequest,
    request: Request = None,
    response: Response = None,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
):
    """Generate one revision under the canonical WorkItem/Attempt/Lease authority."""
    from app.api.idempotency import idempotency_identity
    from app.core.config import get_settings
    from app.execution.application import NewWorkPaused, WorkSubmissionService
    from app.execution.dispatcher import DurableWorkDispatcher
    from app.execution.errors import IdempotencyConflict
    from app.execution.types import RequestBudget, ResourceProfile, WorkKind

    patch_model = get_owned_patch_or_404(db, str(patch_id), current_user)
    if patch_model.status == PatchStatus.APPROVED.value:
        raise HTTPException(status_code=400, detail="Cannot request revision on an already APPROVED patch.")
    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(status_code=400, detail="Cannot request revision on a REJECTED patch. Generate a new revision from the finding instead.")
    if (patch_model.revision_number or 0) >= 1:
        raise HTTPException(status_code=400, detail="Maximum of 1 human revision allowed per patch lineage. Cannot revise a child revision.")

    existing_child = db.query(PatchModel).filter(PatchModel.parent_patch_id == str(patch_id)).first()
    if existing_child is not None:
        if existing_child.user_feedback == payload.user_feedback:
            return existing_child
        raise HTTPException(status_code=400, detail="A revision child has already been created for this patch proposal.")

    feedback_digest = hashlib.sha256(payload.user_feedback.encode("utf-8")).hexdigest()
    client_identity = idempotency_identity(
        "patch-revision",
        idempotency_key,
        maximum=get_settings().IDEMPOTENCY_KEY_MAX_LENGTH,
    )
    identity = client_identity or f"patch-revision:{patch_id}:{feedback_digest}"
    try:
        submission = WorkSubmissionService().submit(
            db,
            tenant_id=current_user.id,
            actor_id=current_user.id,
            request_id=getattr(getattr(request, "state", None), "request_id", str(uuid4())),
            work_kind=WorkKind.PATCH_GENERATION,
            resource_type="PATCH_REVISION",
            resource_id=str(patch_id),
            request_payload={"parent_patch_id": str(patch_id), "user_feedback": payload.user_feedback},
            idempotency_key=identity,
            external_idempotency_key=client_identity,
            resource_profile=ResourceProfile.PATCH_GENERATION,
            budget=RequestBudget(
                max_wall_clock_seconds=get_settings().MAX_SCAN_DURATION_SECONDS,
                max_ai_calls=10,
                max_input_tokens=250_000,
                max_output_tokens=50_000,
                max_escalation_tier=2,
                max_retrieval_context_tokens=125_000,
            ),
            input_artifact_id=patch_model.result_artifact_id,
        )
        if not submission.result.reused:
            check_and_increment_quota(db, current_user.id, UsageOperation.PATCH_GENERATE.value)
            WorkflowEventService.emit_critical(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.HUMAN_REVISION_REQUESTED,
                    scan_id=UUID(str(patch_model.scan_id)),
                    finding_id=UUID(str(patch_model.finding_id)),
                    patch_id=UUID(str(patch_model.id)),
                    actor_user_id=current_user.id,
                    thread_id=patch_model.thread_id,
                    stage="human_review",
                    message="Human revision requested with feedback",
                    metadata_payload={"feedback_digest": feedback_digest},
                ),
            )
        db.commit()
    except NewWorkPaused as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail={"error_code": "NEW_JOBS_PAUSED", "message": str(exc)}) from exc
    except IdempotencyConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail={"error_code": "IDEMPOTENCY_CONFLICT", "message": str(exc)}) from exc

    execution = await DurableWorkDispatcher.execute_specific(
        submission.result.work_item_id,
        session_factory=sessionmaker(
            bind=db.get_bind(),
            autoflush=False,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ),
    )
    if (
        execution["state"] == "FAILED"
        and execution.get("failure_code") == "MODEL_INVALID_OUTPUT"
        and str(execution.get("failure_message") or "").startswith("PATCH_PLAN_PROVENANCE_MISMATCH:")
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(execution["failure_message"]),
        )
    if execution["state"] != "SUCCEEDED" or not execution["outcome_detail"].get("patch_id"):
        db.expire_all()
        conflicting_child = db.execute(
            select(PatchModel).where(PatchModel.parent_patch_id == str(patch_id))
        ).scalar_one_or_none()
        if conflicting_child is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A revision child has already been created for this patch proposal (concurrent conflict).",
            )
        DurableWorkDispatcher.nudge()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error_code": "REVISION_QUEUED", "message": "Revision is durably queued; inspect the job resource."},
            headers={"Location": f"/api/v1/jobs/{submission.result.work_item_id}"},
        )
    child = get_owned_patch_or_404(db, str(execution["outcome_detail"]["patch_id"]), current_user)
    return child
