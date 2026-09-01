"""API endpoints for patch delivery preview, safe execution, and status tracking."""

import logging
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.orm import Session, sessionmaker

from app.api.dependencies import get_current_user, require_operator, verify_csrf
from app.api.idempotency import idempotency_identity
from app.core.config import get_settings
from app.core.database import get_db
from app.delivery.service import DeliveryService
from app.execution.application import NewWorkPaused, WorkPolicyViolation, WorkSubmissionService
from app.execution.dispatcher import DurableWorkDispatcher
from app.execution.errors import IdempotencyConflict
from app.execution.types import RequestBudget, ResourceProfile, SideEffectClass, WorkKind
from app.models.delivery import DeliveryModel
from app.schemas.auth import CurrentUser
from app.schemas.delivery import (
    DeliveryPreviewResponse,
    DeliveryRequest,
    DeliveryResponse,
)
from app.services.authorization_service import get_owned_delivery_or_404, get_owned_patch_or_404

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Safe GitHub Delivery"])


def get_delivery_service() -> DeliveryService:
    """Dependency provider for DeliveryService instance."""
    return DeliveryService()


@router.get(
    "/patches/{patch_id}/delivery-preview",
    response_model=DeliveryPreviewResponse,
    summary="Preview GitHub PR delivery eligibility",
)
async def get_delivery_preview(
    patch_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: DeliveryService = Depends(get_delivery_service),
):
    """Provide a read-only deterministic preview of pull request delivery eligibility."""
    get_owned_patch_or_404(db, patch_id, current_user)
    return await service.get_delivery_preview(db=db, patch_id=patch_id)


@router.post(
    "/patches/{patch_id}/deliver",
    response_model=DeliveryResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Deliver approved patch as a GitHub Pull Request",
)
async def deliver_patch(
    patch_id: str,
    request: Request,
    response: Response,
    payload: DeliveryRequest = DeliveryRequest(requested_by="user"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    prefer: str | None = Header(default=None, alias="Prefer"),
    current_user: CurrentUser = Depends(require_operator),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
    service: DeliveryService = Depends(get_delivery_service),
):
    """Explicit operator action to deliver an already-approved remediation patch to GitHub."""
    get_owned_patch_or_404(db, patch_id, current_user)
    authenticated_payload = DeliveryRequest(
        requested_by=current_user.id,
        notes=payload.notes if payload else None,
    )
    client_identity = idempotency_identity(
        "github-delivery",
        idempotency_key,
        maximum=get_settings().IDEMPOTENCY_KEY_MAX_LENGTH,
    )
    try:
        delivery = service.prepare_delivery(db=db, patch_id=patch_id, payload=authenticated_payload)
        submission = WorkSubmissionService().submit(
            db,
            tenant_id=current_user.id,
            actor_id=current_user.id,
            request_id=getattr(request.state, "request_id", delivery.id),
            work_kind=WorkKind.GITHUB_DELIVERY,
            resource_type="DELIVERY",
            resource_id=str(delivery.id),
            request_payload={
                "delivery_id": str(delivery.id),
                "patch_id": str(patch_id),
                "semantic_idempotency_key": delivery.idempotency_key,
                "notes": authenticated_payload.notes,
            },
            idempotency_key=client_identity or delivery.idempotency_key,
            external_idempotency_key=delivery.idempotency_key,
            resource_profile=ResourceProfile.GITHUB_WRITE,
            side_effect_class=SideEffectClass.EXTERNAL_SIDE_EFFECT,
            budget=RequestBudget(max_wall_clock_seconds=get_settings().MAX_SCAN_DURATION_SECONDS),
        )
        db.commit()
        db.refresh(delivery)
    except (NewWorkPaused, WorkPolicyViolation) as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error_code": "GITHUB_WRITES_DISABLED", "message": str(exc)},
        ) from exc
    except IdempotencyConflict as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "IDEMPOTENCY_CONFLICT", "message": str(exc)},
        ) from exc
    response.headers["Location"] = f"/api/v1/deliveries/{delivery.id}"
    response.headers["X-Job-Location"] = f"/api/v1/jobs/{submission.result.work_item_id}"
    response.headers["Idempotency-Replayed"] = "true" if submission.result.reused else "false"
    if prefer and "respond-async" in prefer.lower():
        DurableWorkDispatcher.nudge()
        return delivery
    execution = await DurableWorkDispatcher.execute_specific(
        submission.result.work_item_id,
        session_factory=sessionmaker(bind=db.get_bind(), autoflush=False, expire_on_commit=False),
    )
    db.expire_all()
    current = get_owned_delivery_or_404(db, str(delivery.id), current_user)
    if execution["state"] in {"LEASED", "RUNNING", "QUEUED", "READY", "RETRY_WAIT"}:
        DurableWorkDispatcher.nudge()
    else:
        response.status_code = status.HTTP_200_OK
    return current


@router.get(
    "/deliveries/{delivery_id}",
    response_model=DeliveryResponse,
    summary="Get delivery execution status",
)
def get_delivery_by_id(
    delivery_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve details and lifecycle status for a specific delivery execution."""
    return get_owned_delivery_or_404(db, str(delivery_id), current_user)


@router.get(
    "/deliveries/patch/{patch_id}",
    response_model=Optional[DeliveryResponse],
    summary="Get delivery record for a specific patch",
)
def get_delivery_by_patch_id(
    patch_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve the latest delivery record for a given patch proposal if one exists."""
    get_owned_patch_or_404(db, patch_id, current_user)
    return db.query(DeliveryModel).filter(DeliveryModel.patch_id == str(patch_id)).order_by(DeliveryModel.created_at.desc()).first()
