"""API endpoints for patch delivery preview, safe execution, and status tracking."""

import logging
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, require_operator, verify_csrf
from app.core.database import get_db
from app.delivery.service import DeliveryService
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
    status_code=status.HTTP_200_OK,
    summary="Deliver approved patch as a GitHub Pull Request",
)
async def deliver_patch(
    patch_id: str,
    payload: DeliveryRequest = DeliveryRequest(requested_by="user"),
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
    return await service.deliver_patch(db=db, patch_id=patch_id, payload=authenticated_payload)


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
