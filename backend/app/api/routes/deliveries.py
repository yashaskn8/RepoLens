"""API endpoints for patch delivery preview, safe execution, and status tracking."""

import logging
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.delivery.service import DeliveryService
from app.models.delivery import DeliveryModel
from app.schemas.delivery import (
    DeliveryPreviewResponse,
    DeliveryRequest,
    DeliveryResponse,
)

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
    db: Session = Depends(get_db),
    service: DeliveryService = Depends(get_delivery_service),
):
    """Provide a read-only deterministic preview of pull request delivery eligibility."""
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
    db: Session = Depends(get_db),
    service: DeliveryService = Depends(get_delivery_service),
):
    """Explicit human action to deliver an already-approved remediation patch to GitHub."""
    return await service.deliver_patch(db=db, patch_id=patch_id, payload=payload)


@router.get(
    "/deliveries/{delivery_id}",
    response_model=DeliveryResponse,
    summary="Get delivery execution status",
)
def get_delivery_by_id(
    delivery_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve details and lifecycle status for a specific delivery execution."""
    delivery = db.query(DeliveryModel).filter(DeliveryModel.id == str(delivery_id)).first()
    if not delivery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delivery record '{delivery_id}' not found.",
        )
    return delivery


@router.get(
    "/deliveries/patch/{patch_id}",
    response_model=Optional[DeliveryResponse],
    summary="Get delivery record for a specific patch",
)
def get_delivery_by_patch_id(
    patch_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve the latest delivery record for a given patch proposal if one exists."""
    return db.query(DeliveryModel).filter(DeliveryModel.patch_id == str(patch_id)).order_by(DeliveryModel.created_at.desc()).first()
