"""API endpoints for patch inspection, human-in-the-loop approval, rejection, and revision."""

from datetime import datetime, timezone
import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.patch import PatchModel
from app.schemas.enums import PatchStatus
from app.schemas.patch import (
    PatchRejectRequest,
    PatchResponse,
    PatchReviewRequest,
    PatchReviseRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/patches", tags=["Patches"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/{patch_id}", response_model=PatchResponse)
def get_patch_by_id(patch_id: str, db: Session = Depends(get_db)):
    """Retrieve details, unified diff, verification report, and approval status for a specific patch."""
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )
    return patch_model


@router.get("/scan/{scan_id}", response_model=List[PatchResponse])
def get_patches_by_scan_id(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve all patch proposals generated for a specific scan."""
    return db.query(PatchModel).filter(PatchModel.scan_id == str(scan_id)).all()


@router.post("/{patch_id}/approve", response_model=PatchResponse)
def approve_patch(patch_id: str, payload: PatchReviewRequest, db: Session = Depends(get_db)):
    """Explicit human approval endpoint for a candidate patch.
    
    Guarantees:
    - An LLM cannot approve its own patch; approval must originate from this human action.
    - Transitions status to APPROVED.
    - Never commits or pushes to the repository automatically.
    """
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot approve a patch that has been explicitly REJECTED. Generate a new revision first.",
        )

    patch_model.status = PatchStatus.APPROVED.value
    patch_model.approved_by = payload.approved_by
    patch_model.approved_at = _utc_now()
    if payload.notes:
        patch_model.user_feedback = payload.notes
    db.commit()
    db.refresh(patch_model)
    return patch_model


@router.post("/{patch_id}/reject", response_model=PatchResponse)
def reject_patch(patch_id: str, payload: PatchRejectRequest, db: Session = Depends(get_db)):
    """Explicit human rejection endpoint for a candidate patch."""
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

    patch_model.status = PatchStatus.REJECTED.value
    patch_model.rejected_reason = payload.reason
    db.commit()
    db.refresh(patch_model)
    return patch_model


@router.post("/{patch_id}/revise", response_model=PatchResponse)
def request_patch_revision(patch_id: str, payload: PatchReviseRequest, db: Session = Depends(get_db)):
    """Request a single targeted revision with explicit human reviewer feedback."""
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

    patch_model.status = PatchStatus.NEEDS_REVIEW.value
    patch_model.user_feedback = payload.user_feedback
    db.commit()
    db.refresh(patch_model)
    return patch_model
