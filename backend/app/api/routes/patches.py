"""API endpoints for patch inspection, human-in-the-loop approval, rejection, and revision."""

from datetime import datetime, timezone
import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.agents.checkpointer import get_sqlite_checkpointer
from app.core.database import get_db
from app.models.patch import PatchModel
from app.patching.workflow_graph import RemediationState, build_remediation_graph
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
async def approve_patch(
    patch_id: str,
    payload: PatchReviewRequest,
    db: Session = Depends(get_db),
):
    """Explicit human approval endpoint for a candidate patch.

    Guarantees:
    - Enforces legal state transitions (REJECTED -> APPROVED directly fails; already APPROVED fails).
    - An LLM cannot approve its own patch; approval must originate from this human action.
    - Synchronizes human approval metadata across database and durable LangGraph checkpoint.
    - Resumes the corresponding LangGraph thread as APPROVED.
    - Never commits or pushes to the repository automatically.
    """
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

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
    config = {"configurable": {"thread_id": thread_id}}
    approved_at = _utc_now()
    approved_at_iso = approved_at.isoformat()

    # Resume the LangGraph thread as APPROVED
    async with get_sqlite_checkpointer() as checkpointer:
        workflow_app = build_remediation_graph(checkpointer=checkpointer)

        # Initialize thread if not yet present in checkpointer
        state = await workflow_app.aget_state(config)
        if not state or not state.values:
            initial_state: RemediationState = {
                "scan_id": str(patch_model.scan_id),
                "finding_id": str(patch_model.finding_id),
                "patch_id": str(patch_model.id),
                "thread_id": thread_id,
                "proposal_dict": {
                    "unified_diff": patch_model.unified_diff,
                    "files_modified": patch_model.files_modified,
                },
                "patch_status": patch_model.status,
                "revision_count": 0,
            }
            await workflow_app.ainvoke(initial_state, config=config)

        await workflow_app.aupdate_state(
            config,
            {
                "patch_status": PatchStatus.APPROVED.value,
                "approved_by": payload.approved_by,
                "approved_at": approved_at_iso,
                "user_feedback": payload.notes or patch_model.user_feedback,
            },
            as_node="human_approval_checkpoint",
        )
        await workflow_app.ainvoke(None, config=config)

    patch_model.status = PatchStatus.APPROVED.value
    patch_model.approved_by = payload.approved_by
    patch_model.approved_at = approved_at
    if payload.notes:
        patch_model.user_feedback = payload.notes
    patch_model.thread_id = thread_id
    db.commit()
    db.refresh(patch_model)
    return patch_model


@router.post("/{patch_id}/reject", response_model=PatchResponse)
async def reject_patch(
    patch_id: str,
    payload: PatchRejectRequest,
    db: Session = Depends(get_db),
):
    """Explicit human rejection endpoint for a candidate patch.

    Guarantees:
    - Enforces legal state transitions (cannot re-reject an already REJECTED patch).
    - Resumes the corresponding LangGraph thread as REJECTED.
    - Synchronizes human rejection metadata across database and durable LangGraph checkpoint.
    """
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

    # Transition validation
    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Patch proposal is already REJECTED.",
        )

    thread_id = patch_model.thread_id or f"remediation-{patch_model.id}"
    config = {"configurable": {"thread_id": thread_id}}

    # Resume the LangGraph thread as REJECTED
    async with get_sqlite_checkpointer() as checkpointer:
        workflow_app = build_remediation_graph(checkpointer=checkpointer)

        state = await workflow_app.aget_state(config)
        if not state or not state.values:
            initial_state: RemediationState = {
                "scan_id": str(patch_model.scan_id),
                "finding_id": str(patch_model.finding_id),
                "patch_id": str(patch_model.id),
                "thread_id": thread_id,
                "proposal_dict": {
                    "unified_diff": patch_model.unified_diff,
                    "files_modified": patch_model.files_modified,
                },
                "patch_status": patch_model.status,
                "revision_count": 0,
            }
            await workflow_app.ainvoke(initial_state, config=config)

        await workflow_app.aupdate_state(
            config,
            {
                "patch_status": PatchStatus.REJECTED.value,
                "rejected_reason": payload.reason,
            },
            as_node="human_approval_checkpoint",
        )
        await workflow_app.ainvoke(None, config=config)

    patch_model.status = PatchStatus.REJECTED.value
    patch_model.rejected_reason = payload.reason
    patch_model.thread_id = thread_id
    db.commit()
    db.refresh(patch_model)
    return patch_model


@router.post("/{patch_id}/revise", response_model=PatchResponse)
async def request_patch_revision(
    patch_id: str,
    payload: PatchReviseRequest,
    db: Session = Depends(get_db),
):
    """Request a single targeted revision with explicit human reviewer feedback.

    Guarantees:
    - Enforces legal state transitions (APPROVED -> REVISE fails; REJECTED -> REVISE fails).
    - Resumes the corresponding LangGraph thread through the revision path with updated feedback.
    - Synchronizes revision metadata across database and durable LangGraph checkpoint.
    """
    patch_model = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
    if not patch_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch proposal '{patch_id}' not found.",
        )

    # Transition validation
    if patch_model.status == PatchStatus.APPROVED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot request revision on an already APPROVED patch.",
        )

    if patch_model.status == PatchStatus.REJECTED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot request revision on a REJECTED patch. Generate a new revision first.",
        )

    thread_id = patch_model.thread_id or f"remediation-{patch_model.id}"
    config = {"configurable": {"thread_id": thread_id}}

    # Resume the LangGraph thread as NEEDS_REVIEW through revision path
    async with get_sqlite_checkpointer() as checkpointer:
        workflow_app = build_remediation_graph(checkpointer=checkpointer)

        state = await workflow_app.aget_state(config)
        if not state or not state.values:
            initial_state: RemediationState = {
                "scan_id": str(patch_model.scan_id),
                "finding_id": str(patch_model.finding_id),
                "patch_id": str(patch_model.id),
                "thread_id": thread_id,
                "proposal_dict": {
                    "unified_diff": patch_model.unified_diff,
                    "files_modified": patch_model.files_modified,
                },
                "patch_status": patch_model.status,
                "revision_count": 0,
            }
            await workflow_app.ainvoke(initial_state, config=config)
            state = await workflow_app.aget_state(config)

        current_rev = (state.values.get("revision_count", 0) + 1) if state and state.values else 1
        await workflow_app.aupdate_state(
            config,
            {
                "patch_status": PatchStatus.NEEDS_REVIEW.value,
                "user_feedback": payload.user_feedback,
                "revision_count": current_rev,
            },
            as_node="human_approval_checkpoint",
        )
        await workflow_app.ainvoke(None, config=config)

    patch_model.status = PatchStatus.NEEDS_REVIEW.value
    patch_model.user_feedback = payload.user_feedback
    patch_model.thread_id = thread_id
    db.commit()
    db.refresh(patch_model)
    return patch_model
