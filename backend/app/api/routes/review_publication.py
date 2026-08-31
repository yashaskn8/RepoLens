"""API routes for Safe Pull Request Review Publication (Phase 7).

Strict invariants:
- All routes require explicit human authorization.
- Review event is strictly COMMENT (never APPROVE or REQUEST_CHANGES).
- Preview → Approve → Publish flow enforced by service state machine.
- All domain exceptions map to typed HTTP error responses.
"""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.review_publication import PullRequestReviewPublicationModel
from app.schemas.review_publication import (
    ReviewPublicationApproveRequest,
    ReviewPublicationError,
    ReviewPublicationPreviewResponse,
    ReviewPublicationPublishRequest,
    ReviewPublicationPublishResponse,
    ReviewPublicationStatus,
)
from app.services.review_publication_service import ReviewPublicationService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/change-analyses/{analysis_id}/review-publication",
    tags=["Review Publication"],
)


def _pub_to_preview_response(pub: PullRequestReviewPublicationModel) -> ReviewPublicationPreviewResponse:
    """Map ORM model to Pydantic response schema."""
    return ReviewPublicationPreviewResponse(
        publication_id=UUID(pub.id),
        analysis_id=UUID(pub.analysis_id),
        status=ReviewPublicationStatus(pub.status),
        repository_owner=pub.repository_owner,
        repository_name=pub.repository_name,
        pr_number=pub.pr_number,
        base_commit_sha=pub.base_commit_sha,
        head_commit_sha=pub.head_commit_sha,
        body_markdown=pub.preview_body or "",
        preview_digest=pub.preview_digest or "",
        inline_comments=[],
        review_event="COMMENT",
        is_truncated=pub.is_truncated or False,
        truncation_reason=pub.truncation_reason,
        approved_at=pub.approved_at,
        published_at=pub.published_at,
        github_review_id=pub.github_review_id,
        github_review_url=pub.github_review_url,
        reconciliation_occurred=pub.reconciliation_occurred or False,
        failure_code=pub.failure_code,
        failure_message=pub.failure_message,
        created_at=pub.created_at,
        updated_at=pub.updated_at,
    )


def _pub_to_publish_response(pub: PullRequestReviewPublicationModel) -> ReviewPublicationPublishResponse:
    """Map ORM model to publish response schema."""
    return ReviewPublicationPublishResponse(
        publication_id=UUID(pub.id),
        analysis_id=UUID(pub.analysis_id),
        status=ReviewPublicationStatus(pub.status),
        github_review_id=pub.github_review_id,
        github_review_url=pub.github_review_url,
        published_at=pub.published_at,
        inline_comments_count=len(pub.inline_comments_payload or []),
        reconciliation_occurred=pub.reconciliation_occurred or False,
    )


@router.get(
    "",
    response_model=ReviewPublicationPreviewResponse,
    summary="Get current review publication state",
)
async def get_review_publication(
    analysis_id: UUID,
    db: Session = Depends(get_db),
):
    """Retrieve the current review publication state for a change analysis."""
    pub = db.query(PullRequestReviewPublicationModel).filter_by(analysis_id=str(analysis_id)).first()
    if not pub:
        raise HTTPException(status_code=404, detail="Review publication not found for this analysis")
    return _pub_to_preview_response(pub)


@router.post(
    "/preview",
    response_model=ReviewPublicationPreviewResponse,
    summary="Generate deterministic review publication preview (ZERO GitHub writes)",
)
async def generate_preview(
    analysis_id: UUID,
    db: Session = Depends(get_db),
):
    """Generate a deterministic preview of the review that would be published to GitHub.

    This step:
    - Validates the analysis is COMPLETED and originates from a pull request.
    - Fetches current PR state from GitHub for drift detection.
    - Renders the review markdown, computes preview_digest, and maps inline comments.
    - Makes ZERO writes to GitHub.
    """
    service = ReviewPublicationService(db=db)
    try:
        pub = await service.generate_preview(analysis_id)
        return _pub_to_preview_response(pub)
    except ReviewPublicationError as e:
        raise HTTPException(status_code=e.status_code, detail={"error_code": e.error_code, "message": e.message})


@router.post(
    "/approve",
    response_model=ReviewPublicationPreviewResponse,
    summary="Approve review preview for publication (requires exact preview digest)",
)
async def approve_preview(
    analysis_id: UUID,
    request: ReviewPublicationApproveRequest,
    db: Session = Depends(get_db),
):
    """Explicitly approve a review publication preview, binding the approval to the exact preview digest.

    This step:
    - Verifies the provided digest matches the current preview_digest.
    - Transitions publication state to APPROVED.
    - Makes ZERO writes to GitHub.
    """
    service = ReviewPublicationService(db=db)
    try:
        pub = await service.approve_preview(analysis_id, request.expected_preview_digest)
        return _pub_to_preview_response(pub)
    except ReviewPublicationError as e:
        raise HTTPException(status_code=e.status_code, detail={"error_code": e.error_code, "message": e.message})


@router.post(
    "/publish",
    response_model=ReviewPublicationPublishResponse,
    summary="Publish approved review to GitHub as COMMENT (requires explicit digest verification)",
)
async def publish_review(
    analysis_id: UUID,
    request: ReviewPublicationPublishRequest,
    db: Session = Depends(get_db),
):
    """Publish the approved review to GitHub as a COMMENT review.

    This step:
    - Re-validates digest equality.
    - Performs final drift validation against live GitHub PR state.
    - Executes atomic APPROVED -> PUBLISHING state transition.
    - Posts exactly one COMMENT review to GitHub.
    - Persists PUBLISHED state with GitHub review ID and trusted URL.
    - Handles crash recovery via deterministic marker reconciliation.
    """
    service = ReviewPublicationService(db=db)
    try:
        pub = await service.publish_review(analysis_id, request.expected_preview_digest)
        return _pub_to_publish_response(pub)
    except ReviewPublicationError as e:
        raise HTTPException(status_code=e.status_code, detail={"error_code": e.error_code, "message": e.message})
