"""API routes for Safe Pull Request Review Publication (Phase 7 & Phase 8).

Strict invariants:
- All routes require OPERATOR role and explicit human authorization.
- Cross-tenant access returns 404 (direct joined ownership verification).
- CSRF verification on state-modifying POST endpoints.
- Review event is strictly COMMENT (never APPROVE or REQUEST_CHANGES).
- Preview -> Approve -> Publish flow enforced by service state machine.
- All domain exceptions map to typed HTTP error responses.
"""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.orm import Session, sessionmaker

from app.api.dependencies import get_db, require_operator, verify_csrf
from app.api.idempotency import idempotency_identity
from app.core.config import get_settings
from app.execution.application import NewWorkPaused, WorkPolicyViolation, WorkSubmissionService
from app.execution.dispatcher import DurableWorkDispatcher
from app.execution.errors import IdempotencyConflict
from app.execution.types import RequestBudget, ResourceProfile, SideEffectClass, WorkKind
from app.models.review_publication import PullRequestReviewPublicationModel
from app.schemas.auth import CurrentUser
from app.schemas.review_publication import (
    InlineReviewCommentPreview,
    ReviewPublicationApproveRequest,
    ReviewPublicationError,
    ReviewPublicationPreviewResponse,
    ReviewPublicationPublishRequest,
    ReviewPublicationPublishResponse,
    ReviewPublicationStatus,
)
from app.services.authorization_service import get_owned_change_analysis_or_404
from app.services.review_publication_service import ReviewPublicationService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/change-analyses/{analysis_id}/review-publication",
    tags=["Review Publication"],
)


def _pub_to_preview_response(pub: PullRequestReviewPublicationModel) -> ReviewPublicationPreviewResponse:
    """Map ORM model to Pydantic response schema with deserialized inline comment previews."""
    inline_previews: List[InlineReviewCommentPreview] = []
    if pub.inline_comments_payload:
        for c in pub.inline_comments_payload:
            if isinstance(c, dict):
                inline_previews.append(
                    InlineReviewCommentPreview(
                        path=c.get("path", ""),
                        line=int(c.get("line", 1)),
                        side=c.get("side", "RIGHT"),
                        body=c.get("body", ""),
                        finding_id=c.get("finding_id"),
                        finding_title=c.get("finding_title"),
                        severity=c.get("severity"),
                    )
                )

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
        inline_comments=inline_previews,
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
    current_user: CurrentUser = Depends(require_operator),
    db: Session = Depends(get_db),
):
    """Retrieve the current review publication state for a change analysis."""
    get_owned_change_analysis_or_404(db, str(analysis_id), current_user)
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
    current_user: CurrentUser = Depends(require_operator),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
):
    """Generate a deterministic preview of the review that would be published to GitHub."""
    get_owned_change_analysis_or_404(db, str(analysis_id), current_user)
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
    payload: ReviewPublicationApproveRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_operator),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
):
    """Explicitly approve a review publication preview, binding the approval to the exact preview digest."""
    get_owned_change_analysis_or_404(db, str(analysis_id), current_user)
    service = ReviewPublicationService(db=db)
    try:
        pub = await service.approve_preview(
            analysis_id,
            payload.expected_preview_digest,
            actor_id=current_user.id,
            request_id=getattr(request.state, "request_id", None),
        )
        return _pub_to_preview_response(pub)
    except ReviewPublicationError as e:
        raise HTTPException(status_code=e.status_code, detail={"error_code": e.error_code, "message": e.message})


@router.post(
    "/publish",
    response_model=ReviewPublicationPublishResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Publish approved review to GitHub as COMMENT (requires explicit digest verification)",
)
async def publish_review(
    analysis_id: UUID,
    payload: ReviewPublicationPublishRequest,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    prefer: str | None = Header(default=None, alias="Prefer"),
    current_user: CurrentUser = Depends(require_operator),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
):
    """Publish the approved review to GitHub as a COMMENT review."""
    get_owned_change_analysis_or_404(db, str(analysis_id), current_user)
    pub = db.query(PullRequestReviewPublicationModel).filter_by(analysis_id=str(analysis_id)).first()
    if pub is None:
        raise HTTPException(status_code=404, detail="Review publication not found for this analysis")
    if pub.status == ReviewPublicationStatus.PUBLISHED.value:
        response.status_code = status.HTTP_200_OK
        return _pub_to_publish_response(pub)
    if pub.status != ReviewPublicationStatus.APPROVED.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "PUBLICATION_NOT_APPROVED", "message": "Review publication must be approved first."},
        )
    if pub.preview_digest != payload.expected_preview_digest:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "PREVIEW_DIGEST_MISMATCH", "message": "The approved preview digest does not match."},
        )
    client_identity = idempotency_identity(
        "review-publication",
        idempotency_key,
        maximum=get_settings().IDEMPOTENCY_KEY_MAX_LENGTH,
    )
    semantic_identity = f"review:{pub.id}:{pub.preview_digest}"
    try:
        submission = WorkSubmissionService().submit(
            db,
            tenant_id=current_user.id,
            actor_id=current_user.id,
            request_id=getattr(request.state, "request_id", pub.id),
            work_kind=WorkKind.REVIEW_PUBLICATION,
            resource_type="REVIEW_PUBLICATION",
            resource_id=str(pub.id),
            request_payload={
                "publication_id": str(pub.id),
                "analysis_id": str(analysis_id),
                "preview_digest": pub.preview_digest,
            },
            idempotency_key=client_identity or semantic_identity,
            external_idempotency_key=semantic_identity,
            resource_profile=ResourceProfile.GITHUB_WRITE,
            side_effect_class=SideEffectClass.EXTERNAL_SIDE_EFFECT,
            budget=RequestBudget(max_wall_clock_seconds=get_settings().MAX_SCAN_DURATION_SECONDS),
        )
        db.commit()
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
    response.headers["Location"] = f"/api/v1/change-analyses/{analysis_id}/review-publication"
    response.headers["X-Job-Location"] = f"/api/v1/jobs/{submission.result.work_item_id}"
    response.headers["Idempotency-Replayed"] = "true" if submission.result.reused else "false"
    if prefer and "respond-async" in prefer.lower():
        DurableWorkDispatcher.nudge()
        return _pub_to_publish_response(pub)
    execution = await DurableWorkDispatcher.execute_specific(
        submission.result.work_item_id,
        session_factory=sessionmaker(
            bind=db.get_bind(),
            autoflush=False,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ),
    )
    db.expire_all()
    pub = db.query(PullRequestReviewPublicationModel).filter_by(id=str(pub.id)).first()
    if execution["state"] in {"LEASED", "RUNNING", "QUEUED", "READY", "RETRY_WAIT"}:
        DurableWorkDispatcher.nudge()
    else:
        response.status_code = status.HTTP_200_OK
    return _pub_to_publish_response(pub)
