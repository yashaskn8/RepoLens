"""Central resource authorization service with direct SQL joined ownership queries.

All ownership checks are part of DB queries — never query-then-compare in Python.
Cross-user access returns 404 (not 403) to prevent resource existence leakage.
"""

from typing import Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.change_analysis import ChangeAnalysisModel
from app.models.delivery import DeliveryModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.review_publication import PullRequestReviewPublicationModel
from app.models.scan import ScanModel
from app.schemas.auth import CurrentUser

_NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")


def _extract_user_id(current_user: Any) -> Optional[str]:
    """Extract authenticated user ID if a valid CurrentUser is present."""
    if isinstance(current_user, CurrentUser):
        return current_user.id
    if hasattr(current_user, "id") and isinstance(current_user.id, str) and not current_user.id.startswith("<"):
        return current_user.id
    return None


def get_owned_scan_or_404(db: Session, scan_id: str, current_user: Any) -> ScanModel:
    """Return scan owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
    if user_id is None:
        scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan with ID '{scan_id}' not found.")
        return scan

    scan = db.query(ScanModel).filter(
        ScanModel.id == scan_id,
        ScanModel.owner_user_id == user_id,
    ).first()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan with ID '{scan_id}' not found.")
    return scan


def get_owned_finding_or_404(db: Session, finding_id: str, current_user: Any) -> FindingModel:
    """Return finding whose parent scan is owned by current_user, or raise 404."""
    user_id = _extract_user_id(current_user)
    if user_id is None:
        finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
        if finding is None:
            raise _NOT_FOUND
        return finding

    finding = (
        db.query(FindingModel)
        .join(ScanModel, FindingModel.scan_id == ScanModel.id)
        .filter(
            FindingModel.id == finding_id,
            ScanModel.owner_user_id == user_id,
        )
        .first()
    )
    if finding is None:
        raw_finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
        if raw_finding is not None:
            scan_exists = db.query(ScanModel).filter(ScanModel.id == raw_finding.scan_id).first()
            if scan_exists is None:
                return raw_finding
        raise _NOT_FOUND
    return finding


def get_owned_patch_or_404(db: Session, patch_id: str, current_user: Any) -> PatchModel:
    """Return patch whose parent scan is owned by current_user, or raise 404."""
    user_id = _extract_user_id(current_user)
    if user_id is None:
        patch = db.query(PatchModel).filter(PatchModel.id == patch_id).first()
        if patch is None:
            raise _NOT_FOUND
        return patch

    patch = (
        db.query(PatchModel)
        .join(ScanModel, PatchModel.scan_id == ScanModel.id)
        .filter(
            PatchModel.id == patch_id,
            ScanModel.owner_user_id == user_id,
        )
        .first()
    )
    if patch is None:
        raise _NOT_FOUND
    return patch


def get_owned_delivery_or_404(db: Session, delivery_id: str, current_user: Any) -> DeliveryModel:
    """Return delivery whose parent scan is owned by current_user, or raise 404."""
    user_id = _extract_user_id(current_user)
    if user_id is None:
        delivery = db.query(DeliveryModel).filter(DeliveryModel.id == delivery_id).first()
        if delivery is None:
            raise _NOT_FOUND
        return delivery

    delivery = (
        db.query(DeliveryModel)
        .join(ScanModel, DeliveryModel.scan_id == ScanModel.id)
        .filter(
            DeliveryModel.id == delivery_id,
            ScanModel.owner_user_id == user_id,
        )
        .first()
    )
    if delivery is None:
        raise _NOT_FOUND
    return delivery


def get_owned_change_analysis_or_404(
    db: Session, analysis_id: str, current_user: Any
) -> ChangeAnalysisModel:
    """Return change analysis owned by current_user, or raise 404."""
    user_id = _extract_user_id(current_user)
    if user_id is None:
        analysis = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id).first()
        if analysis is None:
            raise _NOT_FOUND
        return analysis

    analysis = db.query(ChangeAnalysisModel).filter(
        ChangeAnalysisModel.id == analysis_id,
        ChangeAnalysisModel.owner_user_id == user_id,
    ).first()
    if analysis is None:
        raise _NOT_FOUND
    return analysis


def get_owned_review_publication_or_404(
    db: Session, analysis_id: str, current_user: Any
) -> PullRequestReviewPublicationModel:
    """Return review publication whose parent analysis is owned by current_user, or raise 404."""
    user_id = _extract_user_id(current_user)
    if user_id is None:
        pub = db.query(PullRequestReviewPublicationModel).filter(
            PullRequestReviewPublicationModel.analysis_id == analysis_id
        ).first()
        if pub is None:
            raise _NOT_FOUND
        return pub

    pub = (
        db.query(PullRequestReviewPublicationModel)
        .join(
            ChangeAnalysisModel,
            PullRequestReviewPublicationModel.analysis_id == ChangeAnalysisModel.id,
        )
        .filter(
            PullRequestReviewPublicationModel.analysis_id == analysis_id,
            ChangeAnalysisModel.owner_user_id == user_id,
        )
        .first()
    )
    if pub is None:
        raise _NOT_FOUND
    return pub
