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
from app.models.user import UserModel
from app.schemas.auth import CurrentUser

_NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")


def _extract_user_id(current_user: Any) -> str:
    """Extract authenticated user ID or raise 401 AUTH_REQUIRED."""
    if isinstance(current_user, CurrentUser):
        if current_user.id and current_user.id.strip():
            return current_user.id.strip()
    elif isinstance(current_user, UserModel):
        if current_user.id and str(current_user.id).strip():
            return str(current_user.id).strip()
    elif isinstance(current_user, str):
        if current_user.strip():
            return current_user.strip()

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error_code": "AUTH_REQUIRED", "message": "Authenticated user required"},
    )


def get_owned_scan_or_404(db: Session, scan_id: str, current_user: Any) -> ScanModel:
    """Return scan owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
    scan = db.query(ScanModel).filter(
        ScanModel.id == scan_id,
        ScanModel.owner_user_id == user_id,
    ).first()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan with ID '{scan_id}' not found.")
    return scan


def get_owned_finding_or_404(db: Session, finding_id: str, current_user: Any) -> FindingModel:
    """Return finding belonging to a scan owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding with ID '{finding_id}' not found.")
    return finding


def get_owned_patch_or_404(db: Session, patch_id: str, current_user: Any) -> PatchModel:
    """Return patch belonging to a scan owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch with ID '{patch_id}' not found.")
    return patch


def get_owned_delivery_or_404(db: Session, delivery_id: str, current_user: Any) -> DeliveryModel:
    """Return delivery belonging to a patch/scan owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Delivery with ID '{delivery_id}' not found.")
    return delivery


def get_owned_change_analysis_or_404(db: Session, analysis_id: str, current_user: Any) -> ChangeAnalysisModel:
    """Return change analysis owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
    analysis = db.query(ChangeAnalysisModel).filter(
        ChangeAnalysisModel.id == analysis_id,
        ChangeAnalysisModel.owner_user_id == user_id,
    ).first()
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Change analysis with ID '{analysis_id}' not found.")
    return analysis


def get_owned_review_publication_or_404(db: Session, pub_id: str, current_user: Any) -> PullRequestReviewPublicationModel:
    """Return review publication belonging to a change analysis owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
    pub = (
        db.query(PullRequestReviewPublicationModel)
        .join(ChangeAnalysisModel, PullRequestReviewPublicationModel.analysis_id == ChangeAnalysisModel.id)
        .filter(
            PullRequestReviewPublicationModel.id == pub_id,
            ChangeAnalysisModel.owner_user_id == user_id,
        )
        .first()
    )
    if pub is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Review publication with ID '{pub_id}' not found.")
    return pub
