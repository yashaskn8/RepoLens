"""Central resource authorization service with direct SQL joined ownership queries.

All ownership checks are part of DB queries — never query-then-compare in Python.
Cross-user access returns 404 (not 403) to prevent resource existence leakage.

Authorization identity: CurrentUser ONLY.
Background workers must not use these HTTP authorization helpers.
"""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.change_analysis import ChangeAnalysisModel
from app.models.delivery import DeliveryModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.review_publication import PullRequestReviewPublicationModel
from app.models.report import ReportModel
from app.models.scan import ScanModel
from app.schemas.auth import CurrentUser

_NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

_AUTH_REQUIRED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"error_code": "AUTH_REQUIRED", "message": "Authenticated user required"},
)


def _extract_user_id(current_user: CurrentUser) -> str:
    """Extract authenticated user ID from CurrentUser or raise 401 AUTH_REQUIRED.

    Only CurrentUser (resolved from session cookie via FastAPI Depends) is accepted.
    Raw strings, UserModel, UUID objects, dicts, and arbitrary objects are rejected.
    """
    if not isinstance(current_user, CurrentUser):
        raise _AUTH_REQUIRED

    if not current_user.id or not current_user.id.strip():
        raise _AUTH_REQUIRED

    return current_user.id.strip()


def get_owned_scan_or_404(db: Session, scan_id: str, current_user: CurrentUser) -> ScanModel:
    """Return scan owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
    scan = db.query(ScanModel).filter(
        ScanModel.id == scan_id,
        ScanModel.owner_user_id == user_id,
    ).first()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan with ID '{scan_id}' not found.")
    return scan


def get_owned_report_or_404(db: Session, report_id: str, current_user: CurrentUser) -> ReportModel:
    """Return a report owned by current_user or a non-enumerating 404."""
    user_id = _extract_user_id(current_user)
    report = db.query(ReportModel).filter(
        ReportModel.id == report_id,
        ReportModel.owner_user_id == user_id,
    ).first()
    if report is None:
        raise _NOT_FOUND
    return report


def get_owned_finding_or_404(db: Session, finding_id: str, current_user: CurrentUser) -> FindingModel:
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


def get_owned_patch_or_404(db: Session, patch_id: str, current_user: CurrentUser) -> PatchModel:
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


def get_owned_delivery_or_404(db: Session, delivery_id: str, current_user: CurrentUser) -> DeliveryModel:
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


def get_owned_change_analysis_or_404(db: Session, analysis_id: str, current_user: CurrentUser) -> ChangeAnalysisModel:
    """Return change analysis owned by current_user or raise 404."""
    user_id = _extract_user_id(current_user)
    analysis = db.query(ChangeAnalysisModel).filter(
        ChangeAnalysisModel.id == analysis_id,
        ChangeAnalysisModel.owner_user_id == user_id,
    ).first()
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Change analysis with ID '{analysis_id}' not found.")
    return analysis


def get_owned_review_publication_or_404(db: Session, pub_id: str, current_user: CurrentUser) -> PullRequestReviewPublicationModel:
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
