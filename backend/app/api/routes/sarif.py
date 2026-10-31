"""Owned, read-only SARIF export of verified repository scan findings."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session, selectinload

from app.api.dependencies import get_current_user
from app.core.database import get_db
from app.models.finding import FindingModel
from app.reporting.sarif import SarifTooLarge, build_sarif_document, encode_sarif
from app.schemas.auth import CurrentUser
from app.schemas.enums import FindingStatus, ScanStatus, VerificationVerdict
from app.services.authorization_service import get_owned_scan_or_404


router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("/{scan_id}/sarif", response_class=Response)
def export_scan_sarif(
    scan_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Export only OPEN, canonically verified findings of a completed owned scan.

    No model calls, remote writes, repository execution, or side effects.
    An oversized result fails closed instead of silently dropping alerts.
    """
    scan = get_owned_scan_or_404(db, str(scan_id), current_user)
    if scan.status != ScanStatus.COMPLETED.value:
        raise HTTPException(
            status_code=409,
            detail={"error_code": "SCAN_NOT_COMPLETED", "message": "SARIF export requires a completed scan."},
        )

    candidates = (
        db.query(FindingModel)
        .options(selectinload(FindingModel.evidences))
        .filter(
            FindingModel.scan_id == str(scan_id),
            FindingModel.status == FindingStatus.OPEN.value,
            FindingModel.verification_verdict == VerificationVerdict.CONFIRMED.value,
        )
        .order_by(FindingModel.id.asc())
        .yield_per(200)
    )
    try:
        document = build_sarif_document(candidates, commit_sha=scan.commit_hash or "")
    except SarifTooLarge:
        raise HTTPException(
            status_code=413,
            detail={"error_code": "SARIF_EXPORT_TOO_LARGE", "message": "SARIF export exceeds bounded limits."},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={"error_code": "SCAN_COMMIT_UNAVAILABLE", "message": "A verified commit SHA is required."},
        ) from None

    return Response(
        content=encode_sarif(document),
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": f'attachment; filename="repolens-{scan_id}.sarif"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
