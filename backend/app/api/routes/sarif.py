"""Tenant-scoped SARIF download for completed repository scans."""

from __future__ import annotations

import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session, selectinload

from app.api.dependencies import get_current_user
from app.core.database import get_db
from app.models.finding import FindingModel
from app.reporting.sarif import build_sarif
from app.schemas.auth import CurrentUser
from app.schemas.enums import FindingStatus, ScanStatus, VerificationVerdict
from app.services.authorization_service import get_owned_scan_or_404
from app.services.finding_grounding import is_canonical_confirmed_finding

router = APIRouter(prefix="/scans", tags=["Scan Exports"])

# GitHub displays only 5,000 results per SARIF run. Never silently truncate.
MAX_SARIF_RESULTS = 5_000
MAX_SARIF_BYTES = 10_000_000
BATCH_SIZE = 500


@router.get("/{scan_id}/sarif")
def download_scan_sarif(
    scan_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    scan = get_owned_scan_or_404(db, str(scan_id), current_user)
    if scan.status != ScanStatus.COMPLETED.value or not scan.commit_hash or len(scan.commit_hash) != 40:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "SCAN_NOT_EXPORTABLE", "message": "SARIF requires a completed scan at an immutable commit."},
        )

    verified: list[FindingModel] = []
    last_id: str | None = None
    while True:
        query = (
            db.query(FindingModel)
            .options(selectinload(FindingModel.evidences))
            .filter(
                FindingModel.scan_id == scan.id,
                FindingModel.status == FindingStatus.OPEN.value,
                FindingModel.verification_verdict == VerificationVerdict.CONFIRMED.value,
            )
        )
        if last_id is not None:
            query = query.filter(FindingModel.id > last_id)
        batch = query.order_by(FindingModel.id.asc()).limit(BATCH_SIZE).all()
        if not batch:
            break
        last_id = batch[-1].id
        for finding in batch:
            if is_canonical_confirmed_finding(finding, expected_commit_sha=scan.commit_hash):
                verified.append(finding)
                if len(verified) > MAX_SARIF_RESULTS:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail={"error_code": "SARIF_RESULT_LIMIT", "message": "Too many verified findings for one complete SARIF export."},
                    )
        if len(batch) < BATCH_SIZE:
            break

    data = json.dumps(
        build_sarif(verified, commit_sha=scan.commit_hash),
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    if len(data) > MAX_SARIF_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"error_code": "SARIF_BYTE_LIMIT", "message": "SARIF export exceeds its maximum size."},
        )
    return Response(
        content=data,
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": f'attachment; filename="repolens-{scan.id[:8]}.sarif"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
