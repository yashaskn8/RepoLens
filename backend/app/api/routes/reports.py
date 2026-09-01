"""Authenticated report-resource creation, status, recovery, and PDF download."""

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, verify_csrf
from app.api.idempotency import idempotency_identity
from app.core.config import get_settings
from app.core.database import get_db
from app.execution.application import NewWorkPaused, WorkSubmissionService
from app.execution.dispatcher import DurableWorkDispatcher
from app.execution.errors import IdempotencyConflict
from app.execution.types import RequestBudget, ResourceProfile, WorkKind
from app.governance.events import AuditLedger
from app.models.report import ReportModel
from app.reporting.schemas import ReportResource, ReportStatus
from app.reporting.storage import LocalReportArtifactStorage
from app.schemas.auth import CurrentUser
from app.services.authorization_service import get_owned_report_or_404, get_owned_scan_or_404
from app.services.report_dispatcher import ReportDispatcher  # Backward-compatible import; shared dispatcher owns runtime execution.
from app.services.report_generation import ReportGenerationService, report_to_resource


router = APIRouter(tags=["Reports"])


@router.post("/scans/{scan_id}/reports", response_model=ReportResource, status_code=status.HTTP_202_ACCEPTED)
async def request_scan_report(
    scan_id: str,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
):
    scan = get_owned_scan_or_404(db, scan_id, current_user)
    if scan.status != "COMPLETED":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "SCAN_NOT_COMPLETED", "message": "PDF reports require a completed scan."},
        )
    external_identity = idempotency_identity(
        "report-generation",
        idempotency_key,
        maximum=get_settings().IDEMPOTENCY_KEY_MAX_LENGTH,
    )
    submission_service = WorkSubmissionService()
    service = ReportGenerationService()
    if external_identity:
        existing_work = submission_service.find_by_external_identity(
            db,
            tenant_id=current_user.id,
            work_kind=WorkKind.REPORT_GENERATION,
            identity=external_identity,
        )
        if existing_work is not None:
            existing_report = get_owned_report_or_404(db, existing_work.resource_id, current_user)
            try:
                submission = submission_service.submit(
                    db,
                    tenant_id=current_user.id,
                    actor_id=current_user.id,
                    request_id=getattr(request.state, "request_id", existing_work.request_id),
                    work_kind=WorkKind.REPORT_GENERATION,
                    resource_type="REPORT",
                    resource_id=existing_report.id,
                    request_payload={
                        "report_id": existing_report.id,
                        "input_digest": existing_report.input_digest,
                    },
                    idempotency_key=external_identity,
                    external_idempotency_key=external_identity,
                    resource_profile=ResourceProfile.REPORT_RENDER,
                    budget=RequestBudget(
                        max_wall_clock_seconds=get_settings().REPORT_LEASE_SECONDS,
                        max_report_bytes=get_settings().REPORT_MAX_PDF_BYTES,
                        max_report_pages=get_settings().REPORT_MAX_PDF_PAGES,
                    ),
                    max_attempts=get_settings().REPORT_MAX_ATTEMPTS,
                    allow_when_paused=True,
                )
            except IdempotencyConflict as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={"error_code": "IDEMPOTENCY_CONFLICT", "message": str(exc)},
                ) from exc
            service.register_document_artifact(
                db,
                existing_report,
                policy_snapshot_id=submission.policy_snapshot_id,
                actor_id=current_user.id,
                request_id=getattr(request.state, "request_id", None),
            )
            db.commit()
            response.headers["Location"] = f"/api/v1/reports/{existing_report.id}"
            response.headers["X-Job-Location"] = f"/api/v1/jobs/{submission.result.work_item_id}"
            response.headers["Idempotency-Replayed"] = "true"
            response.headers["Cache-Control"] = "private, no-store"
            if existing_report.status == ReportStatus.READY.value:
                response.status_code = status.HTTP_200_OK
            return report_to_resource(existing_report, reused=True)

    result = service.request_report(
        db,
        scan_id=scan.id,
        tenant_id=current_user.id,
        auto_commit=False,
    )
    try:
        submission = submission_service.submit(
            db,
            tenant_id=current_user.id,
            actor_id=current_user.id,
            request_id=getattr(request.state, "request_id", result.report.id),
            work_kind=WorkKind.REPORT_GENERATION,
            resource_type="REPORT",
            resource_id=result.report.id,
            request_payload={"report_id": result.report.id, "input_digest": result.report.input_digest},
            idempotency_key=external_identity or f"report:{result.report.input_digest}",
            external_idempotency_key=external_identity,
            resource_profile=ResourceProfile.REPORT_RENDER,
            budget=RequestBudget(
                max_wall_clock_seconds=get_settings().REPORT_LEASE_SECONDS,
                max_report_bytes=get_settings().REPORT_MAX_PDF_BYTES,
                max_report_pages=get_settings().REPORT_MAX_PDF_PAGES,
            ),
            max_attempts=get_settings().REPORT_MAX_ATTEMPTS,
        )
        service.register_document_artifact(
            db,
            result.report,
            policy_snapshot_id=submission.policy_snapshot_id,
            actor_id=current_user.id,
            request_id=getattr(request.state, "request_id", None),
        )
        db.commit()
    except NewWorkPaused as exc:
        db.rollback()
        if not result.reused:
            service.storage.discard_document(result.report.document_locator, result.report.document_digest)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error_code": "NEW_JOBS_PAUSED", "message": str(exc)},
        ) from exc
    except IdempotencyConflict as exc:
        db.rollback()
        if not result.reused:
            service.storage.discard_document(result.report.document_locator, result.report.document_digest)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "IDEMPOTENCY_CONFLICT", "message": str(exc)},
        ) from exc

    if result.should_dispatch:
        DurableWorkDispatcher.nudge()
    if result.reused and result.report.status == ReportStatus.READY.value:
        response.status_code = status.HTTP_200_OK
    response.headers["Location"] = f"/api/v1/reports/{result.report.id}"
    response.headers["X-Job-Location"] = f"/api/v1/jobs/{submission.result.work_item_id}"
    response.headers["Idempotency-Replayed"] = "true" if submission.result.reused else "false"
    response.headers["Cache-Control"] = "private, no-store"
    return report_to_resource(result.report, reused=result.reused)


@router.get("/scans/{scan_id}/reports/latest", response_model=ReportResource)
def get_latest_scan_report(
    scan_id: str,
    response: Response,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = get_owned_scan_or_404(db, scan_id, current_user)
    report = (
        db.query(ReportModel)
        .filter(ReportModel.scan_id == scan.id, ReportModel.owner_user_id == current_user.id)
        .order_by(ReportModel.requested_at.desc(), ReportModel.id.desc())
        .first()
    )
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    response.headers["Cache-Control"] = "private, no-store"
    return report_to_resource(report)


@router.get("/reports/{report_id}", response_model=ReportResource)
def get_report_status(
    report_id: str,
    response: Response,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    response.headers["Cache-Control"] = "private, no-store"
    return report_to_resource(get_owned_report_or_404(db, report_id, current_user))


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report = get_owned_report_or_404(db, report_id, current_user)
    if report.status != ReportStatus.READY.value or not report.payload_locator or not report.pdf_digest:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "REPORT_NOT_READY", "message": "The PDF report is not ready for download."},
        )
    storage = LocalReportArtifactStorage.from_settings()
    if not storage.verify(report.payload_locator, report.pdf_digest, kind="pdf"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "REPORT_ARTIFACT_UNAVAILABLE", "message": "The PDF artifact failed availability verification."},
        )
    path = storage.resolve_pdf(report.payload_locator)
    AuditLedger.append(
        db,
        tenant_id=current_user.id,
        actor_id=current_user.id,
        request_id=getattr(request.state, "request_id", None),
        event_type="REPORT_DOWNLOADED",
        resource_type="REPORT",
        resource_id=report.id,
        artifact_digest=report.pdf_digest,
        payload={"scan_id": report.scan_id},
    )
    db.commit()
    return FileResponse(
        path=path,
        media_type="application/pdf",
        filename=f"repolens-report-{report.id[:8]}.pdf",
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
