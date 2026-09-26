"""Report request idempotency, execution, and immutable artifact finalization."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from pathlib import Path
import tempfile
from time import monotonic as _monotonic
from types import SimpleNamespace
from typing import Callable, Optional
from uuid import uuid4

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.artifacts.schemas import (
    ArtifactCoverage,
    ArtifactSensitivity,
    ArtifactType,
    CoverageStatus,
    LineageRelation,
    RetentionClass,
)
from app.artifacts.registry import ArtifactRegistry
from app.artifacts.schemas import ArtifactType
from app.artifacts.service import CanonicalArtifactService, get_artifact_store
from app.core.config import Settings, get_settings
from app.core.database import SessionLocal
from app.models.report import ReportModel
from app.reporting.assembler import ReportAssembler, report_input_digest
from app.reporting.renderer import ReportLabPdfRenderer, ReportRenderError
from app.reporting.schemas import REPORT_TYPE_SCAN, ReportDocument, ReportResource, ReportStatus
from app.reporting.storage import LocalReportArtifactStorage


logger = logging.getLogger(__name__)

# A local facade keeps report timing patchable without replacing the
# process-global clock used by asyncio and other concurrent runtimes.
time = SimpleNamespace(monotonic=_monotonic)


@dataclass(frozen=True)
class ReportRequestResult:
    report: ReportModel
    reused: bool
    should_dispatch: bool
    staged_document_locator: str | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _json_bytes(document: ReportDocument) -> bytes:
    return document.model_dump_json().encode("utf-8")


def _coverage_digest(document: ReportDocument) -> str:
    payload = json.dumps(document.coverage.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _repository_identity(repository_url: str) -> str:
    return hashlib.sha256(repository_url.encode("utf-8")).hexdigest()[:32]


def _registered_lineage_ids(db: Session, tenant_id: str, payload: dict) -> list[str]:
    from app.models.artifact import ArtifactModel

    candidates: set[str] = set()
    for key, value in payload.items():
        if key.endswith("artifact_id") and value:
            candidates.add(str(value))
        elif key.endswith("artifact_ids") and isinstance(value, (list, tuple, set)):
            candidates.update(str(item) for item in value if item)
    if not candidates:
        return []
    return [
        row[0]
        for row in db.query(ArtifactModel.id).filter(
            ArtifactModel.tenant_id == tenant_id,
            ArtifactModel.id.in_(candidates),
        ).all()
    ]


def _report_lineage_payload(value: object) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, (list, tuple, set)):
        return {"upstream_artifact_ids": [str(item) for item in value if item]}
    return {}


def _read_staged_report_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    """Read a staging file with a hard bound before canonical publication."""
    if maximum_bytes < 0:
        raise ValueError("maximum_bytes must be non-negative")
    try:
        with path.open("rb") as stream:
            payload = stream.read(maximum_bytes + 1)
    except OSError:
        raise RuntimeError("REPORT_STAGING_UNAVAILABLE") from None
    if len(payload) > maximum_bytes:
        raise RuntimeError("REPORT_STAGING_TOO_LARGE")
    return payload


def _canonical_report_artifact(
    db: Session,
    report: ReportModel,
    *,
    artifact_id: str | None,
    expected_type: ArtifactType,
    expected_digest: str,
    settings: Settings,
):
    """Resolve and verify report bytes only through the tenant-bound registry/store."""
    if not artifact_id:
        raise RuntimeError("REPORT_ARTIFACT_UNAVAILABLE")
    store = get_artifact_store(settings)
    try:
        artifact = ArtifactRegistry(db, store=store).get(
            tenant_id=report.owner_user_id,
            artifact_id=artifact_id,
            include_tombstoned=False,
        )
        metadata = store.metadata(artifact.payload_locator)
        valid = (
            artifact.tenant_id == report.owner_user_id
            and artifact.artifact_type == expected_type
            and artifact.content_digest == expected_digest
            and artifact.payload_size_bytes == metadata.size_bytes
            and artifact.content_digest == metadata.content_digest
            and artifact.media_type == metadata.content_type
            and store.verify_digest(artifact.payload_locator, expected_digest)
        )
    except Exception:
        raise RuntimeError("REPORT_ARTIFACT_UNAVAILABLE") from None
    if not valid:
        raise RuntimeError("REPORT_ARTIFACT_INTEGRITY_FAILURE")
    return artifact, store


def read_canonical_report_document(
    db: Session,
    report: ReportModel,
    *,
    settings: Settings | None = None,
) -> ReportDocument:
    """Read a bounded immutable document from canonical authority and attest identity."""
    active_settings = settings or get_settings()
    if not report.document_digest:
        raise RuntimeError("REPORT_DOCUMENT_UNAVAILABLE")
    artifact, store = _canonical_report_artifact(
        db,
        report,
        artifact_id=report.document_artifact_id,
        expected_type=ArtifactType.REPORT_DOCUMENT,
        expected_digest=report.document_digest,
        settings=active_settings,
    )
    if artifact.media_type != "application/json" or artifact.payload_size_bytes > active_settings.REPORT_MAX_PDF_BYTES:
        raise RuntimeError("REPORT_DOCUMENT_TOO_LARGE_OR_INVALID")
    output = bytearray()
    digest = hashlib.sha256()
    try:
        with store.get(artifact.payload_locator) as stream:
            while True:
                chunk = stream.read(min(64 * 1024, active_settings.REPORT_MAX_PDF_BYTES + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                digest.update(chunk)
                if len(output) > active_settings.REPORT_MAX_PDF_BYTES:
                    raise RuntimeError("REPORT_DOCUMENT_TOO_LARGE")
    except Exception:
        raise RuntimeError("REPORT_DOCUMENT_UNAVAILABLE") from None
    if digest.hexdigest() != report.document_digest:
        raise RuntimeError("REPORT_DOCUMENT_INTEGRITY_FAILURE")
    try:
        document = ReportDocument.model_validate_json(bytes(output))
    except Exception:
        raise RuntimeError("REPORT_DOCUMENT_INVALID") from None
    metadata = document.metadata
    if (
        metadata.report_id != report.id
        or metadata.tenant_id != report.owner_user_id
        or metadata.scan_id != report.scan_id
        or metadata.renderer_version != report.renderer_version
        or metadata.report_schema_version != report.report_schema_version
        or metadata.repository != report.repository_url
        or metadata.commit_sha != report.commit_sha
    ):
        raise RuntimeError("REPORT_DOCUMENT_IDENTITY_MISMATCH")
    return document


def spool_canonical_report_pdf(
    db: Session,
    report: ReportModel,
    *,
    settings: Settings | None = None,
):
    """Return a bounded, digest-verified PDF spool from canonical authority."""
    active_settings = settings or get_settings()
    if not report.pdf_digest:
        raise RuntimeError("REPORT_ARTIFACT_UNAVAILABLE")
    artifact, store = _canonical_report_artifact(
        db,
        report,
        artifact_id=report.pdf_artifact_id,
        expected_type=ArtifactType.PDF_REPORT,
        expected_digest=report.pdf_digest,
        settings=active_settings,
    )
    if artifact.media_type != "application/pdf":
        raise RuntimeError("REPORT_PDF_INVALID")
    if (
        artifact.payload_size_bytes != report.payload_size_bytes
        or artifact.payload_size_bytes > active_settings.REPORT_MAX_PDF_BYTES
    ):
        raise RuntimeError("REPORT_PDF_SIZE_MISMATCH")

    spool = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b")
    digest = hashlib.sha256()
    size = 0
    try:
        with store.get(artifact.payload_locator) as source:
            while True:
                chunk = source.read(min(64 * 1024, active_settings.REPORT_MAX_PDF_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > active_settings.REPORT_MAX_PDF_BYTES:
                    raise RuntimeError("REPORT_PDF_TOO_LARGE")
                spool.write(chunk)
                digest.update(chunk)
        if size != artifact.payload_size_bytes or digest.hexdigest() != report.pdf_digest:
            raise RuntimeError("REPORT_ARTIFACT_INTEGRITY_FAILURE")
        spool.seek(0)
        return spool
    except RuntimeError:
        spool.close()
        raise
    except Exception:
        spool.close()
        raise RuntimeError("REPORT_ARTIFACT_UNAVAILABLE") from None


def verify_ready_report_artifacts(
    db: Session,
    report: ReportModel,
    *,
    settings: Settings | None = None,
) -> None:
    """Fail closed unless every artifact required by READY resolves canonically."""
    if report.status != ReportStatus.READY.value:
        return
    active_settings = settings or get_settings()
    if not report.pdf_artifact_id or not report.pdf_digest or not report.generated_at:
        raise RuntimeError("REPORT_ARTIFACT_UNAVAILABLE")
    if not report.document_artifact_id or not report.document_digest:
        raise RuntimeError("REPORT_DOCUMENT_UNAVAILABLE")
    pdf, _ = _canonical_report_artifact(
        db,
        report,
        artifact_id=report.pdf_artifact_id,
        expected_type=ArtifactType.PDF_REPORT,
        expected_digest=report.pdf_digest,
        settings=active_settings,
    )
    document, _ = _canonical_report_artifact(
        db,
        report,
        artifact_id=report.document_artifact_id,
        expected_type=ArtifactType.REPORT_DOCUMENT,
        expected_digest=report.document_digest,
        settings=active_settings,
    )
    if (
        pdf.artifact_id != report.pdf_artifact_id
        or pdf.media_type != "application/pdf"
        or pdf.payload_size_bytes != report.payload_size_bytes
        or pdf.payload_size_bytes > active_settings.REPORT_MAX_PDF_BYTES
        or document.artifact_id != report.document_artifact_id
        or document.media_type != "application/json"
        or document.payload_size_bytes > active_settings.REPORT_MAX_PDF_BYTES
    ):
        raise RuntimeError("REPORT_ARTIFACT_INTEGRITY_FAILURE")


def report_to_resource(report: ReportModel, *, reused: bool = False) -> ReportResource:
    status = ReportStatus(report.status)
    return ReportResource(
        id=report.id,
        scan_id=report.scan_id,
        report_type=report.kind,
        status=status,
        repository=report.repository_url,
        branch=report.branch,
        commit_sha=report.commit_sha,
        report_schema_version=report.report_schema_version,
        renderer_version=report.renderer_version,
        created_at=report.requested_at,
        generated_at=report.generated_at,
        failure_code=report.failure_code,
        failure_message=report.failure_message,
        retryable=bool(report.retryable and status == ReportStatus.FAILED),
        content_digest=report.pdf_digest if status == ReportStatus.READY else None,
        file_size_bytes=report.payload_size_bytes if status == ReportStatus.READY else None,
        page_count=report.page_count if status == ReportStatus.READY else None,
        download_url=f"/api/v1/reports/{report.id}/download" if status == ReportStatus.READY else None,
        reused=reused,
    )


class ReportGenerationService:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.storage = LocalReportArtifactStorage.from_settings(self.settings)
        self.assembler = ReportAssembler(self.settings)

    def request_report(
        self,
        db: Session,
        *,
        scan_id: str,
        tenant_id: str,
        auto_commit: bool = True,
    ) -> ReportRequestResult:
        """Create or reuse the report resource for the exact canonical input snapshot."""
        now = _utc_now()
        proposed_id = str(uuid4())
        document = self.assembler.assemble(
            db,
            scan_id=scan_id,
            tenant_id=tenant_id,
            report_id=proposed_id,
            generated_at=now,
        )
        input_digest = report_input_digest(document)
        existing = (
            db.query(ReportModel)
            .filter(
                ReportModel.owner_user_id == tenant_id,
                ReportModel.scan_id == scan_id,
                ReportModel.input_digest == input_digest,
                ReportModel.report_schema_version == document.metadata.report_schema_version,
                ReportModel.renderer_version == document.metadata.renderer_version,
            )
            .first()
        )
        if existing is not None:
            if existing.status == ReportStatus.READY.value:
                try:
                    verify_ready_report_artifacts(db, existing, settings=self.settings)
                    available = True
                except RuntimeError:
                    available = False
                if available:
                    return ReportRequestResult(existing, reused=True, should_dispatch=False)
                existing.status = ReportStatus.FAILED.value
                existing.failure_code = "REPORT_ARTIFACT_UNAVAILABLE"
                existing.failure_message = "The canonical PDF artifact is unavailable; operator reconciliation is required."
                existing.retryable = False
                existing.lease_owner = None
                existing.lease_expires_at = None
                if auto_commit:
                    db.commit()
                else:
                    db.flush()
                db.refresh(existing)
                return ReportRequestResult(existing, reused=False, should_dispatch=False)
            if existing.status in {
                ReportStatus.REQUESTED.value,
                ReportStatus.ASSEMBLING.value,
                ReportStatus.RENDERING.value,
            } and not existing.document_artifact_id:
                existing.status = ReportStatus.FAILED.value
                existing.failure_code = "LEGACY_REPORT_DOCUMENT_UNAVAILABLE"
                existing.failure_message = "The canonical report document is unavailable; operator reconciliation is required."
                existing.retryable = False
                if auto_commit:
                    db.commit()
                else:
                    db.flush()
                db.refresh(existing)
                return ReportRequestResult(existing, reused=False, should_dispatch=False)
            if existing.status == ReportStatus.FAILED.value:
                if (
                    not existing.retryable
                    or existing.attempt_count >= self.settings.REPORT_MAX_ATTEMPTS
                    or not existing.document_artifact_id
                ):
                    return ReportRequestResult(existing, reused=False, should_dispatch=False)
                existing.status = ReportStatus.REQUESTED.value
                existing.failure_code = None
                existing.failure_message = None
                existing.retryable = True
                existing.lease_owner = None
                existing.lease_expires_at = None
                if auto_commit:
                    db.commit()
                else:
                    db.flush()
                db.refresh(existing)
                return ReportRequestResult(existing, reused=False, should_dispatch=True)
            return ReportRequestResult(existing, reused=True, should_dispatch=False)

        payload = _json_bytes(document)
        if len(payload) > self.settings.REPORT_MAX_PDF_BYTES:
            raise ValueError("Report document exceeded the configured artifact budget.")
        document_locator, document_digest = self.storage.publish_document(proposed_id, payload)
        report = ReportModel(
            id=proposed_id,
            owner_user_id=tenant_id,
            scan_id=scan_id,
            kind=REPORT_TYPE_SCAN,
            status=ReportStatus.REQUESTED.value,
            input_digest=input_digest,
            evidence_digest=document.metadata.evidence_digest,
            coverage_digest=_coverage_digest(document),
            document_digest=document_digest,
            document_locator=document_locator,
            repository_url=document.metadata.repository,
            branch=document.metadata.branch,
            commit_sha=document.metadata.commit_sha,
            report_schema_version=document.metadata.report_schema_version,
            renderer_version=document.metadata.renderer_version,
            analysis_policy_version=document.metadata.analysis_policy_version,
            application_version=document.metadata.application_version,
            coverage_artifact_id=document.metadata.coverage_artifact_id,
            finding_ids=document.metadata.finding_ids,
            artifact_lineage=document.metadata.artifact_lineage,
            attempt_count=0,
            retryable=True,
            requested_at=now,
            updated_at=now,
        )
        try:
            with db.begin_nested():
                db.add(report)
                db.flush()
            if auto_commit:
                db.commit()
        except IntegrityError:
            if auto_commit:
                db.rollback()
            self.storage.discard_document(document_locator, document_digest)
            winner = (
                db.query(ReportModel)
                .filter(
                    ReportModel.owner_user_id == tenant_id,
                    ReportModel.scan_id == scan_id,
                    ReportModel.input_digest == input_digest,
                    ReportModel.report_schema_version == document.metadata.report_schema_version,
                    ReportModel.renderer_version == document.metadata.renderer_version,
                )
                .first()
            )
            if winner is None:
                raise
            return ReportRequestResult(winner, reused=True, should_dispatch=False)
        except Exception:
            if auto_commit:
                db.rollback()
            self.storage.discard_document(document_locator, document_digest)
            raise
        db.refresh(report)
        return ReportRequestResult(
            report,
            reused=False,
            should_dispatch=True,
            staged_document_locator=document_locator,
        )

    def register_document_artifact(
        self,
        db: Session,
        report: ReportModel,
        *,
        policy_snapshot_id: str,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> str:
        """Publish the staged document and bind the report to canonical authority."""
        lineage_payload = _report_lineage_payload(report.artifact_lineage)
        existing_id = report.document_artifact_id or lineage_payload.get("document_artifact_id")
        if existing_id:
            artifact, _ = _canonical_report_artifact(
                db,
                report,
                artifact_id=str(existing_id),
                expected_type=ArtifactType.REPORT_DOCUMENT,
                expected_digest=report.document_digest,
                settings=self.settings,
            )
            if artifact.media_type != "application/json":
                raise RuntimeError("REPORT_DOCUMENT_INVALID")
            report.document_artifact_id = str(existing_id)
            lineage_payload["document_artifact_id"] = str(existing_id)
            report.artifact_lineage = lineage_payload
            report.document_locator = None
            db.flush()
            return str(existing_id)
        if not report.document_locator:
            raise RuntimeError("REPORT_DOCUMENT_UNAVAILABLE")
        document_path = self.storage.resolve_document(report.document_locator)
        payload = _read_staged_report_bytes(
            document_path,
            maximum_bytes=self.settings.REPORT_MAX_PDF_BYTES,
        )
        if hashlib.sha256(payload).hexdigest() != report.document_digest:
            raise RuntimeError("REPORT_DOCUMENT_INTEGRITY_FAILURE")
        upstream_ids = _registered_lineage_ids(db, report.owner_user_id, lineage_payload)
        registration = CanonicalArtifactService(db, settings=self.settings).publish_bytes(
            payload=payload,
            media_type="application/json",
            tenant_id=report.owner_user_id,
            repository_id=_repository_identity(report.repository_url),
            revision_id=report.commit_sha or report.scan_id,
            artifact_type=ArtifactType.REPORT_DOCUMENT,
            producer="repolens-report-assembler",
            producer_version=report.report_schema_version,
            policy_snapshot_id=policy_snapshot_id,
            lineage=[(LineageRelation.DERIVED_FROM, artifact_id) for artifact_id in upstream_ids],
            coverage=ArtifactCoverage(
                status=CoverageStatus.SUCCESSFULLY_ANALYZED,
                discovered_count=len(report.finding_ids or []),
                analyzed_count=len(report.finding_ids or []),
            ),
            sensitivity=ArtifactSensitivity.SOURCE_DERIVED,
            retention_class=RetentionClass.ANALYSIS_ARTIFACT,
            referrer=("REPORT", report.id),
            actor_id=actor_id,
            request_id=request_id,
        )
        if registration.artifact.content_digest != report.document_digest:
            raise RuntimeError("REPORT_DOCUMENT_INTEGRITY_FAILURE")
        report.document_artifact_id = registration.artifact.artifact_id
        lineage_payload["document_artifact_id"] = registration.artifact.artifact_id
        report.artifact_lineage = lineage_payload
        report.document_locator = None
        db.flush()
        return registration.artifact.artifact_id

    @classmethod
    def _register_pdf_artifact(
        cls,
        db: Session,
        report: ReportModel,
        *,
        pdf_path: Path,
        policy_snapshot_id: str,
        settings: Settings,
    ) -> str:
        lineage_payload = _report_lineage_payload(report.artifact_lineage)
        existing_id = report.pdf_artifact_id or lineage_payload.get("pdf_artifact_id")
        if existing_id:
            artifact, _ = _canonical_report_artifact(
                db,
                report,
                artifact_id=str(existing_id),
                expected_type=ArtifactType.PDF_REPORT,
                expected_digest=report.pdf_digest or "",
                settings=settings,
            )
            if artifact.media_type != "application/pdf":
                raise RuntimeError("REPORT_PDF_INVALID")
            report.pdf_artifact_id = str(existing_id)
            lineage_payload["pdf_artifact_id"] = str(existing_id)
            report.artifact_lineage = lineage_payload
            report.payload_locator = None
            db.flush()
            return str(existing_id)
        document_artifact_id = report.document_artifact_id or lineage_payload.get("document_artifact_id")
        lineage = (
            [(LineageRelation.DERIVED_FROM, str(document_artifact_id))]
            if document_artifact_id
            else []
        )
        payload = _read_staged_report_bytes(
            pdf_path,
            maximum_bytes=settings.REPORT_MAX_PDF_BYTES,
        )
        if hashlib.sha256(payload).hexdigest() != report.pdf_digest:
            raise RuntimeError("REPORT_PDF_INTEGRITY_FAILURE")
        registration = CanonicalArtifactService(db, settings=settings).publish_bytes(
            payload=payload,
            media_type="application/pdf",
            tenant_id=report.owner_user_id,
            repository_id=_repository_identity(report.repository_url),
            revision_id=report.commit_sha or report.scan_id,
            artifact_type=ArtifactType.PDF_REPORT,
            producer="repolens-report-renderer",
            producer_version=report.renderer_version,
            policy_snapshot_id=policy_snapshot_id,
            lineage=lineage,
            coverage=ArtifactCoverage(
                status=CoverageStatus.SUCCESSFULLY_ANALYZED,
                discovered_count=report.page_count or 1,
                analyzed_count=report.page_count or 1,
            ),
            sensitivity=ArtifactSensitivity.SOURCE_DERIVED,
            retention_class=RetentionClass.PDF_REPORT,
            referrer=("REPORT", report.id),
            actor_id=report.owner_user_id,
        )
        if (
            registration.artifact.content_digest != report.pdf_digest
            or registration.artifact.payload_size_bytes != report.payload_size_bytes
        ):
            raise RuntimeError("REPORT_PDF_INTEGRITY_FAILURE")
        report.pdf_artifact_id = registration.artifact.artifact_id
        lineage_payload["pdf_artifact_id"] = registration.artifact.artifact_id
        report.artifact_lineage = lineage_payload
        db.flush()
        return registration.artifact.artifact_id

    @classmethod
    def execute_report_under_work_item(
        cls,
        report_id: str,
        settings: Optional[Settings] = None,
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> None:
        """Render a report already owned by the shared WorkItem lease.

        Report rows retain their legacy lease columns for backward compatibility,
        but this production path never treats them as execution authority.
        """
        effective_settings = settings or get_settings()
        storage = LocalReportArtifactStorage.from_settings(effective_settings)
        db = (session_factory or SessionLocal)()
        temp_path: Optional[Path] = None
        started = time.monotonic()
        try:
            report = db.query(ReportModel).filter(ReportModel.id == report_id).first()
            if report is None:
                raise RuntimeError("REPORT_NOT_FOUND")
            if report.status == ReportStatus.READY.value:
                try:
                    verify_ready_report_artifacts(db, report, settings=effective_settings)
                    return
                except RuntimeError:
                    report.status = ReportStatus.FAILED.value
                    report.failure_code = "REPORT_ARTIFACT_UNAVAILABLE"
                    report.failure_message = "The canonical PDF artifact is unavailable."
                    report.retryable = False
                    report.updated_at = _utc_now()
                    db.commit()
                    return
            if report.attempt_count >= effective_settings.REPORT_MAX_ATTEMPTS:
                report.status = ReportStatus.FAILED.value
                report.retryable = False
                report.failure_code = "REPORT_ATTEMPTS_EXHAUSTED"
                report.failure_message = "Report generation exhausted its bounded attempt budget."
                report.updated_at = _utc_now()
                db.commit()
                return

            report.status = ReportStatus.ASSEMBLING.value
            report.attempt_count += 1
            report.started_at = report.started_at or _utc_now()
            report.lease_owner = None
            report.lease_expires_at = None
            report.updated_at = _utc_now()
            db.commit()

            document = read_canonical_report_document(db, report, settings=effective_settings)

            report.status = ReportStatus.RENDERING.value
            report.updated_at = _utc_now()
            db.commit()
            temp_path = storage.create_pdf_temp(report.id)
            generated = ReportLabPdfRenderer(effective_settings).render(document, temp_path)
            report.pdf_digest = generated.digest
            report.payload_locator = None
            report.payload_size_bytes = generated.size_bytes
            report.page_count = generated.page_count
            report.generated_at = document.metadata.generated_at

            from app.models.execution import WorkItemModel

            work = db.query(WorkItemModel).filter(
                WorkItemModel.work_kind == "REPORT_GENERATION",
                WorkItemModel.resource_id == report.id,
            ).order_by(WorkItemModel.created_at.desc()).first()
            if work is None:
                raise RuntimeError("REPORT_WORK_ITEM_MISSING")
            cls._register_pdf_artifact(
                db,
                report,
                pdf_path=temp_path,
                policy_snapshot_id=work.policy_snapshot_id,
                settings=effective_settings,
            )
            report.status = ReportStatus.READY.value
            report.failure_code = None
            report.failure_message = None
            report.retryable = False
            report.lease_owner = None
            report.lease_expires_at = None
            report.updated_at = _utc_now()
            db.commit()
            temp_path.unlink(missing_ok=True)
            temp_path = None

            from app.governance.telemetry import TelemetryRecorder

            TelemetryRecorder.record(
                db,
                tenant_id=report.owner_user_id,
                metric_name="report.generation_duration",
                value=max(0.0, time.monotonic() - started),
                unit="seconds",
                dimensions={"renderer_version": report.renderer_version},
            )
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.exception("Shared report work item failed for %s", report_id)
            report = db.query(ReportModel).filter(ReportModel.id == report_id).first()
            if report is not None and report.status != ReportStatus.READY.value:
                report.status = ReportStatus.FAILED.value
                report.failure_code = str(exc) if str(exc).startswith("REPORT_") else "REPORT_RENDER_FAILED"
                report.failure_message = "Report generation failed safely. Retry is available when the attempt budget permits."
                report.retryable = report.attempt_count < effective_settings.REPORT_MAX_ATTEMPTS
                report.lease_owner = None
                report.lease_expires_at = None
                report.updated_at = _utc_now()
                db.commit()
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            db.close()

    @classmethod
    def execute_report(
        cls,
        report_id: str,
        worker_id: str,
        settings: Optional[Settings] = None,
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> None:
        """Claim and execute one durable report job in its own database session."""
        effective_settings = settings or get_settings()
        storage = LocalReportArtifactStorage.from_settings(effective_settings)
        db = (session_factory or SessionLocal)()
        temp_path: Optional[Path] = None
        try:
            now = _utc_now()
            lease_until = now + timedelta(seconds=effective_settings.REPORT_LEASE_SECONDS)
            claimed = (
                db.query(ReportModel)
                .filter(
                    ReportModel.id == report_id,
                    ReportModel.status.in_([
                        ReportStatus.REQUESTED.value,
                        ReportStatus.ASSEMBLING.value,
                        ReportStatus.RENDERING.value,
                    ]),
                    ReportModel.retryable.is_(True),
                    ReportModel.attempt_count < effective_settings.REPORT_MAX_ATTEMPTS,
                    or_(ReportModel.lease_owner.is_(None), ReportModel.lease_expires_at < now),
                )
                .update(
                    {
                        ReportModel.status: ReportStatus.ASSEMBLING.value,
                        ReportModel.lease_owner: worker_id,
                        ReportModel.lease_expires_at: lease_until,
                        ReportModel.attempt_count: ReportModel.attempt_count + 1,
                        ReportModel.started_at: now,
                        ReportModel.updated_at: now,
                    },
                    synchronize_session=False,
                )
            )
            db.commit()
            if claimed != 1:
                return

            report = db.query(ReportModel).filter(ReportModel.id == report_id).first()
            if report is None:
                raise RuntimeError("REPORT_DOCUMENT_UNAVAILABLE")
            document = read_canonical_report_document(db, report, settings=effective_settings)

            report.status = ReportStatus.RENDERING.value
            report.lease_expires_at = _utc_now() + timedelta(seconds=effective_settings.REPORT_LEASE_SECONDS)
            report.updated_at = _utc_now()
            db.commit()

            temp_path = storage.create_pdf_temp(report.id)
            heartbeat_interval = max(1.0, effective_settings.REPORT_LEASE_SECONDS / 3.0)
            next_heartbeat = time.monotonic() + heartbeat_interval

            def renew_render_lease(_page_number: int) -> None:
                nonlocal next_heartbeat
                current_tick = time.monotonic()
                if current_tick < next_heartbeat:
                    return
                heartbeat_at = _utc_now()
                renewed = (
                    db.query(ReportModel)
                    .filter(
                        ReportModel.id == report_id,
                        ReportModel.status == ReportStatus.RENDERING.value,
                        ReportModel.lease_owner == worker_id,
                    )
                    .update(
                        {
                            ReportModel.lease_expires_at: heartbeat_at + timedelta(
                                seconds=effective_settings.REPORT_LEASE_SECONDS
                            ),
                            ReportModel.updated_at: heartbeat_at,
                        },
                        synchronize_session=False,
                    )
                )
                db.commit()
                if renewed != 1:
                    raise ReportRenderError("REPORT_LEASE_LOST")
                next_heartbeat = current_tick + heartbeat_interval

            generated = ReportLabPdfRenderer(effective_settings).render(
                document,
                temp_path,
                progress_callback=renew_render_lease,
            )
            from app.models.execution import WorkItemModel

            work = db.query(WorkItemModel).filter(
                WorkItemModel.work_kind == "REPORT_GENERATION",
                WorkItemModel.resource_id == report.id,
            ).order_by(WorkItemModel.created_at.desc()).first()
            if work is None:
                raise RuntimeError("REPORT_WORK_ITEM_MISSING")
            owned_report = (
                db.query(ReportModel)
                .filter(
                    ReportModel.id == report.id,
                    ReportModel.status == ReportStatus.RENDERING.value,
                    ReportModel.lease_owner == worker_id,
                )
                .with_for_update()
                .first()
            )
            if owned_report is None:
                raise RuntimeError("REPORT_LEASE_LOST")
            report.pdf_digest = generated.digest
            report.payload_locator = None
            report.payload_size_bytes = generated.size_bytes
            report.page_count = generated.page_count
            report.generated_at = document.metadata.generated_at
            cls._register_pdf_artifact(
                db,
                report,
                pdf_path=temp_path,
                policy_snapshot_id=work.policy_snapshot_id,
                settings=effective_settings,
            )
            report.status = ReportStatus.READY.value
            report.failure_code = None
            report.failure_message = None
            report.retryable = False
            report.lease_owner = None
            report.lease_expires_at = None
            report.updated_at = _utc_now()
            db.commit()
            temp_path.unlink(missing_ok=True)
            temp_path = None
        except Exception as exc:
            db.rollback()
            logger.exception("Report generation failed for %s", report_id)
            report = db.query(ReportModel).filter(ReportModel.id == report_id).first()
            if report is not None and report.lease_owner == worker_id:
                report.status = ReportStatus.FAILED.value
                report.failure_code = str(exc) if str(exc).startswith("REPORT_") else "REPORT_RENDER_FAILED"
                report.failure_message = "Report generation failed safely. Retry is available when the attempt budget permits."
                report.retryable = report.attempt_count < effective_settings.REPORT_MAX_ATTEMPTS
                report.lease_owner = None
                report.lease_expires_at = None
                report.updated_at = _utc_now()
                db.commit()
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            db.close()
