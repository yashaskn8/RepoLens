"""Focused verification for the immutable PDF reporting vertical slice."""

from datetime import datetime, timedelta, timezone
import hashlib
import io
from pathlib import Path
import shutil
from uuid import uuid4

from fastapi.testclient import TestClient
from pypdf import PdfReader
import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.api.routes.reports import _iter_pdf_spool
from app.artifacts.registry import ArtifactRegistry
from app.artifacts.service import CanonicalArtifactService, get_artifact_store
from app.artifacts.schemas import (
    ArtifactCoverage,
    ArtifactSensitivity,
    ArtifactType,
    CoverageStatus,
    RetentionClass,
)
from app.cli.create_operator import create_or_elevate_operator
from app.core.config import Settings, get_settings
from app.models.finding import EvidenceModel, FindingModel
from app.models.report import ReportModel
from app.models.scan import ScanModel
from app.models.user import UserModel
from app.reporting.assembler import ReportAssembler, _coverage
from app.reporting.renderer import ReportLabPdfRenderer
from app.reporting.schemas import ReportDocument, ReportScope, ReportStatus
from app.reporting.storage import ArtifactStorageError, LocalReportArtifactStorage
from app.schemas.enums import FindingStatus, ScanStatus, Severity, VerificationVerdict
from app.services.auth_service import AuthService
from app.services.report_dispatcher import ReportDispatcher
from app.services.report_generation import ReportGenerationService, spool_canonical_report_pdf


def _finding(
    scan_id: str,
    *,
    finding_id: str,
    severity: str,
    title: str,
    category: str = "security",
) -> FindingModel:
    return FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title=title,
        description=f"Evidence-backed explanation for {title}",
        severity=severity,
        status=FindingStatus.OPEN.value,
        rule_id="CWE-502" if severity == Severity.CRITICAL.value else "contract.response-shape",
        category=category,
        mitigation_guidance=f"Apply the recorded remediation for {title}",
        verification_verdict=VerificationVerdict.CONFIRMED.value,
        verification_reason=f"Confirmed impact for {title}",
        source_tool="semgrep",
        detector_id="detector-1",
    )


def test_report_pipeline_is_deterministic_bounded_and_tenant_safe(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("REPORT_ARTIFACT_DIR", str(tmp_path / "report-artifacts"))
    monkeypatch.setenv("ARTIFACT_ROOT_DIR", str(tmp_path / "canonical-artifacts"))
    monkeypatch.setenv("REPORT_MAX_FINDINGS", "2")
    monkeypatch.setenv("REPORT_MAX_DETAILED_FINDINGS", "1")
    monkeypatch.setenv("REPORT_MAX_EVIDENCE_REFERENCES", "2")
    monkeypatch.setenv("REPORT_MAX_EVIDENCE_PER_FINDING", "3")
    monkeypatch.setenv("REPORT_LEASE_SECONDS", "3")
    monotonic_ticks = iter(float(value) for value in range(1000))
    monkeypatch.setattr("app.services.report_generation.time.monotonic", lambda: next(monotonic_ticks))
    get_settings.cache_clear()
    try:
        settings = get_settings()
        owner = db_session.query(UserModel).filter(UserModel.email == "default_test_user@example.com").one()
        scan_id = str(uuid4())
        commit_sha = "d34db33fd34db33fd34db33fd34db33fd34db33f"
        scan = ScanModel(
            id=scan_id,
            owner_user_id=owner.id,
            repository_url="https://github.com/example/evidence-repo",
            branch="main",
            commit_hash=commit_sha,
            status=ScanStatus.COMPLETED.value,
            completed_at=datetime(2026, 9, 1, 8, 30, tzinfo=timezone.utc),
            model_metadata={
                "resolved_branch_or_ref": "main",
                "analysis_policy_version": "policy-7",
                "languages": {"Python": 12, "TypeScript": 8},
                "analysis_scope": {
                    "files_processed": 20,
                    "total_observed_files": 20,
                    "source_bytes_processed": 12000,
                    "total_observed_bytes": 12000,
                    "truncated": False,
                },
                "index_coverage": {
                    "discovered_files": 20,
                    "indexed_files": 20,
                    "inventory_complete": True,
                    "partial_files": 0,
                    "excluded_by_reason": {},
                },
                "scanner_coverage": [
                    {"tool": "semgrep", "status": "COMPLETED", "findings_count": 2},
                    {"tool": "osv", "status": "COMPLETED", "findings_count": 0},
                ],
                "tool_versions": {"semgrep": "1.0-recorded"},
            },
        )
        db_session.add(scan)

        critical_id, high_id, low_id = (str(uuid4()) for _ in range(3))
        critical = _finding(
            scan_id,
            finding_id=critical_id,
            severity=Severity.CRITICAL.value,
            title="Unsafe deserialization <script>alert(1)</script> 😀",
        )
        high = _finding(
            scan_id,
            finding_id=high_id,
            severity=Severity.HIGH.value,
            title="Frontend/API response contract mismatch",
            category="contract",
        )
        low = _finding(
            scan_id,
            finding_id=low_id,
            severity=Severity.LOW.value,
            title="Bounded report omission sentinel",
            category="code-quality",
        )
        db_session.add_all([critical, high, low])
        raw_secret = "sk-123456789012345678901234"
        db_session.add_all([
            EvidenceModel(
                id="00000000-0000-0000-0000-000000000001",
                finding_id=critical_id,
                file_path="src/" + "very-long-untrusted-path/" * 30 + "decoder.py",
                start_line=41,
                end_line=42,
                code_snippet=f"<img src='https://attacker.invalid/x'>\nvalue = loads(payload)  # {raw_secret}\u202e",
                context_notes="Repository-controlled <b>markup</b> is inert text.",
            ),
            EvidenceModel(
                id="00000000-0000-0000-0000-000000000002",
                finding_id=high_id,
                file_path="frontend/src/api.ts",
                start_line=10,
                end_line=12,
                code_snippet="fetch('/api/items').then(r => r.json())",
                context_notes="Expected list; handler records an object response.",
            ),
            EvidenceModel(
                id="00000000-0000-0000-0000-000000000003",
                finding_id=critical_id,
                file_path="src/decoder_helper.py",
                start_line=7,
                end_line=7,
                code_snippet="helper(payload)",
                context_notes="Additional evidence must not starve other findings.",
            ),
            EvidenceModel(
                id="00000000-0000-0000-0000-000000000004",
                finding_id=critical_id,
                file_path="src/decoder_config.py",
                start_line=3,
                end_line=3,
                code_snippet="ALLOW_UNSAFE = True",
                context_notes="Additional evidence beyond the per-report budget.",
            ),
            EvidenceModel(
                id="00000000-0000-0000-0000-000000000005",
                finding_id=critical_id,
                file_path="src/decoder_entry.py",
                start_line=12,
                end_line=12,
                code_snippet="decode(request.body)",
                context_notes="Additional evidence beyond the per-report budget.",
            ),
        ])
        db_session.commit()

        monkeypatch.setattr(
            "app.api.routes.reports.ReportDispatcher.dispatch_report",
            lambda report_id: None,
        )
        create_response = client.post(f"/api/v1/scans/{scan_id}/reports")
        assert create_response.status_code == 202
        created_resource = create_response.json()
        assert created_resource["status"] == ReportStatus.REQUESTED.value
        assert create_response.headers["location"] == f"/api/v1/reports/{created_resource['id']}"
        status_response = client.get(f"/api/v1/reports/{created_resource['id']}")
        assert status_response.status_code == 200
        assert status_response.headers["cache-control"] == "private, no-store"
        not_ready = client.get(f"/api/v1/reports/{created_resource['id']}/download")
        assert not_ready.status_code == 409
        assert not_ready.json()["detail"]["error_code"] == "REPORT_NOT_READY"
        requested_report = db_session.query(ReportModel).filter(ReportModel.id == created_resource["id"]).one()

        service = ReportGenerationService(settings)

        worker_sessions = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=db_session.connection(),
            join_transaction_mode="create_savepoint",
        )
        ReportGenerationService.execute_report_under_work_item(
            requested_report.id,
            settings,
            session_factory=worker_sessions,
        )
        db_session.expire_all()
        report = db_session.query(ReportModel).filter(ReportModel.id == requested_report.id).one()
        assert report.status == ReportStatus.READY.value
        assert report.pdf_artifact_id and report.pdf_digest
        assert report.document_artifact_id
        assert report.payload_locator is None
        assert report.document_locator is None
        assert not (tmp_path / "report-artifacts" / "pdf").exists()
        assert not list((tmp_path / "report-artifacts" / "documents").rglob("*.json"))
        assert report.payload_size_bytes and report.payload_size_bytes < settings.REPORT_MAX_PDF_BYTES

        storage = LocalReportArtifactStorage.from_settings(settings)
        artifact_store = get_artifact_store(settings)
        registry = ArtifactRegistry(db_session, store=artifact_store)
        pdf_artifact = registry.get(tenant_id=owner.id, artifact_id=report.pdf_artifact_id, include_tombstoned=False)
        document_artifact = registry.get(
            tenant_id=owner.id,
            artifact_id=report.document_artifact_id,
            include_tombstoned=False,
        )
        assert artifact_store.verify_digest(pdf_artifact.payload_locator, report.pdf_digest)
        assert artifact_store.verify_digest(document_artifact.payload_locator, report.document_digest)
        with artifact_store.get(pdf_artifact.payload_locator) as stream:
            pdf_bytes = stream.read(settings.REPORT_MAX_PDF_BYTES + 1)
        with artifact_store.get(document_artifact.payload_locator) as stream:
            document_bytes = stream.read(settings.REPORT_MAX_PDF_BYTES + 1)
        assert len(pdf_bytes) == report.payload_size_bytes
        assert len(document_bytes) <= settings.REPORT_MAX_PDF_BYTES
        document = ReportDocument.model_validate_json(document_bytes)
        pdf_path = tmp_path / "canonical-report.pdf"
        pdf_path.write_bytes(pdf_bytes)
        assert document.metadata.repository == scan.repository_url
        assert document.metadata.commit_sha == commit_sha
        assert document.coverage.status == "FULL"
        assert document.scope.inventory_complete is True
        assert document.appendix.omitted_finding_count == 1
        assert document.appendix.omitted_evidence_count == 3
        assert {item.finding_id for item in document.appendix.evidence} == {critical_id, high_id}
        assert [item.finding_id for item in document.prioritized_fix_plan] == [critical_id, high_id]
        assert document.prioritized_fix_plan[0].priority_band == "FIX FIRST"
        assert [finding_id for section in document.finding_sections for finding_id in section.finding_ids] == [critical_id]
        assert any("detail budget is 1" in limitation for limitation in document.limitations)
        assert document.appendix.evidence[0].evidence_id

        reader = PdfReader(str(pdf_path), strict=True)
        assert len(reader.pages) == report.page_count
        extracted = "\n".join(page.extract_text() or "" for page in reader.pages)
        assert scan.repository_url in extracted
        assert commit_sha in extracted
        assert "Unsafe deserialization" in extracted
        assert "Frontend/API response contract mismatch" in extracted
        assert extracted.index("Unsafe deserialization") < extracted.index("Frontend/API response contract mismatch")
        assert "Evidence Appendix" in extracted
        assert "frontend/src/api.ts" in extracted
        assert "Coverage status" in extracted and "FULL" in extracted
        assert "Files inventoried" in extracted and "Inventory complete" in extracted
        assert raw_secret not in extracted
        assert "[REDACTED]" in extracted
        assert "attacker.invalid" in extracted
        assert "/JavaScript" not in reader.trailer["/Root"]
        assert "/OpenAction" not in reader.trailer["/Root"]

        # The renderer is byte-deterministic for the same immutable document.
        duplicate_path = storage.create_pdf_temp(report.id)
        duplicate = service.storage.create_pdf_temp(report.id)
        try:
            from app.reporting.renderer import ReportLabPdfRenderer

            first_receipt = ReportLabPdfRenderer(settings).render(document, duplicate_path)
            second_receipt = ReportLabPdfRenderer(settings).render(document, duplicate)
            assert first_receipt.digest == second_receipt.digest == report.pdf_digest
        finally:
            duplicate_path.unlink(missing_ok=True)
            duplicate.unlink(missing_ok=True)

        # Simulate a process restart: remove every staging artifact and construct
        # fresh DB/store/service objects. The immutable canonical artifacts alone
        # must be sufficient to validate READY and reproduce the exact PDF bytes.
        shutil.rmtree(settings.REPORT_ARTIFACT_DIR, ignore_errors=True)
        monkeypatch.setattr("app.artifacts.service._configured_store", None)
        restarted_sessions = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=db_session.connection(),
            join_transaction_mode="create_savepoint",
        )
        restarted_db = restarted_sessions()
        try:
            restarted_report = restarted_db.query(ReportModel).filter(ReportModel.id == report.id).one()
            assert restarted_report.status == ReportStatus.READY.value
            restarted_store = get_artifact_store(settings)
            restarted_artifact = ArtifactRegistry(restarted_db, store=restarted_store).get(
                tenant_id=owner.id,
                artifact_id=restarted_report.pdf_artifact_id,
                include_tombstoned=False,
            )
            with spool_canonical_report_pdf(
                restarted_db,
                restarted_report,
                settings=settings,
            ) as restarted_pdf:
                restarted_bytes = restarted_pdf.read()
            assert hashlib.sha256(restarted_bytes).hexdigest() == restarted_report.pdf_digest
            assert restarted_artifact.content_digest == restarted_report.pdf_digest
            assert restarted_bytes == pdf_bytes
        finally:
            restarted_db.close()

        reused = service.request_report(db_session, scan_id=scan_id, tenant_id=owner.id)
        assert reused.report.id == report.id
        assert reused.reused is True
        assert reused.should_dispatch is False

        download = client.get(f"/api/v1/reports/{report.id}/download")
        assert download.status_code == 200
        assert download.headers["content-type"].startswith("application/pdf")
        assert "attachment" in download.headers["content-disposition"].lower()
        assert "repolens-report-" in download.headers["content-disposition"]
        assert str(tmp_path) not in download.headers["content-disposition"]
        assert download.headers["cache-control"] == "private, no-store"
        assert download.content.startswith(b"%PDF")
        assert hashlib.sha256(download.content).hexdigest() == report.pdf_digest

        other_user = create_or_elevate_operator(
            db_session,
            email="pdf-report-other@example.com",
            password="OtherUserPass12345!",
        )
        raw_session, raw_csrf, _ = AuthService(db_session).create_session(other_user)
        client.cookies.set("repolens_session", raw_session)
        client.cookies.set("repolens_csrf", raw_csrf)
        client.headers["X-CSRF-Token"] = raw_csrf
        assert client.get(f"/api/v1/reports/{report.id}").status_code == 404
        assert client.get(f"/api/v1/reports/{report.id}/download").status_code == 404
    finally:
        get_settings.cache_clear()


def test_ready_status_accessor_rejects_cross_tenant_canonical_document_and_pdf(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ARTIFACT_ROOT_DIR", str(tmp_path / "canonical-artifacts"))
    get_settings.cache_clear()
    settings = get_settings()
    owner = db_session.query(UserModel).filter(UserModel.email == "default_test_user@example.com").one()
    foreign_owner = UserModel(
        id=str(uuid4()),
        email="foreign-report-owner@example.com",
        password_hash="test-only-not-used",
        role="USER",
        is_active=True,
    )
    scan = ScanModel(
        id=str(uuid4()),
        owner_user_id=owner.id,
        repository_url="https://github.com/example/canonical-report",
        commit_hash="a" * 40,
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add_all([foreign_owner, scan])
    db_session.flush()
    report_id = str(uuid4())
    report = ReportModel(
        id=report_id,
        owner_user_id=owner.id,
        scan_id=scan.id,
        kind="SCAN_SECURITY",
        status=ReportStatus.RENDERING.value,
        input_digest="1" * 64,
        evidence_digest="2" * 64,
        coverage_digest="3" * 64,
        document_digest="4" * 64,
        repository_url=scan.repository_url,
        branch="main",
        commit_sha=scan.commit_hash,
        report_schema_version="1.0",
        renderer_version="test-renderer",
        analysis_policy_version="test-policy",
        application_version="test",
        finding_ids=[],
        artifact_lineage={},
    )
    db_session.add(report)
    db_session.flush()

    def publish(tenant_id: str, artifact_type: ArtifactType, payload: bytes):
        return CanonicalArtifactService(db_session, settings=settings).publish_bytes(
            tenant_id=tenant_id,
            repository_id="repo-identity",
            revision_id=scan.commit_hash,
            artifact_type=artifact_type,
            payload=payload,
            media_type="application/pdf" if artifact_type == ArtifactType.PDF_REPORT else "application/json",
            producer="report-accessor-test",
            producer_version="1",
            policy_snapshot_id="test-policy",
            coverage=ArtifactCoverage(
                status=CoverageStatus.SUCCESSFULLY_ANALYZED,
                discovered_count=0,
                analyzed_count=0,
            ),
            sensitivity=ArtifactSensitivity.SOURCE_DERIVED,
            retention_class=(
                RetentionClass.PDF_REPORT
                if artifact_type == ArtifactType.PDF_REPORT
                else RetentionClass.ANALYSIS_ARTIFACT
            ),
        )

    own_document = b'{"report":"own"}'
    own_pdf = b"%PDF-1.4\nown-report"
    foreign_document = b'{"report":"foreign"}'
    foreign_pdf = b"%PDF-1.4\nforeign-report"
    own_doc_artifact = publish(owner.id, ArtifactType.REPORT_DOCUMENT, own_document).artifact
    own_pdf_artifact = publish(owner.id, ArtifactType.PDF_REPORT, own_pdf).artifact
    foreign_doc_artifact = publish(foreign_owner.id, ArtifactType.REPORT_DOCUMENT, foreign_document).artifact
    foreign_pdf_artifact = publish(foreign_owner.id, ArtifactType.PDF_REPORT, foreign_pdf).artifact

    report.document_artifact_id = own_doc_artifact.artifact_id
    report.document_digest = own_doc_artifact.content_digest
    report.pdf_artifact_id = own_pdf_artifact.artifact_id
    report.pdf_digest = own_pdf_artifact.content_digest
    report.payload_size_bytes = len(own_pdf)
    report.page_count = 1
    report.generated_at = datetime.now(timezone.utc)
    report.status = ReportStatus.READY.value
    db_session.flush()
    assert client.get(f"/api/v1/reports/{report_id}").status_code == 200

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            report.document_artifact_id = None
            report.document_digest = None
            db_session.flush()
    db_session.refresh(report)
    assert report.status == ReportStatus.READY.value
    assert report.document_artifact_id == own_doc_artifact.artifact_id

    report.pdf_artifact_id = foreign_pdf_artifact.artifact_id
    report.pdf_digest = foreign_pdf_artifact.content_digest
    report.payload_size_bytes = len(foreign_pdf)
    db_session.flush()
    pdf_substitution = client.get(f"/api/v1/reports/{report_id}")
    assert pdf_substitution.status_code == 409
    assert pdf_substitution.json()["detail"]["error_code"] == "REPORT_ARTIFACT_UNAVAILABLE"
    pdf_download_substitution = client.get(f"/api/v1/reports/{report_id}/download")
    assert pdf_download_substitution.status_code == 409
    assert pdf_download_substitution.json()["detail"]["error_code"] == "REPORT_ARTIFACT_UNAVAILABLE"

    report.pdf_artifact_id = own_pdf_artifact.artifact_id
    report.pdf_digest = own_pdf_artifact.content_digest
    report.payload_size_bytes = len(own_pdf)
    report.document_artifact_id = foreign_doc_artifact.artifact_id
    report.document_digest = foreign_doc_artifact.content_digest
    db_session.flush()
    document_substitution = client.get(f"/api/v1/reports/{report_id}")
    assert document_substitution.status_code == 409
    assert document_substitution.json()["detail"]["error_code"] == "REPORT_ARTIFACT_UNAVAILABLE"
    document_download_substitution = client.get(f"/api/v1/reports/{report_id}/download")
    assert document_download_substitution.status_code == 409
    assert document_download_substitution.json()["detail"]["error_code"] == "REPORT_ARTIFACT_UNAVAILABLE"


def test_report_coverage_distinguishes_complete_inventory_from_scoped_semantics():
    scope = ReportScope(
        files_discovered=377,
        files_analyzed=326,
        inventory_complete=True,
        partial_files=5,
        excluded_files=51,
    )
    coverage, _ = _coverage(
        {"scanner_coverage": [{"tool": "repolens-core", "status": "COMPLETED"}]},
        scope,
    )

    assert not scope.truncated
    assert coverage.status == "PARTIAL"
    assert "Repository inventory completed" in coverage.distinction
    assert "326 analyzable files" in coverage.distinction
    assert "51 non-analyzable files" in coverage.distinction


def test_large_report_renders_with_a_bounded_detail_budget(
    db_session: Session,
    tmp_path: Path,
):
    """A large finding set stays useful and within hard artifact limits."""
    owner = create_or_elevate_operator(
        db_session,
        email="default_test_user@example.com",
        password="DefaultTestPass12345!",
    )
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        owner_user_id=owner.id,
        repository_url="https://github.com/example/large-report-repo",
        branch="main",
        commit_hash="a" * 40,
        status=ScanStatus.COMPLETED.value,
        completed_at=datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc),
        model_metadata={
            "analysis_scope": {
                "files_processed": 900,
                "total_observed_files": 900,
                "source_bytes_processed": 8_000_000,
                "total_observed_bytes": 8_000_000,
                "truncated": False,
            },
            "scanner_coverage": [
                {"tool": "semgrep", "status": "COMPLETED", "findings_count": 125},
            ],
        },
    )
    db_session.add(scan)
    db_session.add_all([
        _finding(
            scan_id,
            finding_id=f"large-{index:03d}",
            severity=Severity.HIGH.value if index < 10 else Severity.MEDIUM.value,
            title=f"Bounded large-report finding {index:03d}",
        )
        for index in range(125)
    ])
    db_session.commit()

    settings = Settings(
        REPORT_ARTIFACT_DIR=str(tmp_path / "large-report-artifacts"),
        REPORT_MAX_FINDINGS=120,
        REPORT_MAX_DETAILED_FINDINGS=5,
        REPORT_MAX_EVIDENCE_REFERENCES=10,
    )
    document = ReportAssembler(settings).assemble(
        db_session,
        scan_id=scan_id,
        tenant_id=owner.id,
        report_id=str(uuid4()),
        generated_at=datetime(2026, 9, 1, 9, 5, tzinfo=timezone.utc),
    )

    detailed_ids = [finding_id for section in document.finding_sections for finding_id in section.finding_ids]
    assert len(document.findings) == 120
    assert len(document.prioritized_fix_plan) == 120
    assert len(detailed_ids) == 5
    assert document.appendix.omitted_finding_count == 5
    assert any("115 selected findings" in limitation for limitation in document.limitations)

    rendered_pages: list[int] = []
    receipt = ReportLabPdfRenderer(settings).render(
        document,
        tmp_path / "large-report.pdf",
        progress_callback=rendered_pages.append,
    )
    assert receipt.page_count <= settings.REPORT_MAX_PDF_PAGES
    assert receipt.size_bytes <= settings.REPORT_MAX_PDF_BYTES
    assert rendered_pages == list(range(1, receipt.page_count + 1))


def test_pdf_storage_rejects_a_claimed_digest_mismatch(tmp_path: Path):
    storage = LocalReportArtifactStorage(tmp_path / "artifact-root")
    report_id = str(uuid4())
    temp_path = storage.create_pdf_temp(report_id)
    temp_path.write_bytes(b"%PDF-1.4\nnot-the-claimed-content")

    with pytest.raises(ArtifactStorageError, match="digest verification"):
        storage.publish_pdf(report_id, "0" * 64, temp_path)

    assert temp_path.exists()


def test_report_recovery_terminalizes_an_exhausted_attempt_budget(
    db_session: Session,
    monkeypatch,
):
    monkeypatch.setenv("REPORT_MAX_ATTEMPTS", "2")
    get_settings.cache_clear()
    try:
        owner = create_or_elevate_operator(
            db_session,
            email="default_test_user@example.com",
            password="DefaultTestPass12345!",
        )
        scan_id = str(uuid4())
        report_id = str(uuid4())
        db_session.add(ScanModel(
            id=scan_id,
            owner_user_id=owner.id,
            repository_url="https://github.com/example/exhausted-report",
            branch="main",
            commit_hash="b" * 40,
            status=ScanStatus.COMPLETED.value,
        ))
        db_session.add(ReportModel(
            id=report_id,
            owner_user_id=owner.id,
            scan_id=scan_id,
            kind="SCAN_SECURITY",
            status=ReportStatus.RENDERING.value,
            input_digest="1" * 64,
            evidence_digest="2" * 64,
            coverage_digest="3" * 64,
            document_digest="4" * 64,
            document_locator="documents/exhausted.json",
            repository_url="https://github.com/example/exhausted-report",
            commit_sha="b" * 40,
            report_schema_version="1.0",
            renderer_version="renderer-test",
            analysis_policy_version="policy-test",
            application_version="1.0.1",
            finding_ids=[],
            artifact_lineage=[],
            attempt_count=2,
            retryable=True,
            lease_owner="dead-worker",
            lease_expires_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        ))
        db_session.commit()
        worker_sessions = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=db_session.connection(),
            join_transaction_mode="create_savepoint",
        )
        monkeypatch.setattr("app.services.report_dispatcher.SessionLocal", worker_sessions)

        assert report_id not in ReportDispatcher.recoverable_report_ids()
        db_session.expire_all()
        exhausted = db_session.query(ReportModel).filter(ReportModel.id == report_id).one()
        assert exhausted.status == ReportStatus.FAILED.value
        assert exhausted.failure_code == "REPORT_ATTEMPTS_EXHAUSTED"
        assert exhausted.retryable is False
    finally:
        get_settings.cache_clear()


def test_pdf_response_iterator_is_bounded_and_closes_on_success_empty_failure_and_cancel():
    payload = b"x" * (64 * 1024 + 7)
    completed = io.BytesIO(payload)
    chunks = list(_iter_pdf_spool(completed))
    assert b"".join(chunks) == payload
    assert max(map(len, chunks)) <= 64 * 1024
    assert completed.closed

    empty = io.BytesIO(b"")
    assert list(_iter_pdf_spool(empty)) == []
    assert empty.closed

    class BrokenRead(io.BytesIO):
        def read(self, size=-1):
            raise OSError("injected stream failure")

    broken = BrokenRead(b"data")
    with pytest.raises(OSError, match="injected stream failure"):
        list(_iter_pdf_spool(broken))
    assert broken.closed

    cancelled = io.BytesIO(payload)
    iterator = _iter_pdf_spool(cancelled)
    assert next(iterator)
    iterator.close()
    assert cancelled.closed
