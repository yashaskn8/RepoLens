"""Focused verification for the immutable PDF reporting vertical slice."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from pypdf import PdfReader
import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.cli.create_operator import create_or_elevate_operator
from app.core.config import Settings, get_settings
from app.models.finding import EvidenceModel, FindingModel
from app.models.report import ReportModel
from app.models.scan import ScanModel
from app.models.user import UserModel
from app.reporting.assembler import ReportAssembler
from app.reporting.renderer import ReportLabPdfRenderer
from app.reporting.schemas import ReportDocument, ReportStatus
from app.reporting.storage import ArtifactStorageError, LocalReportArtifactStorage
from app.schemas.enums import FindingStatus, ScanStatus, Severity, VerificationVerdict
from app.services.auth_service import AuthService
from app.services.report_dispatcher import ReportDispatcher
from app.services.report_generation import ReportGenerationService


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
        ReportGenerationService.execute_report(
            requested_report.id,
            "test-worker",
            settings,
            session_factory=worker_sessions,
        )
        db_session.expire_all()
        report = db_session.query(ReportModel).filter(ReportModel.id == requested_report.id).one()
        assert report.status == ReportStatus.READY.value
        assert report.payload_locator and report.pdf_digest
        assert report.payload_size_bytes and report.payload_size_bytes < settings.REPORT_MAX_PDF_BYTES

        storage = LocalReportArtifactStorage.from_settings(settings)
        pdf_path = storage.resolve_pdf(report.payload_locator)
        document_path = storage.resolve_document(report.document_locator)
        assert storage.verify(report.payload_locator, report.pdf_digest, kind="pdf")
        document = ReportDocument.model_validate_json(document_path.read_bytes())
        assert document.metadata.repository == scan.repository_url
        assert document.metadata.commit_sha == commit_sha
        assert document.coverage.status == "FULL"
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


def test_large_report_renders_with_a_bounded_detail_budget(
    db_session: Session,
    tmp_path: Path,
):
    """A large finding set stays useful and within hard artifact limits."""
    owner = db_session.query(UserModel).filter(UserModel.email == "default_test_user@example.com").one()
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
        owner = db_session.query(UserModel).filter(UserModel.email == "default_test_user@example.com").one()
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
