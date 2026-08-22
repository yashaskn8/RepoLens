"""Tests for Task 4E: Structured Evidence Reporting Service (Markdown and JSON)."""

from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.report_service import ScanReportService
from app.services.workflow_event_service import WorkflowEventService


def test_build_scan_report_and_render_markdown(db_session: Session):
    """Verify ScanReportService builds structured reports with grounded evidences, patches, and audit events."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/fastapi/fastapi",
        branch="main",
        commit_hash="a1b2c3d4e5f6789012345678901234567890abcd",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "requested_branch": "main",
            "resolved_branch_or_ref": "main",
            "architecture_overview": "FastAPI async web application framework",
            "languages": {"Python": 120},
            "frameworks": ["FastAPI", "Starlette", "Pydantic"],
        },
    )
    db_session.add(scan)

    # Add verified finding with grounded evidence
    finding_id = uuid4()
    finding = FindingModel(
        id=str(finding_id),
        scan_id=str(scan_id),
        title="Insecure Deserialization",
        description="Pickle loads untrusted input",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        rule_id="python.security.pickle-load",
        category="security",
        mitigation_guidance="Use json.loads instead of pickle.loads",
        verification_verdict=VerificationVerdict.CONFIRMED.value,
        verification_reason="Direct unvalidated pickle.loads call on request body",
        source_tool="semgrep",
        detector_id="semgrep-py-pickle",
    )
    db_session.add(finding)

    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=str(finding_id),
        file_path="app/serializer.py",
        start_line=45,
        end_line=46,
        code_snippet="data = pickle.loads(raw_data)",
        context_notes="Direct pickle deserialization",
    )
    db_session.add(evidence)

    # Add generated patch
    patch_id = uuid4()
    patch = PatchModel(
        id=str(patch_id),
        finding_id=str(finding_id),
        scan_id=str(scan_id),
        status=PatchStatus.APPROVED.value,
        machine_verdict="PASSED",
        unified_diff="--- a/app/serializer.py\n+++ b/app/serializer.py\n@@ -45,1 +45,1 @@\n-data = pickle.loads(raw_data)\n+data = json.loads(raw_data)\n",
        files_modified=["app/serializer.py"],
        explanation="Replaced insecure pickle deserialization with safe json deserialization",
        expected_behavior_change="Parses valid JSON strings securely",
        approved_by="lead-architect",
        revision_number=0,
    )
    db_session.add(patch)

    # Add workflow events
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_CREATED,
            scan_id=scan_id,
            message="Scan initiated",
        ),
    )
    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.SCAN_COMPLETED,
            scan_id=scan_id,
            message="Scan completed with 1 finding",
        ),
    )
    db_session.commit()

    # Build report
    report = ScanReportService.build_scan_report(db=db_session, scan_id=str(scan_id))
    assert report is not None
    assert report.scan_id == str(scan_id)
    assert report.summary.total_findings == 1
    assert report.summary.high_findings == 1
    assert report.summary.confirmed_findings == 1
    assert report.summary.total_patches == 1
    assert report.summary.approved_patches == 1
    assert len(report.findings) == 1
    assert report.findings[0].evidences[0].file_path == "app/serializer.py"
    assert len(report.findings[0].patches) == 1
    assert report.findings[0].patches[0].approved_by == "lead-architect"
    assert len(report.events_audit_trail) == 2

    # Render Markdown
    md = ScanReportService.render_markdown(report)
    assert "# RepoLens Evidence & Intelligence Report" in md
    assert "FastAPI async web application framework" in md
    assert "Insecure Deserialization" in md
    assert "app/serializer.py" in md
    assert "data = pickle.loads(raw_data)" in md
    assert "```diff" in md
    assert "+data = json.loads(raw_data)" in md
    assert "Workflow Audit Trail" in md
    assert "SCAN_CREATED" in md


def test_report_endpoints_markdown_and_json(client: TestClient, db_session: Session):
    """Verify GET /api/v1/scans/{scan_id}/report returns Markdown and JSON correctly."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/test-api",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan)
    db_session.commit()

    # Markdown format via query param
    resp_md = client.get(f"/api/v1/scans/{scan_id}/report?format=markdown")
    assert resp_md.status_code == 200
    assert "text/markdown" in resp_md.headers["content-type"]
    assert "# RepoLens Evidence & Intelligence Report" in resp_md.text

    # JSON format via query param
    resp_json = client.get(f"/api/v1/scans/{scan_id}/report?format=json")
    assert resp_json.status_code == 200
    data = resp_json.json()
    assert data["scan_id"] == str(scan_id)
    assert "summary" in data

    # Dedicated convenience endpoints
    resp_md_direct = client.get(f"/api/v1/scans/{scan_id}/report/markdown")
    assert resp_md_direct.status_code == 200
    assert "text/markdown" in resp_md_direct.headers["content-type"]

    resp_json_direct = client.get(f"/api/v1/scans/{scan_id}/report/json")
    assert resp_json_direct.status_code == 200
    assert resp_json_direct.json()["scan_id"] == str(scan_id)


def test_report_unknown_scan_returns_404(client: TestClient):
    """Verify requesting report for a non-existent scan returns 404."""
    random_id = uuid4()
    resp = client.get(f"/api/v1/scans/{random_id}/report")
    assert resp.status_code == 404


def test_report_analysis_scope_and_scanner_coverage(db_session: Session):
    """Verify ScanReport accurately reflects analysis scope, truncation, and scanner coverage statuses."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/scope-test-repo",
        branch="main",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "analysis_scope": {
                "truncated": True,
                "reason": "Max byte limit 50MB exceeded during clone ingestion",
                "files_processed": 500,
                "source_bytes_processed": 52428800,
                "total_observed_files": 1250,
                "total_observed_bytes": 104857600,
            },
            "scanner_coverage": [
                {
                    "tool": "semgrep",
                    "status": "COMPLETED",
                    "findings_count": 3,
                    "execution_time_ms": 240,
                },
                {
                    "tool": "trivy",
                    "status": "UNAVAILABLE",
                    "findings_count": 0,
                    "failure_reason": "Trivy binary not installed on runner host",
                },
                {
                    "tool": "osv",
                    "status": "FAILED",
                    "findings_count": 0,
                    "execution_time_ms": 1500,
                    "failure_reason": "OSV scanner network timeout querying database",
                },
            ],
        },
    )
    db_session.add(scan)
    db_session.commit()

    report = ScanReportService.build_scan_report(db=db_session, scan_id=str(scan_id))
    assert report is not None

    # Verify JSON structure
    assert report.analysis_scope is not None
    assert report.analysis_scope.truncated is True
    assert "Max byte limit" in report.analysis_scope.reason
    assert report.analysis_scope.files_processed == 500
    assert report.analysis_scope.total_observed_files == 1250

    assert len(report.scanner_coverage) == 3
    tools = {sc.tool: sc for sc in report.scanner_coverage}
    assert tools["semgrep"].status == "COMPLETED"
    assert tools["semgrep"].findings_count == 3
    assert tools["trivy"].status == "UNAVAILABLE"
    assert tools["trivy"].failure_reason == "Trivy binary not installed on runner host"
    assert tools["osv"].status == "FAILED"

    # Verify Markdown rendering
    md = ScanReportService.render_markdown(report)
    assert "## Analysis Scope & Ingestion Boundary" in md
    assert "**Analysis Truncated**: **YES** ⚠️" in md
    assert "Max byte limit 50MB exceeded" in md
    assert "500 / 1250 observed" in md

    assert "## Deterministic Scanner Coverage" in md
    assert "semgrep" in md
    assert "`COMPLETED`" in md
    assert "trivy" in md
    assert "`UNAVAILABLE`" in md
    assert "Trivy binary not installed on runner host" in md
    assert "osv" in md
    assert "`FAILED`" in md


def test_report_hostile_markdown_and_secret_redaction(db_session: Session):
    """Verify malicious HTML tags are inert, code fences are breakout-proof, and secrets are redacted."""
    scan_id = uuid4()
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/org/hostile-repo",
        branch="main",
        status=ScanStatus.COMPLETED.value,
        model_metadata={
            "architecture_overview": "Overview with <script>alert(1)</script> and sk-12345678901234567890 and Bearer secrettoken12345",
        },
    )
    db_session.add(scan)

    # Finding with hostile script tags, backticks, and secret tokens in title and snippet
    finding_id = uuid4()
    finding = FindingModel(
        id=str(finding_id),
        scan_id=str(scan_id),
        title="XSS via <img src=x onerror=alert('hack')> and sk-abcdef1234567890",
        description="User input contains <script>alert('pwned')</script> and Authorization: Bearer supersecrettoken999",
        severity=Severity.CRITICAL.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(finding)

    # Snippet with nested code fences to test breakout prevention
    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=str(finding_id),
        file_path="app/auth/`user_token`.py",
        start_line=10,
        end_line=20,
        code_snippet='const token = "sk-live12345678901234567890";\n```javascript\n// Attempted fence breakout\n```\nconst auth = "Bearer toplevelsecret99999";',
        context_notes="Host path leak attempt C:\\Users\\Administrator\\AppData and AIzaSyD1234567890123456789012345678901",
    )
    db_session.add(evidence)

    # Patch with diff
    patch = PatchModel(
        id=str(uuid4()),
        finding_id=str(finding_id),
        scan_id=str(scan_id),
        status=PatchStatus.APPROVED.value,
        machine_verdict="PASSED",
        unified_diff='--- a/auth.py\n+++ b/auth.py\n@@ -1,1 +1,1 @@\n-apiKey = "sk-badsecretkey1234567890"\n+apiKey = os.environ["API_KEY"]\n',
        files_modified=["app/auth/`user_token`.py"],
        explanation="Removed raw key sk-badsecretkey1234567890",
        expected_behavior_change="Use env var with <script>test</script>",
        approved_by="admin-user | with | pipes",
        revision_number=0,
    )
    db_session.add(patch)
    db_session.commit()

    report = ScanReportService.build_scan_report(db=db_session, scan_id=str(scan_id))
    assert report is not None

    # Verify JSON redaction
    assert "sk-12345678901234567890" not in report.architecture_overview
    assert "sk-abcdef1234567890" not in report.findings[0].title
    assert "supersecrettoken999" not in report.findings[0].description
    assert "sk-live12345678901234567890" not in report.findings[0].evidences[0].code_snippet
    assert "toplevelsecret99999" not in report.findings[0].evidences[0].code_snippet
    assert "AIzaSyD1234567890123456789012345678901" not in report.findings[0].evidences[0].context_notes
    assert "sk-badsecretkey1234567890" not in report.findings[0].patches[0].unified_diff

    # Verify Markdown rendering
    md = ScanReportService.render_markdown(report)

    # 1. No executable scripts
    assert "<script>alert" not in md
    assert "&lt;script&gt;alert" in md or "alert" in md
    assert "<img src=x onerror" not in md

    # 2. No secrets in markdown
    assert "sk-1234567890" not in md
    assert "sk-abcdef" not in md
    assert "supersecrettoken999" not in md
    assert "sk-live1234567890" not in md
    assert "toplevelsecret99999" not in md
    assert "AIzaSyD" not in md
    assert "sk-badsecretkey" not in md

    # 3. Dynamic code fences used (4 backticks because 3 backticks was inside content)
    assert "````" in md

