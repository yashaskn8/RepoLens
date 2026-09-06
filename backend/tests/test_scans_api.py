import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.execution.dispatcher import DomainWorkFailed, DurableWorkDispatcher
from app.execution.types import FailureCode, WorkKind
from app.schemas.enums import FindingStatus, ScanStatus, Severity, VerificationVerdict
from app.services.finding_grounding import build_grounding_context_notes


def test_post_scans_valid_url_accepted(client, db_session):
    """POST /api/v1/scans with valid GitHub URL returns 202 Accepted and creates Scan."""
    with patch("app.api.routes.scans.execute_background_scan", new_callable=AsyncMock) as mock_bg:
        response = client.post(
            "/api/v1/scans",
            json={"repository_url": "https://github.com/fastapi/fastapi", "branch": "main"},
        )

    assert response.status_code == 202
    data = response.json()
    assert "id" in data
    assert data["repository_url"] == "https://github.com/fastapi/fastapi.git"
    assert data["status"] == "PENDING"

    # Verify scan exists in database
    db_scan = db_session.query(ScanModel).filter(ScanModel.id == data["id"]).first()
    assert db_scan is not None
    assert db_scan.status == ScanStatus.PENDING.value


def test_post_scans_invalid_url_rejected(client):
    """POST /api/v1/scans with invalid/malicious URL returns 400 Bad Request."""
    invalid_payloads = [
        {"repository_url": "http://insecure-site.com/repo"},
        {"repository_url": "https://gitlab.com/owner/repo"},
        {"repository_url": "https://github.com/owner/repo; rm -rf /"},
        {"repository_url": ""},
    ]

    for p in invalid_payloads:
        response = client.post("/api/v1/scans", json=p)
        assert response.status_code in (400, 422)


def test_post_scans_rejects_unmigrated_analysis_storage(client, db_session):
    """A connected but stale database must fail before quota or work is created."""
    scan_count_before = db_session.query(ScanModel).count()
    with patch(
        "app.api.routes.scans.missing_scan_storage_tables",
        return_value=frozenset({"index_snapshots"}),
    ):
        response = client.post(
            "/api/v1/scans",
            json={"repository_url": "https://github.com/fastapi/fastapi"},
        )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["error_code"] == "DATABASE_MIGRATION_REQUIRED"
    assert "migrations" in detail["message"].lower()
    assert db_session.query(ScanModel).count() == scan_count_before


def test_scan_result_preserves_non_retryable_domain_failure(db_session, monkeypatch):
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo.git",
        status=ScanStatus.FAILED.value,
        model_metadata={
            "failure_code": FailureCode.INTERNAL_INVARIANT_VIOLATION.value,
            "failure_message": "Repository analysis storage is not ready.",
        },
    )
    db_session.add(scan)
    db_session.commit()
    session_factory = db_session.__class__
    monkeypatch.setattr(
        "app.execution.dispatcher.SessionLocal",
        lambda: session_factory(bind=db_session.get_bind()),
    )

    with pytest.raises(DomainWorkFailed) as captured:
        DurableWorkDispatcher._scan_result(scan.id)

    assert captured.value.code == FailureCode.INTERNAL_INVARIANT_VIOLATION
    assert captured.value.retryable is False
    assert str(captured.value) == "Repository analysis storage is not ready."


def test_scan_budget_timeout_marks_domain_terminal(db_session, monkeypatch):
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo.git",
        status=ScanStatus.RUNNING.value,
        model_metadata={"index_coverage": {"indexed_files": 10}},
    )
    db_session.add(scan)
    db_session.commit()
    session_factory = db_session.__class__
    monkeypatch.setattr(
        "app.execution.dispatcher.SessionLocal",
        lambda: session_factory(bind=db_session.get_bind()),
    )

    DurableWorkDispatcher._mark_domain_budget_stopped(
        SimpleNamespace(work_kind=WorkKind.SCAN, resource_id=scan.id)
    )
    db_session.expire_all()
    persisted = db_session.get(ScanModel, scan.id)

    assert persisted.status == ScanStatus.FAILED.value
    assert persisted.completed_at is not None
    assert persisted.model_metadata["failure_code"] == FailureCode.WORKFLOW_TIMEOUT.value
    assert persisted.model_metadata["index_coverage"] == {"indexed_files": 10}
    terminal_event = db_session.query(WorkflowEventModel).filter_by(scan_id=scan.id).one()
    assert terminal_event.event_type == "SCAN_FAILED"
    assert terminal_event.metadata_payload["coverage"] == "PARTIAL"


def test_get_scan_by_id(client, db_session):
    """GET /api/v1/scans/{id} returns scan details and status."""
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/sample-repo.git",
        branch="main",
        status=ScanStatus.COMPLETED.value,
        commit_hash="1234567890abcdef",
    )
    db_session.add(scan)
    db_session.commit()

    response = client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == scan_id
    assert data["status"] == "COMPLETED"
    assert data["commit_hash"] == "1234567890abcdef"


def test_get_scan_preserves_aggregate_coverage_metadata(client, db_session):
    """Scan responses preserve truthful coverage rather than hiding it in a model envelope."""
    scan_id = str(uuid4())
    metadata = {
        "index_coverage": {"discovered_files": 593, "indexed_files": 514},
        "analysis_scope": {"files_processed": 328},
        "graph_coverage": {"total_nodes": 512, "total_edges": 494, "complete": False},
        "analysis_coverage": {"status": "UNAVAILABLE"},
        "scanner_coverage": [{"tool": "osv-scanner", "status": "UNAVAILABLE"}],
    }
    db_session.add(
        ScanModel(
            id=scan_id,
            repository_url="https://github.com/org/sample-repo.git",
            status=ScanStatus.COMPLETED.value,
            commit_hash="a" * 40,
            model_metadata=metadata,
        )
    )
    db_session.commit()

    response = client.get(f"/api/v1/scans/{scan_id}")

    assert response.status_code == 200
    assert response.json()["model_metadata"] == metadata


def test_list_scans_returns_only_current_users_scans(client, db_session):
    """GET /api/v1/scans returns a tenant-scoped durable scan history."""
    owned_scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/owned.git",
        status=ScanStatus.COMPLETED.value,
    )
    other_scan = ScanModel(
        id=str(uuid4()),
        owner_user_id=str(uuid4()),
        repository_url="https://github.com/org/other.git",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add_all([owned_scan, other_scan])
    db_session.commit()

    response = client.get("/api/v1/scans")

    assert response.status_code == 200
    returned_ids = {scan["id"] for scan in response.json()}
    assert owned_scan.id in returned_ids
    assert other_scan.id not in returned_ids


def test_get_scan_not_found(client):
    """GET /api/v1/scans/{id} with unknown ID returns 404."""
    random_id = str(uuid4())
    response = client.get(f"/api/v1/scans/{random_id}")
    assert response.status_code == 404
    assert f"Scan with ID '{random_id}' not found" in response.json()["detail"]


def test_get_scan_findings(client, db_session):
    """GET /api/v1/scans/{id}/findings returns verified findings with evidence."""
    scan_id = str(uuid4())
    finding_id = str(uuid4())
    commit_sha = "a" * 40

    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/sample-repo.git",
        status=ScanStatus.COMPLETED.value,
        commit_hash=commit_sha,
    )
    db_session.add(scan)

    finding = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Unverified Signature",
        description="JWT parsed without verification.",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        category="security",
        verification_verdict=VerificationVerdict.CONFIRMED.value,
        verification_reason="Code evidence confirms verify=False.",
    )
    snippet = "jwt.decode(token, verify=False)"
    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=finding_id,
        file_path="src/auth.py",
        start_line=12,
        end_line=14,
        code_snippet=snippet,
        context_notes=build_grounding_context_notes(
            commit_sha=commit_sha,
            file_path="src/auth.py",
            start_line=12,
            end_line=14,
            file_sha256="3" * 64,
            snippet_sha256=hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
        ),
    )
    finding.evidences.append(evidence)
    db_session.add(finding)
    db_session.commit()

    response = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == finding_id
    assert data[0]["title"] == "Unverified Signature"
    assert data[0]["severity"] == "HIGH"
    assert data[0]["verification_verdict"] == "CONFIRMED"
    assert len(data[0]["evidences"]) == 1
    assert data[0]["evidences"][0]["file_path"] == "src/auth.py"
