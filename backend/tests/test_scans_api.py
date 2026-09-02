import hashlib
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
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
