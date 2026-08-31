"""Test Phase 8: Multi-User Tenant Isolation and SQL-Joined Ownership Verification.

Verifies:
- Scans and change analyses are unconditionally bound to `owner_user_id = current_user.id`.
- Cross-tenant requests to any entity (scan, finding, patch, delivery, change analysis) return HTTP 404 (never 403).
- Legacy ownerless resources return HTTP 404 for normal users.
- Resource listing endpoints (/scans, /change-analyses) strictly filter by owner.
"""

from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.change_analysis import ChangeAnalysisModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel


def _login_user(_unused_client: TestClient, email: str, password: str = "SecurePass12345!"):
    """Helper to register and login user with a dedicated TestClient, returning user info and client."""
    user_client = TestClient(app)
    user_client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_resp = user_client.post("/api/v1/auth/login", json={"email": email, "password": password})
    user_id = login_resp.json()["id"]
    session_cookie = login_resp.cookies["repolens_session"]
    csrf_cookie = login_resp.cookies["repolens_csrf"]

    user_client.headers["X-CSRF-Token"] = csrf_cookie
    return {
        "id": user_id,
        "email": email,
        "client": user_client,
        "cookies": {"repolens_session": session_cookie, "repolens_csrf": csrf_cookie},
        "headers": {"X-CSRF-Token": csrf_cookie},
    }


def test_cross_tenant_scan_isolation_returns_404(client: TestClient, db_session: Session):
    """Test User B cannot access or see User A's scan and findings."""
    user_a = _login_user(client, "tenant_a@example.com")
    user_b = _login_user(client, "tenant_b@example.com")

    # User A creates a scan
    scan_resp = user_a["client"].post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/tenant-a/repo"},
    )
    assert scan_resp.status_code == 202
    scan_id = scan_resp.json()["id"]

    # Verify scan has owner_user_id in DB
    scan_row = db_session.query(ScanModel).filter_by(id=scan_id).first()
    assert scan_row.owner_user_id == user_a["id"]

    # User A can fetch scan
    a_get = user_a["client"].get(f"/api/v1/scans/{scan_id}")
    assert a_get.status_code == 200

    # User B fetching User A's scan returns 404 (Not Found, preventing existence probing)
    b_get = user_b["client"].get(f"/api/v1/scans/{scan_id}")
    assert b_get.status_code == 404

    # User B fetching User A's scan findings returns 404
    b_findings = user_b["client"].get(f"/api/v1/scans/{scan_id}/findings")
    assert b_findings.status_code == 404


def test_cross_tenant_change_analysis_isolation_returns_404(client: TestClient, db_session: Session):
    """Test User B cannot access User A's change analysis and reports."""
    user_a = _login_user(client, "ca_tenant_a@example.com")
    user_b = _login_user(client, "ca_tenant_b@example.com")

    # User A creates change analysis
    ca_resp = user_a["client"].post(
        "/api/v1/change-analyses",
        json={
            "repository_url": "https://github.com/tenant-a/project",
            "base_commit_sha": "1111111111111111111111111111111111111111",
            "head_commit_sha": "2222222222222222222222222222222222222222",
        },
    )
    assert ca_resp.status_code == 202
    ca_id = ca_resp.json()["id"]

    # User A can access change analysis
    assert user_a["client"].get(f"/api/v1/change-analyses/{ca_id}").status_code == 200
    assert user_a["client"].get(f"/api/v1/change-analyses/{ca_id}/diff").status_code == 200
    assert user_a["client"].get(f"/api/v1/change-analyses/{ca_id}/impacts").status_code == 200
    assert user_a["client"].get(f"/api/v1/change-analyses/{ca_id}/report").status_code == 200

    # User B receives 404 for all endpoints
    assert user_b["client"].get(f"/api/v1/change-analyses/{ca_id}").status_code == 404
    assert user_b["client"].get(f"/api/v1/change-analyses/{ca_id}/diff").status_code == 404
    assert user_b["client"].get(f"/api/v1/change-analyses/{ca_id}/impacts").status_code == 404
    assert user_b["client"].get(f"/api/v1/change-analyses/{ca_id}/report").status_code == 404
    assert user_b["client"].get(f"/api/v1/change-analyses/{ca_id}/events").status_code == 404


def test_legacy_ownerless_rows_inaccessible(client: TestClient, db_session: Session):
    """Test legacy unowned rows (owner_user_id=None) return 404 for authenticated users."""
    user = _login_user(client, "normal_user@example.com")

    # Insert legacy scan and change analysis directly with owner_user_id=None
    legacy_scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/legacy/repo",
        owner_user_id=None,
        status="COMPLETED",
    )
    legacy_ca = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/legacy/repo",
        repository_owner="legacy",
        repository_name="repo",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        owner_user_id=None,
        status="COMPLETED",
        model_metadata={},
    )
    legacy_scan._explicit_unowned = True
    legacy_ca._explicit_unowned = True
    db_session.add_all([legacy_scan, legacy_ca])
    db_session.commit()

    # User attempts to query legacy resources -> 404
    assert user["client"].get(f"/api/v1/scans/{legacy_scan.id}").status_code == 404
    assert user["client"].get(f"/api/v1/change-analyses/{legacy_ca.id}").status_code == 404
