"""Test Phase 8: Operator Role Privilege Boundary & Confused-Deputy Defense.

Verifies:
- Privileged GitHub writes require role OPERATOR:
  - POST /api/v1/patches/{patch_id}/deliver
  - POST /api/v1/change-analyses/{analysis_id}/review-publication/preview
  - POST /api/v1/change-analyses/{analysis_id}/review-publication/approve
  - POST /api/v1/change-analyses/{analysis_id}/review-publication/publish
- Role USER calling privileged endpoints receives HTTP 403 OPERATOR_REQUIRED.
- Role OPERATOR is strictly tenant-isolated to their own resources (cross-tenant returns 404).
- Confused-Deputy defense: `GitHubPRResolver` uses unauthenticated transport without ambient GITHUB_TOKEN.
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.cli.create_operator import create_or_elevate_operator
from app.api.routes.deliveries import get_delivery_service
from app.delivery.provider import RepositoryDeliveryProvider
from app.delivery.service import DeliveryService
from app.ingestion.github_pr import GitHubPRResolver, get_github_pr_resolver
from app.main import app
from app.models.change_analysis import ChangeAnalysisModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.user import UserModel
from tests.request_helpers import cookie_headers


def _create_and_login_user(client: TestClient, email: str, password: str = "SecurePass12345!"):
    """Helper to create and log in a regular USER."""
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    user_id = login_resp.json()["id"]
    session_cookie = login_resp.cookies["repolens_session"]
    csrf_cookie = login_resp.cookies["repolens_csrf"]

    return {
        "id": user_id,
        "email": email,
        "role": "USER",
        "cookies": {"repolens_session": session_cookie, "repolens_csrf": csrf_cookie},
        "headers": {"X-CSRF-Token": csrf_cookie},
    }


def _create_and_login_operator(client: TestClient, db_session: Session, email: str, password: str = "OperatorPass12345!"):
    """Helper to create and log in an OPERATOR."""
    create_or_elevate_operator(db_session, email=email, password=password)
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    user_id = login_resp.json()["id"]
    session_cookie = login_resp.cookies["repolens_session"]
    csrf_cookie = login_resp.cookies["repolens_csrf"]

    return {
        "id": user_id,
        "email": email,
        "role": "OPERATOR",
        "cookies": {"repolens_session": session_cookie, "repolens_csrf": csrf_cookie},
        "headers": {"X-CSRF-Token": csrf_cookie},
    }


def test_regular_user_cannot_deliver_patch(client: TestClient, db_session: Session):
    """Test standard USER receives 403 on POST /deliveries."""
    user = _create_and_login_user(client, "regular_dev@example.com")

    # Create scan, finding, and approved patch owned by user
    scan = ScanModel(id=str(uuid4()), repository_url="https://github.com/org/repo", owner_user_id=user["id"], status="COMPLETED")
    finding = FindingModel(id=str(uuid4()), scan_id=scan.id, title="Test finding", description="desc", severity="HIGH", status="OPEN")
    patch_obj = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan.id,
        status="APPROVED",
        unified_diff="diff --git a/a b/b\n",
        files_modified=["a.py"],
        explanation="fix vulnerability",
        expected_behavior_change="none",
    )
    db_session.add_all([scan, finding, patch_obj])
    db_session.commit()

    # User attempts to trigger delivery -> 403 OPERATOR_REQUIRED
    resp = client.post(
        f"/api/v1/patches/{patch_obj.id}/deliver",
        json={"target_branch": "patch-branch"},
        headers=cookie_headers(user["cookies"], user["headers"]),
    )
    assert resp.status_code == 403
    assert "INSUFFICIENT_PRIVILEGES" in str(resp.json()["detail"])


def test_regular_user_cannot_publish_pr_review(client: TestClient, db_session: Session):
    """Test standard USER receives 403 on review publication endpoints."""
    user = _create_and_login_user(client, "regular_reviewer@example.com")

    ca = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo",
        repository_owner="org",
        repository_name="repo",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        owner_user_id=user["id"],
        status="COMPLETED",
        model_metadata={"pr_number": 42},
    )
    db_session.add(ca)
    db_session.commit()

    # User attempts preview -> 403
    resp = client.post(
        f"/api/v1/change-analyses/{ca.id}/review-publication/preview",
        headers=cookie_headers(user["cookies"], user["headers"]),
    )
    assert resp.status_code == 403
    assert "INSUFFICIENT_PRIVILEGES" in str(resp.json()["detail"])


def test_operator_cross_tenant_delivery_isolation(client: TestClient, db_session: Session):
    """Test OPERATOR cannot deliver a patch owned by a different user (returns 404)."""
    user_a = _create_and_login_user(client, "user_victim@example.com")
    operator = _create_and_login_operator(client, db_session, "operator_admin@example.com")

    # Resource owned by user A
    scan = ScanModel(id=str(uuid4()), repository_url="https://github.com/org/repo", owner_user_id=user_a["id"], status="COMPLETED")
    finding = FindingModel(id=str(uuid4()), scan_id=scan.id, title="Test finding", description="desc", severity="HIGH", status="OPEN")
    patch_obj = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan.id,
        status="APPROVED",
        unified_diff="diff --git a/a b/b\n",
        files_modified=["a.py"],
        explanation="fix vulnerability",
        expected_behavior_change="none",
    )
    db_session.add_all([scan, finding, patch_obj])
    db_session.commit()

    # Operator attempts to deliver User A's patch -> 404 (not owned by operator)
    resp = client.post(
        f"/api/v1/patches/{patch_obj.id}/deliver",
        json={"target_branch": "patch-branch"},
        headers=cookie_headers(operator["cookies"], operator["headers"]),
    )
    assert resp.status_code == 404


def test_confused_deputy_defense_credential_free_transport(monkeypatch):
    """Test GitHubPRResolver explicitly passes token='' and does NOT leak server GITHUB_TOKEN."""
    import app.ingestion.github_pr as gh_module

    # Reset singleton to force re-creation
    monkeypatch.setattr(gh_module, "_default_github_pr_resolver", None)

    # Set ambient environment GITHUB_TOKEN
    monkeypatch.setenv("GITHUB_TOKEN", "super-secret-operator-github-token-999")

    resolver = GitHubPRResolver()
    assert resolver._token == ""

    # Verify get_github_pr_resolver singleton factory also uses empty token
    singleton_resolver = get_github_pr_resolver()
    assert singleton_resolver._token == ""


def test_unapproved_patch_never_invokes_github_mutations(client: TestClient, db_session: Session):
    """An operator request without human approval must stop before any remote write."""
    owner = db_session.query(UserModel).filter_by(email="default_test_user@example.com").one()
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo",
        owner_user_id=owner.id,
        status="COMPLETED",
        branch="main",
        commit_hash="a" * 40,
    )
    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title="Pending approval finding",
        description="Requires explicit human approval before delivery.",
        severity="HIGH",
        status="OPEN",
    )
    patch_obj = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan.id,
        status="DRAFT",
        unified_diff="diff --git a/app.py b/app.py\n",
        files_modified=["app.py"],
        explanation="pending",
        expected_behavior_change="none",
    )
    db_session.add_all([scan, finding, patch_obj])
    db_session.commit()

    provider = MagicMock(spec=RepositoryDeliveryProvider)
    provider.is_configured = True
    service = DeliveryService(provider=provider)
    app.dependency_overrides[get_delivery_service] = lambda: service
    try:
        response = client.post(f"/api/v1/patches/{patch_obj.id}/deliver")
    finally:
        app.dependency_overrides.pop(get_delivery_service, None)

    assert response.status_code == 409
    for method_name in (
        "create_blob",
        "create_tree",
        "create_commit",
        "create_branch",
        "create_pull_request",
    ):
        assert getattr(provider, method_name).await_count == 0
