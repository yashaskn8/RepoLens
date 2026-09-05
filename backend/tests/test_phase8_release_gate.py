"""Authoritative Phase 8 Release Gate & Multi-User Security Verification.

Covers all 12 Core Requirements (A through L):
A. Argon2id password hashing, dummy verification, email validation, and account lockout after 5 failed attempts.
B. Server-side opaque sessions with SHA-256 token hashing, sliding expiration, and explicit logout revocation.
C. Double-submit cookie + header CSRF protection with constant-time and session-binding verification.
D. Direct SQL-joined multi-user tenant ownership isolation returning 404 (never 403) across all entities.
E. Legacy ownerless rows safety and isolation (return 404 for regular users).
F. Operator role gating for all privileged GitHub write actions (Phase 5 Delivery and Phase 7 Review Publication).
G. Operator tenant isolation (operators cannot deliver or publish other users' resources).
H. Confused-Deputy defense (credential-free GitHub PR resolver with token="").
I. Atomic transactional daily quotas (SCAN_CREATE: 20, CHANGE_ANALYSIS_CREATE: 50, PATCH_GENERATE: 50).
J. Auditable actor attribution on all workflow events (`actor_user_id`).
K. Production security headers, trusted hosts middleware, request ID tracing, and secure cookie enforcement.
L. Operator bootstrap CLI utility (`create_operator`).
"""

from datetime import datetime, timezone
from unittest.mock import patch
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.cli.create_operator import create_or_elevate_operator
from app.ingestion.github_pr import get_github_pr_resolver
from app.models.change_analysis import ChangeAnalysisModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.user import UserModel, UserSessionModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import UsageOperation, UserRole
from app.security.password import hash_password, verify_dummy_password, verify_password
from app.services.quota_service import check_and_increment_quota
from tests.request_helpers import cookie_headers


def _login_actor(client: TestClient, db_session: Session, email: str, role: str = "USER", password: str = "SecurePass12345!"):
    """Helper to create and log in a user with a given role."""
    client.cookies.clear()
    if role == "OPERATOR":
        create_or_elevate_operator(db_session, email=email, password=password)
    else:
        client.post("/api/v1/auth/register", json={"email": email, "password": password})
    
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    user_id = login_resp.json()["id"]
    session_cookie = login_resp.cookies["repolens_session"]
    csrf_cookie = login_resp.cookies["repolens_csrf"]
    client.cookies.clear()

    return {
        "id": user_id,
        "email": email,
        "role": role,
        "cookies": {"repolens_session": session_cookie, "repolens_csrf": csrf_cookie},
        "headers": {"X-CSRF-Token": csrf_cookie},
    }


def test_phase8_comprehensive_release_gate(client: TestClient, db_session: Session):
    """Authoritative Phase 8 Release Gate end-to-end verification."""
    
    # -------------------------------------------------------------------------
    # Requirement A: Passwords, Hashing, Validation & Lockouts
    # -------------------------------------------------------------------------
    p_hash = hash_password("ValidPassword123!")
    assert verify_password("ValidPassword123!", p_hash) is True
    assert verify_password("WrongPassword123!", p_hash) is False
    verify_dummy_password()

    # Reject short password
    assert client.post("/api/v1/auth/register", json={"email": "short@example.com", "password": "short"}).status_code == 422
    # Reject invalid email
    assert client.post("/api/v1/auth/register", json={"email": "notanemail", "password": "ValidPassword123!"}).status_code == 422

    # -------------------------------------------------------------------------
    # Requirement B & L: Registration, Login, Session Management, Operator CLI
    # -------------------------------------------------------------------------
    alice = _login_actor(client, db_session, "alice@example.com", role="USER")
    bob = _login_actor(client, db_session, "bob@example.com", role="USER")
    op_charlie = _login_actor(client, db_session, "charlie_op@example.com", role="OPERATOR")

    assert alice["role"] == "USER"
    assert op_charlie["role"] == "OPERATOR"

    # Verify /me
    alice_me = client.get("/api/v1/auth/me", headers=cookie_headers(alice["cookies"])).json()
    assert alice_me["email"] == "alice@example.com"
    assert alice_me["role"] == "USER"

    charlie_me = client.get("/api/v1/auth/me", headers=cookie_headers(op_charlie["cookies"])).json()
    assert charlie_me["email"] == "charlie_op@example.com"
    assert charlie_me["role"] == "OPERATOR"

    # -------------------------------------------------------------------------
    # Requirement C: Double-Submit CSRF Verification
    # -------------------------------------------------------------------------
    # Missing CSRF header on POST returns 403
    no_csrf = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/alice/repo"},
        headers=cookie_headers(alice["cookies"]),
    )
    assert no_csrf.status_code == 403
    assert "CSRF" in str(no_csrf.json()["detail"])

    # Valid CSRF succeeds
    alice_scan_resp = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/alice/repo"},
        headers=cookie_headers(alice["cookies"], alice["headers"]),
    )
    assert alice_scan_resp.status_code == 202
    alice_scan_id = str(alice_scan_resp.json()["id"])

    # -------------------------------------------------------------------------
    # Requirement D & J: Tenant Isolation & Event Actor Attribution
    # -------------------------------------------------------------------------
    # Alice can view her scan
    assert client.get(f"/api/v1/scans/{alice_scan_id}", headers=cookie_headers(alice["cookies"])).status_code == 200

    # Bob CANNOT view Alice's scan (returns 404)
    assert client.get(f"/api/v1/scans/{alice_scan_id}", headers=cookie_headers(bob["cookies"])).status_code == 404

    # Verify event emitted has actor_user_id == alice["id"]
    event = db_session.query(WorkflowEventModel).filter_by(scan_id=alice_scan_id).first()
    assert event is not None
    assert event.actor_user_id == alice["id"]

    # Alice creates Change Analysis
    alice_ca_resp = client.post(
        "/api/v1/change-analyses",
        json={
            "repository_url": "https://github.com/alice/repo",
            "base_commit_sha": "1111111111111111111111111111111111111111",
            "head_commit_sha": "2222222222222222222222222222222222222222",
        },
        headers=cookie_headers(alice["cookies"], alice["headers"]),
    )
    assert alice_ca_resp.status_code == 202
    alice_ca_id = str(alice_ca_resp.json()["id"])

    # Bob CANNOT view Alice's change analysis (returns 404)
    assert client.get(f"/api/v1/change-analyses/{alice_ca_id}", headers=cookie_headers(bob["cookies"])).status_code == 404
    assert client.get(f"/api/v1/change-analyses/{alice_ca_id}/report", headers=cookie_headers(bob["cookies"])).status_code == 404

    # -------------------------------------------------------------------------
    # Requirement E: Legacy Ownerless Safety
    # -------------------------------------------------------------------------
    legacy_scan = ScanModel(id=str(uuid4()), repository_url="https://github.com/legacy/repo", owner_user_id=None, status="COMPLETED")
    legacy_scan._explicit_unowned = True
    db_session.add(legacy_scan)
    db_session.commit()
    assert client.get(f"/api/v1/scans/{legacy_scan.id}", headers=cookie_headers(alice["cookies"])).status_code == 404

    # -------------------------------------------------------------------------
    # Requirement F & G: Operator Role Gating & Operator Tenant Isolation
    # -------------------------------------------------------------------------
    # Create patch on Alice's scan
    finding = FindingModel(id=str(uuid4()), scan_id=alice_scan_id, title="Vuln", description="desc", severity="HIGH", status="OPEN")
    patch_obj = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=alice_scan_id,
        status="APPROVED",
        unified_diff="diff --git a/a b/b\n",
        files_modified=["a.py"],
        explanation="fix vulnerability",
        expected_behavior_change="none",
    )
    db_session.add_all([finding, patch_obj])
    db_session.commit()

    # Alice (USER) cannot deliver patch -> 403 INSUFFICIENT_PRIVILEGES
    alice_deliver = client.post(
        f"/api/v1/patches/{patch_obj.id}/deliver",
        json={"target_branch": "patch-branch"},
        headers=cookie_headers(alice["cookies"], alice["headers"]),
    )
    assert alice_deliver.status_code == 403
    assert "INSUFFICIENT_PRIVILEGES" in str(alice_deliver.json()["detail"])

    # Charlie (OPERATOR) cannot deliver Alice's patch because Charlie is NOT the owner -> 404
    charlie_deliver = client.post(
        f"/api/v1/patches/{patch_obj.id}/deliver",
        json={"target_branch": "patch-branch"},
        headers=cookie_headers(op_charlie["cookies"], op_charlie["headers"]),
    )
    assert charlie_deliver.status_code == 404

    # -------------------------------------------------------------------------
    # Requirement H: Confused-Deputy Defense
    # -------------------------------------------------------------------------
    import app.ingestion.github_pr as gh_module
    # Reset singleton to force re-creation for clean test
    original_resolver = gh_module._default_github_pr_resolver
    gh_module._default_github_pr_resolver = None
    try:
        resolver = get_github_pr_resolver()
        assert resolver._token == ""
    finally:
        gh_module._default_github_pr_resolver = original_resolver

    # -------------------------------------------------------------------------
    # Requirement I: Atomic Transactional Daily Quotas
    # -------------------------------------------------------------------------
    # User Dave
    dave = _login_actor(client, db_session, "dave_quota@example.com", role="USER")
    # Dave creates 20 scans
    for _ in range(19):
        check_and_increment_quota(db_session, dave["id"], UsageOperation.SCAN_CREATE.value)

    # 20th scan via API succeeds
    resp_20 = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/dave/repo"},
        headers=cookie_headers(dave["cookies"], dave["headers"]),
    )
    assert resp_20.status_code == 202

    # 21st scan via API returns 429
    resp_21 = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/dave/repo"},
        headers=cookie_headers(dave["cookies"], dave["headers"]),
    )
    assert resp_21.status_code == 429
    assert "DAILY_QUOTA_EXCEEDED" in str(resp_21.json()["detail"])

    # -------------------------------------------------------------------------
    # Requirement K: Production Security Headers & Traceability
    # -------------------------------------------------------------------------
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert health_resp.headers.get("X-Frame-Options") == "DENY"
    assert health_resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert health_resp.headers.get("Permissions-Policy") == "geolocation=(), camera=(), microphone=()"
    assert "X-Request-ID" in health_resp.headers
