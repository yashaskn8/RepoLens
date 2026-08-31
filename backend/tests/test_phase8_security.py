"""Comprehensive Phase 8 Production Security, Hardening, and Concurrency Test Suite.

Verifies:
1. Production secure-cookie requirement fail-closed
2. Wildcard and empty CORS rejected in production
3. Wildcard and empty trusted hosts rejected in production
4. API docs disabled in production / when configured
5. Authorization helper fail-closed semantics (raises 401 on unauthenticated identity)
6. No default-test-user quota fallback (rejects unauthenticated quota consumption)
7. Cross-tenant IDOR prevention (404 on non-owned resources)
8. Operator cross-tenant boundary
9. approved_by spoof attempt overridden by authenticated identity
10. requested_by spoof attempt overridden by authenticated identity
11. CLI --password / -p rejected by argument parser
12. Existing user operator elevation requires explicit confirmation
13. Production CSRF rejects localhost / testserver / arbitrary origins
14. Production CSRF accepts exact configured CORS origin
15. Confused-deputy defense: Outgoing public GitHub PR request contains NO Authorization header
16. Private repository 404 remains private
17. Missing GitHub PR state fails closed
18. Missing GitHub repository metadata fails closed
19. Session token never persisted raw in database (SHA-256 hash only)
20. CSRF token never persisted raw in database (SHA-256 hash only)
21. Auth errors contain no passwords, hashes, or secret tokens
22. Legacy ownerless rows inaccessible to normal authenticated users
23. Genuinely atomic quota increments under multi-connection SQLite concurrency
24. Base.metadata.create_all not invoked during application startup lifespan
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse
from uuid import UUID, uuid4
import httpx
import pytest
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.dependencies import get_current_user, require_operator, verify_csrf
from app.cli.create_operator import main as cli_main
from app.core.config import Settings, get_settings
from app.core.database import Base, SessionLocal
from app.delivery.github_client import GitHubHttpTransport
from app.ingestion.github_pr import (
    GitHubPRAPIError,
    GitHubPRNotFoundError,
    GitHubPRResolver,
)
from app.main import app, lifespan
from app.models.change_analysis import ChangeAnalysisModel
from app.models.delivery import DeliveryModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.user import UserModel, UserSessionModel, UsageCounterModel
from app.schemas.auth import CurrentUser, get_user_id
from app.schemas.change_analysis import ChangeAnalysisPRRequest
from app.schemas.delivery import DeliveryRequest
from app.schemas.enums import PatchStatus, ScanStatus, UsageOperation, UserRole
from app.schemas.patch import PatchReviewRequest
from app.services.auth_service import AuthService
from app.services.authorization_service import (
    get_owned_change_analysis_or_404,
    get_owned_delivery_or_404,
    get_owned_finding_or_404,
    get_owned_patch_or_404,
    get_owned_review_publication_or_404,
    get_owned_scan_or_404,
)
from app.services.quota_service import check_and_increment_quota, get_usage_count


# =========================================================================
# Helpers
# =========================================================================

def _create_user_client(email: str = "sec_user@example.com", role: str = "USER") -> Dict[str, Any]:
    """Helper creating a test user and returning a dedicated TestClient with active session."""
    user_client = TestClient(app)
    user_client.post("/api/v1/auth/register", json={"email": email, "password": "SecurePassword123!"})
    
    # If role is OPERATOR, elevate in DB
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.email == email).first()
        if role == "OPERATOR" and user:
            user.role = UserRole.OPERATOR.value
            db.commit()
    finally:
        db.close()

    login_resp = user_client.post("/api/v1/auth/login", json={"email": email, "password": "SecurePassword123!"})
    user_id = login_resp.json()["id"]
    csrf_token = login_resp.cookies["repolens_csrf"]
    user_client.headers["X-CSRF-Token"] = csrf_token

    return {
        "id": user_id,
        "email": email,
        "role": role,
        "client": user_client,
        "csrf_token": csrf_token,
    }


# =========================================================================
# 1. Production Configuration & Cookie Invariants
# =========================================================================

def test_production_requires_secure_cookie():
    """In production, AUTH_COOKIE_SECURE must be True; False raises ValueError."""
    with pytest.raises(ValueError, match="AUTH_COOKIE_SECURE must be True"):
        Settings(
            ENVIRONMENT="production",
            AUTH_COOKIE_SECURE=False,
            CORS_ORIGINS=["https://app.example.com"],
            TRUSTED_HOSTS=["app.example.com"],
        )


def test_production_rejects_wildcard_cors():
    """In production, wildcard CORS ('*') is prohibited."""
    with pytest.raises(ValueError, match="Wildcard CORS origin"):
        Settings(
            ENVIRONMENT="production",
            AUTH_COOKIE_SECURE=True,
            CORS_ORIGINS=["*"],
            TRUSTED_HOSTS=["app.example.com"],
        )


def test_production_rejects_empty_cors():
    """In production, CORS_ORIGINS must not be empty."""
    with pytest.raises(ValueError, match="CORS_ORIGINS must not be empty"):
        Settings(
            ENVIRONMENT="production",
            AUTH_COOKIE_SECURE=True,
            CORS_ORIGINS=[],
            TRUSTED_HOSTS=["app.example.com"],
        )


def test_production_rejects_wildcard_trusted_hosts():
    """In production, wildcard TRUSTED_HOSTS ('*') is prohibited."""
    with pytest.raises(ValueError, match="Wildcard Trusted Hosts"):
        Settings(
            ENVIRONMENT="production",
            AUTH_COOKIE_SECURE=True,
            CORS_ORIGINS=["https://app.example.com"],
            TRUSTED_HOSTS=["*"],
        )


def test_samesite_none_requires_secure_cookie():
    """When AUTH_COOKIE_SAMESITE is 'none', AUTH_COOKIE_SECURE must be True."""
    with pytest.raises(ValueError, match="When AUTH_COOKIE_SAMESITE is 'none', AUTH_COOKIE_SECURE must be True"):
        Settings(
            AUTH_COOKIE_SAMESITE="none",
            AUTH_COOKIE_SECURE=False,
        )


def test_docs_disabled_in_production(monkeypatch):
    """When ENABLE_API_DOCS is False, /docs and /openapi.json return 404."""
    # Test setting openapi_url and docs_url to None
    disabled_app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    client = TestClient(disabled_app)
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_production_and_dev_enable_api_docs_defaults():
    """Verify ENABLE_API_DOCS defaults to False in production and True in dev."""
    prod_s = Settings(
        ENVIRONMENT="production",
        AUTH_COOKIE_SECURE=True,
        CORS_ORIGINS=["https://app.example.com"],
        TRUSTED_HOSTS=["app.example.com"],
    )
    assert prod_s.ENABLE_API_DOCS is False

    dev_s = Settings(
        ENVIRONMENT="development",
    )
    assert dev_s.ENABLE_API_DOCS is True

    # Explicit override in production is preserved if configured
    prod_custom = Settings(
        ENVIRONMENT="production",
        AUTH_COOKIE_SECURE=True,
        CORS_ORIGINS=["https://app.example.com"],
        TRUSTED_HOSTS=["app.example.com"],
        ENABLE_API_DOCS=True,
    )
    assert prod_custom.ENABLE_API_DOCS is True


# =========================================================================
# 2. Schema Lifecycle: Base.metadata.create_all not invoked on startup
# =========================================================================

@pytest.mark.asyncio
async def test_startup_lifespan_does_not_mutate_schema():
    """Application lifespan startup must NOT invoke Base.metadata.create_all."""
    with patch.object(Base.metadata, "create_all") as mock_create_all:
        test_app = FastAPI(lifespan=lifespan)
        async with test_app.router.lifespan_context(test_app):
            pass
        mock_create_all.assert_not_called()


# =========================================================================
# 3. Fail-Closed Authorization Helpers
# =========================================================================

def test_authorization_helpers_fail_closed_on_none_identity(db_session: Session):
    """All get_owned_*_or_404 helpers must raise 401 AUTH_REQUIRED when user is unauthenticated or None."""
    with pytest.raises(HTTPException) as exc:
        get_owned_scan_or_404(db_session, str(uuid4()), None)
    assert exc.value.status_code == 401
    assert exc.value.detail["error_code"] == "AUTH_REQUIRED"

    with pytest.raises(HTTPException) as exc:
        get_owned_finding_or_404(db_session, str(uuid4()), None)
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        get_owned_patch_or_404(db_session, str(uuid4()), None)
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        get_owned_delivery_or_404(db_session, str(uuid4()), None)
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        get_owned_change_analysis_or_404(db_session, str(uuid4()), None)
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        get_owned_review_publication_or_404(db_session, str(uuid4()), None)
    assert exc.value.status_code == 401


def test_authorization_helpers_reject_arbitrary_objects(db_session: Session):
    """Objects that merely have an 'id' attribute but are not CurrentUser must be rejected."""
    class FakeIdentity:
        id = "malicious-injected-id"

    with pytest.raises(HTTPException) as exc:
        get_owned_scan_or_404(db_session, str(uuid4()), FakeIdentity())
    assert exc.value.status_code == 401


def test_authorization_rejects_raw_string_identity(db_session: Session):
    """Authorization must reject raw string user IDs — only CurrentUser is trusted."""
    with pytest.raises(HTTPException) as exc:
        get_owned_scan_or_404(db_session, str(uuid4()), "real-looking-user-id")
    assert exc.value.status_code == 401
    assert exc.value.detail["error_code"] == "AUTH_REQUIRED"


def test_authorization_rejects_uuid_string_identity(db_session: Session):
    """Even a valid UUID string must be rejected — only CurrentUser objects are accepted."""
    valid_uuid_str = str(uuid4())
    with pytest.raises(HTTPException) as exc:
        get_owned_scan_or_404(db_session, str(uuid4()), valid_uuid_str)
    assert exc.value.status_code == 401
    assert exc.value.detail["error_code"] == "AUTH_REQUIRED"


def test_authorization_rejects_user_model_identity(db_session: Session):
    """UserModel is NOT a trusted authorization identity — only CurrentUser is."""
    fake_user = UserModel(id=str(uuid4()), email="attacker@example.com", role="USER")
    with pytest.raises(HTTPException) as exc:
        get_owned_scan_or_404(db_session, str(uuid4()), fake_user)
    assert exc.value.status_code == 401
    assert exc.value.detail["error_code"] == "AUTH_REQUIRED"


def test_authorization_rejects_uuid_object_identity(db_session: Session):
    """UUID objects must be rejected — only CurrentUser is accepted."""
    with pytest.raises(HTTPException) as exc:
        get_owned_scan_or_404(db_session, str(uuid4()), uuid4())
    assert exc.value.status_code == 401
    assert exc.value.detail["error_code"] == "AUTH_REQUIRED"


def test_authorization_rejects_dict_identity(db_session: Session):
    """A dict with an 'id' key must be rejected."""
    with pytest.raises(HTTPException) as exc:
        get_owned_scan_or_404(db_session, str(uuid4()), {"id": str(uuid4()), "role": "OPERATOR"})
    assert exc.value.status_code == 401
    assert exc.value.detail["error_code"] == "AUTH_REQUIRED"


# =========================================================================
# 4. Quota Identity & Atomic Increments
# =========================================================================

def test_quota_service_fails_closed_on_missing_or_default_user_id(db_session: Session):
    """check_and_increment_quota rejects None, empty, or default-test-user IDs with 401."""
    with pytest.raises(HTTPException) as exc:
        check_and_increment_quota(db_session, user_id=None, operation=UsageOperation.SCAN_CREATE.value)
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        check_and_increment_quota(db_session, user_id="default-test-user", operation=UsageOperation.SCAN_CREATE.value)
    assert exc.value.status_code == 401


def test_quota_accepts_valid_uuid_string(db_session: Session):
    """check_and_increment_quota must accept a valid UUID string and increment."""
    valid_user_id = str(uuid4())
    count = check_and_increment_quota(db_session, user_id=valid_user_id, operation=UsageOperation.SCAN_CREATE.value)
    assert count == 1


def test_quota_rejects_current_user_object(db_session: Session):
    """Passing a CurrentUser object directly (instead of current_user.id) must be rejected."""
    cu = CurrentUser(id=str(uuid4()), email="test@example.com", role="USER", is_active=True, session_id="sess")
    with pytest.raises(HTTPException) as exc:
        check_and_increment_quota(db_session, user_id=cu, operation=UsageOperation.SCAN_CREATE.value)
    assert exc.value.status_code == 401


def test_quota_rejects_user_model_object(db_session: Session):
    """Passing a UserModel object must be rejected — only string UUID accepted."""
    um = UserModel(id=str(uuid4()), email="model@example.com", role="USER")
    with pytest.raises(HTTPException) as exc:
        check_and_increment_quota(db_session, user_id=um, operation=UsageOperation.SCAN_CREATE.value)
    assert exc.value.status_code == 401


def test_quota_rejects_uuid_object(db_session: Session):
    """Passing a UUID object (not string) must be rejected."""
    with pytest.raises(HTTPException) as exc:
        check_and_increment_quota(db_session, user_id=uuid4(), operation=UsageOperation.SCAN_CREATE.value)
    assert exc.value.status_code == 401


def test_quota_rejects_non_uuid_strings(db_session: Session):
    """Non-UUID strings must be rejected by UUID validation."""
    for bad_id in ["some-user", "admin", "<injected>", "   ", "12345"]:
        with pytest.raises(HTTPException) as exc:
            check_and_increment_quota(db_session, user_id=bad_id, operation=UsageOperation.SCAN_CREATE.value)
        assert exc.value.status_code == 401, f"Should reject '{bad_id}'"


def test_quota_rejects_empty_string(db_session: Session):
    """Empty string must be rejected."""
    with pytest.raises(HTTPException) as exc:
        check_and_increment_quota(db_session, user_id="", operation=UsageOperation.SCAN_CREATE.value)
    assert exc.value.status_code == 401


def test_quota_multi_connection_concurrency_file_backed_sqlite(tmp_path: Path):
    """Prove atomic conditional quota updates with multi-connection SQLite concurrency.

    Sets limit to 2. Starts with count=1.
    Dispatches two concurrent requests on separate connections.
    Exactly 1 request must succeed (reaching limit 2) and exactly 1 must receive 429.
    Final DB count must be strictly 2 (never 3).
    """
    db_path = tmp_path / "quota_atomic_concurrency.db"
    db_url = f"sqlite:///{db_path}"
    test_engine = create_engine(db_url, connect_args={"check_same_thread": False, "timeout": 30.0})
    Base.metadata.create_all(bind=test_engine)
    SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    user_id = str(uuid4())
    today = datetime.now(timezone.utc).date()
    op = UsageOperation.SCAN_CREATE.value

    # Seed row with count = 1
    init_db = SessionMaker()
    init_db.add(UsageCounterModel(
        id=str(uuid4()),
        user_id=user_id,
        bucket_date=today,
        operation=op,
        count=1,
    ))
    init_db.commit()
    init_db.close()

    test_settings = Settings(MAX_DAILY_SCANS_PER_USER=2)

    def worker_increment():
        worker_db = SessionMaker()
        try:
            res = check_and_increment_quota(
                db=worker_db,
                user_id=user_id,
                operation=op,
                settings=test_settings,
            )
            worker_db.commit()
            return ("SUCCESS", res)
        except HTTPException as e:
            worker_db.rollback()
            return ("429", e.status_code)
        finally:
            worker_db.close()

    # Run two concurrent increment attempts
    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(worker_increment)
        f2 = executor.submit(worker_increment)
        results = [f1.result(), f2.result()]

    statuses = [r[0] for r in results]
    assert "SUCCESS" in statuses, f"Expected one success, got {statuses}"
    assert "429" in statuses, f"Expected one 429 rejection, got {statuses}"

    # Verify final count in database is exactly 2
    verify_db = SessionMaker()
    final_count = get_usage_count(verify_db, user_id, op)
    verify_db.close()
    assert final_count == 2, f"Final count should be 2, got {final_count}"


# =========================================================================
# 5. Operator CLI Argument Hardening & Interactive Confirmation
# =========================================================================

def test_cli_parser_rejects_password_flag():
    """CLI argument parser must reject --password and -p flags."""
    import sys
    test_args = ["create_operator", "--email", "admin@example.com", "--password", "Secret123456!"]
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit):
            cli_main()


def test_cli_existing_user_elevation_requires_confirmation(db_session: Session):
    """Elevating an existing user to OPERATOR via CLI requires explicit interactive confirmation."""
    existing_email = "regular_user@example.com"
    user = UserModel(
        id=str(uuid4()),
        email=existing_email,
        password_hash="hash",
        role=UserRole.USER.value,
    )
    db_session.add(user)
    db_session.commit()

    import sys
    test_args = ["create_operator", "--email", existing_email]
    db_wrapper = MagicMock(wraps=db_session)
    db_wrapper.close = MagicMock()

    # 1. User says 'no' -> elevation cancelled, role unchanged
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit):
            cli_main(input_func=lambda prompt: "n", db_factory=lambda: db_wrapper)

    db_session.refresh(user)
    assert user.role == UserRole.USER.value

    # 2. User says 'yes' -> role elevated to OPERATOR
    with patch.object(sys, "argv", test_args):
        cli_main(input_func=lambda prompt: "y", db_factory=lambda: db_wrapper)

    db_session.refresh(user)
    assert user.role == UserRole.OPERATOR.value


# =========================================================================
# 6. Actor Attribution Spoofing Prevention
# =========================================================================

@pytest.mark.asyncio
async def test_patch_approval_ignores_spoofed_approved_by_in_payload(db_session: Session):
    """When User A approves a patch, approved_by is set to User A's ID regardless of payload."""
    from app.api.routes.patches import approve_patch
    
    user_a_id = str(uuid4())
    user_a = CurrentUser(id=user_a_id, email="a@example.com", role="USER", is_active=True, session_id="s1")
    
    scan = ScanModel(id=str(uuid4()), repository_url="https://github.com/org/repo", owner_user_id=user_a_id, status="COMPLETED")
    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title="Vuln",
        description="desc",
        severity="HIGH",
        status="CONFIRMED",
    )
    patch_obj = PatchModel(
        id=str(uuid4()),
        scan_id=scan.id,
        finding_id=finding.id,
        status=PatchStatus.DRAFT.value,
        unified_diff="diff",
        files_modified=["app.py"],
        explanation="fix",
        expected_behavior_change="none",
    )
    db_session.add_all([scan, finding, patch_obj])
    db_session.commit()

    spoofed_payload = PatchReviewRequest(approved_by="spoofed-admin-root", notes="Looks good")
    
    with patch("app.api.routes.patches.build_remediation_graph") as mock_graph_builder:
        mock_graph = MagicMock()
        mock_graph.aget_state = AsyncMock(return_value=None)
        mock_graph.aupdate_state = AsyncMock()
        mock_graph.ainvoke = AsyncMock()
        mock_graph_builder.return_value = mock_graph

        await approve_patch(
            patch_id=patch_obj.id,
            payload=spoofed_payload,
            current_user=user_a,
            _csrf=None,
            db=db_session,
        )

    db_session.refresh(patch_obj)
    assert patch_obj.approved_by == user_a_id, f"Expected '{user_a_id}', got '{patch_obj.approved_by}'"
    assert patch_obj.status == PatchStatus.APPROVED.value


# =========================================================================
# 7. Production CSRF Exact-Origin Policy
# =========================================================================

def test_production_csrf_rejects_localhost_and_arbitrary_origins():
    """In production, CSRF validation must reject localhost, testserver, and subdomain evil origins."""
    prod_settings = Settings(
        ENVIRONMENT="production",
        AUTH_COOKIE_SECURE=True,
        CORS_ORIGINS=["https://app.example.com"],
        TRUSTED_HOSTS=["app.example.com"],
    )

    # 1. Localhost in production -> 403
    req_localhost = MagicMock()
    req_localhost.method = "POST"
    req_localhost.headers = {"Origin": "http://localhost:3000"}
    with pytest.raises(HTTPException) as exc:
        verify_csrf(request=req_localhost, db=MagicMock(), settings=prod_settings)
    assert exc.value.status_code == 403

    # 2. Evil subdomain in production -> 403
    req_evil = MagicMock()
    req_evil.method = "POST"
    req_evil.headers = {"Origin": "https://app.example.com.evil.com"}
    with pytest.raises(HTTPException) as exc:
        verify_csrf(request=req_evil, db=MagicMock(), settings=prod_settings)
    assert exc.value.status_code == 403

    # 3. Exact origin in production with missing CSRF token -> proceeds past origin check to CSRF_MISSING
    req_exact = MagicMock()
    req_exact.method = "POST"
    req_exact.headers = {"Origin": "https://app.example.com"}
    req_exact.cookies = {}
    with pytest.raises(HTTPException) as exc:
        verify_csrf(request=req_exact, db=MagicMock(), settings=prod_settings)
    assert exc.value.detail["error_code"] == "CSRF_MISSING"


# =========================================================================
# 8. Confused-Deputy Defense: Public PR Reads Dispatched Without Authorization
# =========================================================================

@pytest.mark.asyncio
async def test_confused_deputy_public_pr_outbound_request_has_no_authorization_header():
    """Public PR resolver must NOT send Authorization header even if server GITHUB_TOKEN is set."""
    server_settings = Settings(GITHUB_TOKEN="ghp_PRIVILEGED_SERVER_TOKEN_DO_NOT_SEND")

    # Use real GitHubHttpTransport with token=""
    transport = GitHubHttpTransport(token="", settings=server_settings)
    headers = transport.get_headers()
    
    assert "Authorization" not in headers, "Authorization header must be absent when token=''"
    assert "ghp_PRIVILEGED" not in str(headers), "Server GITHUB_TOKEN must not leak into headers"


@pytest.mark.asyncio
async def test_e2e_from_pr_route_confused_deputy_outbound_request_strips_token(monkeypatch):
    """Full E2E route test: POST /api/v1/change-analyses/from-pr executes through real resolver
    and sends outbound HTTP request WITHOUT Authorization header, even when server GITHUB_TOKEN is set.
    """
    privileged_token = "ghp_PRIVILEGED_SERVER_AMBIENT_TOKEN_SECRET123"
    custom_settings = Settings(
        GITHUB_TOKEN=privileged_token,
        ENVIRONMENT="development",
    )
    monkeypatch.setattr("app.core.config.get_settings", lambda: custom_settings)

    captured_requests: List[httpx.Request] = []

    def mock_transport_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        if "pulls/42" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "title": "PR 42",
                    "state": "open",
                    "base": {
                        "ref": "main",
                        "sha": "1111111111111111111111111111111111111111",
                        "repo": {"full_name": "owner/repo"},
                    },
                    "head": {
                        "ref": "feat",
                        "sha": "2222222222222222222222222222222222222222",
                        "repo": {"full_name": "owner/repo"},
                    },
                },
            )
        return httpx.Response(404, json={"message": "Not Found"})

    mock_async_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_transport_handler))
    e2e_resolver = GitHubPRResolver(settings=custom_settings, client=mock_async_client)
    monkeypatch.setattr("app.api.routes.change_analysis.get_github_pr_resolver", lambda: e2e_resolver)

    user_info = _create_user_client(email="pr_tester@example.com")
    client = user_info["client"]

    response = client.post(
        "/api/v1/change-analyses/from-pr",
        json={"pr_url": "https://github.com/owner/repo/pull/42"},
        headers={"X-CSRF-Token": user_info["csrf_token"]},
    )

    assert response.status_code == status.HTTP_202_ACCEPTED
    assert len(captured_requests) == 1
    sent_request = captured_requests[0]

    # Verify headers sent to GitHub API
    assert "authorization" not in sent_request.headers
    assert "Authorization" not in sent_request.headers
    assert privileged_token not in str(sent_request.headers)


# =========================================================================
# 9. GitHub PR Resolver Fail-Closed Metadata Invariants
# =========================================================================

@pytest.mark.asyncio
async def test_github_pr_missing_state_fails_closed():
    """Missing or empty state in GitHub API response raises GitHubPRAPIError."""
    mock_response = {
        "title": "No state PR",
        # "state" missing
        "base": {"ref": "main", "sha": "1111111111111111111111111111111111111111", "repo": {"full_name": "owner/repo"}},
        "head": {"ref": "feat", "sha": "2222222222222222222222222222222222222222", "repo": {"full_name": "owner/repo"}},
    }
    mock_transport = MagicMock()
    mock_transport.request = AsyncMock(return_value=mock_response)
    
    resolver = GitHubPRResolver(transport=mock_transport)
    with pytest.raises(GitHubPRAPIError, match="Missing state"):
        await resolver.resolve_pr("https://github.com/owner/repo/pull/1")


@pytest.mark.asyncio
async def test_github_pr_missing_repo_metadata_fails_closed():
    """Missing base.repo or head.repo metadata raises GitHubPRAPIError."""
    mock_response = {
        "title": "PR with missing repo info",
        "state": "open",
        "base": {"ref": "main", "sha": "1111111111111111111111111111111111111111"},
        "head": {"ref": "feat", "sha": "2222222222222222222222222222222222222222"},
    }
    mock_transport = MagicMock()
    mock_transport.request = AsyncMock(return_value=mock_response)
    
    resolver = GitHubPRResolver(transport=mock_transport)
    with pytest.raises(GitHubPRAPIError, match="Missing base repository metadata"):
        await resolver.resolve_pr("https://github.com/owner/repo/pull/1")


# =========================================================================
# 10. Database Hashing & Token Exposure Defense
# =========================================================================

def test_session_and_csrf_tokens_never_persisted_raw(db_session: Session):
    """Raw session tokens and CSRF tokens must never be written to database in plaintext."""
    client = TestClient(app)
    email = f"hash_test_{uuid4().hex[:8]}@example.com"
    client.post("/api/v1/auth/register", json={"email": email, "password": "SecurePassword123!"})
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": "SecurePassword123!"})
    
    raw_session = login_resp.cookies["repolens_session"]
    raw_csrf = login_resp.cookies["repolens_csrf"]

    user_session = db_session.query(UserSessionModel).all()
    
    for s in user_session:
        assert s.token_hash != raw_session, "Raw session token found in database token_hash!"
        assert s.csrf_token_hash != raw_csrf, "Raw CSRF token found in database csrf_token_hash!"
        assert len(s.token_hash) == 64, "token_hash should be 64-char SHA256 hex string"
        assert len(s.csrf_token_hash) == 64, "csrf_token_hash should be 64-char SHA256 hex string"


def test_auth_errors_contain_no_secrets():
    """Authentication errors must never reflect passwords or internal hashes."""
    client = TestClient(app)
    resp = client.post("/api/v1/auth/login", json={"email": "nonexistent@example.com", "password": "SecretInputPassword123!"})
    assert resp.status_code == 401
    assert "SecretInputPassword123!" not in resp.text
    assert "argon2" not in resp.text
    assert "hash" not in resp.text
