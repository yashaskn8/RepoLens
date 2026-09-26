"""Test Phase 8: Cross-Site Request Forgery (CSRF) Protection.

Verifies:
- Safe methods (GET, HEAD, OPTIONS) do not require CSRF tokens.
- Public auth endpoints (register, login) do not require CSRF tokens.
- State-modifying requests (POST, PUT, PATCH, DELETE) require:
  1. `repolens_csrf` raw cookie.
  2. `X-CSRF-Token` raw header matching cookie in constant time.
  3. SHA-256 hash of header token matching session `csrf_token_hash` in DB.
- Rejection of missing CSRF token (403).
- Rejection of mismatched cookie/header CSRF token (403).
- Rejection of token forged for a different session (403).
"""

import hashlib

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from sqlalchemy.orm import Session
from tests.request_helpers import cookie_headers
from app.api.dependencies import verify_csrf
from app.core.config import Settings
from app.models.user import UserSessionModel


@pytest.fixture
def authenticated_user(client: TestClient):
    """Register and login a user, returning email, cookies, and csrf token."""
    email = "csrf_tester@example.com"
    password = "SecurePassword12345!"

    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    
    session_cookie = login_resp.cookies["repolens_session"]
    csrf_cookie = login_resp.cookies["repolens_csrf"]
    client.cookies.clear()
    
    return {
        "email": email,
        "session_cookie": session_cookie,
        "csrf_cookie": csrf_cookie,
    }


def test_safe_methods_bypass_csrf(client: TestClient, authenticated_user):
    """Test GET requests do not require CSRF token."""
    client.cookies.clear()
    resp = client.get(
        "/api/v1/auth/me",
        headers=cookie_headers({"repolens_session": authenticated_user["session_cookie"]}),
    )
    assert resp.status_code == 200


def test_valid_csrf_token_succeeds(client: TestClient, authenticated_user):
    """Test state-modifying POST request with valid double-submit CSRF token succeeds."""
    client.cookies.clear()
    cookies = {
        "repolens_session": authenticated_user["session_cookie"],
        "repolens_csrf": authenticated_user["csrf_cookie"],
    }
    headers = {
        "X-CSRF-Token": authenticated_user["csrf_cookie"],
    }

    resp = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/org/repo"},
        headers=cookie_headers(cookies, headers),
    )
    assert resp.status_code == 202
    assert "github.com/org/repo" in resp.json()["repository_url"]


def test_missing_csrf_header_rejected(client: TestClient, authenticated_user):
    """Test POST request with missing X-CSRF-Token header returns 403."""
    client.cookies.clear()
    cookies = {
        "repolens_session": authenticated_user["session_cookie"],
        "repolens_csrf": authenticated_user["csrf_cookie"],
    }

    resp = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/org/repo"},
        headers=cookie_headers(cookies),
    )
    assert resp.status_code == 403
    assert "CSRF" in str(resp.json()["detail"])


def test_missing_csrf_cookie_rejected(client: TestClient, authenticated_user):
    """Test POST request with missing repolens_csrf cookie returns 403."""
    client.cookies.clear()
    cookies = {
        "repolens_session": authenticated_user["session_cookie"],
    }
    headers = {
        "X-CSRF-Token": authenticated_user["csrf_cookie"],
    }

    resp = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/org/repo"},
        headers=cookie_headers(cookies, headers),
    )
    assert resp.status_code == 403
    assert "CSRF" in str(resp.json()["detail"])


def test_mismatched_csrf_cookie_and_header_rejected(client: TestClient, authenticated_user):
    """Test POST request where cookie != header returns 403."""
    client.cookies.clear()
    cookies = {
        "repolens_session": authenticated_user["session_cookie"],
        "repolens_csrf": authenticated_user["csrf_cookie"],
    }
    headers = {
        "X-CSRF-Token": "tampered_csrf_token_value_1234567890",
    }

    resp = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/org/repo"},
        headers=cookie_headers(cookies, headers),
    )
    assert resp.status_code == 403
    assert "CSRF" in str(resp.json()["detail"])


def test_csrf_token_bound_to_different_session_rejected(client: TestClient, db_session: Session):
    """Test using User B's CSRF token for User A's session returns 403."""
    client.cookies.clear()
    # User A
    client.post("/api/v1/auth/register", json={"email": "usera@example.com", "password": "PasswordUserA123!"})
    login_a = client.post("/api/v1/auth/login", json={"email": "usera@example.com", "password": "PasswordUserA123!"})
    session_a = login_a.cookies["repolens_session"]

    client.cookies.clear()
    # User B
    client.post("/api/v1/auth/register", json={"email": "userb@example.com", "password": "PasswordUserB123!"})
    login_b = client.post("/api/v1/auth/login", json={"email": "userb@example.com", "password": "PasswordUserB123!"})
    csrf_b = login_b.cookies["repolens_csrf"]

    client.cookies.clear()
    # Send User A's session with User B's CSRF cookie & header (matching each other, but not session A)
    cookies = {
        "repolens_session": session_a,
        "repolens_csrf": csrf_b,
    }
    headers = {
        "X-CSRF-Token": csrf_b,
    }

    resp = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/org/repo"},
        headers=cookie_headers(cookies, headers),
    )
    assert resp.status_code == 403
    assert "CSRF" in str(resp.json()["detail"])


def test_matching_double_submit_pair_without_a_valid_session_is_rejected(db_session: Session):
    class RequestStub:
        method = "POST"
        headers = {"X-CSRF-Token": "syntactically-matching-csrf-token"}
        cookies = {
            "repolens_csrf": "syntactically-matching-csrf-token",
            "repolens_session": "not-a-real-session",
        }

    with pytest.raises(HTTPException) as raised:
        verify_csrf(
            request=RequestStub(),  # type: ignore[arg-type]
            db=db_session,
            settings=Settings(_env_file=None),
        )
    assert raised.value.status_code == 403
    assert raised.value.detail["error_code"] == "CSRF_SESSION_INVALID"


def test_revoked_session_cannot_authorize_csrf_pair(client: TestClient, db_session: Session):
    session_token = client.cookies.get("repolens_session")
    assert session_token
    token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    session = db_session.query(UserSessionModel).filter(UserSessionModel.token_hash == token_hash).one_or_none()
    assert session is not None
    session.revoked_at = session.created_at
    db_session.commit()
    class RequestStub:
        method = "POST"
        headers = {"X-CSRF-Token": client.cookies.get("repolens_csrf")}
        cookies = {
            "repolens_csrf": client.cookies.get("repolens_csrf"),
            "repolens_session": client.cookies.get("repolens_session"),
        }

    with pytest.raises(HTTPException) as raised:
        verify_csrf(
            request=RequestStub(),  # type: ignore[arg-type]
            db=db_session,
            settings=Settings(_env_file=None),
        )
    assert raised.value.status_code == 403
    assert raised.value.detail["error_code"] == "CSRF_SESSION_INVALID"


def test_login_cookie_scope_uses_independent_csrf_domain(client: TestClient, monkeypatch):
    monkeypatch.setenv("CSRF_COOKIE_DOMAIN", ".example.test")
    monkeypatch.setenv("AUTH_COOKIE_DOMAIN", "")
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "default_test_user@example.com", "password": "DefaultTestPass12345!"},
        )
        assert response.status_code == 200
        cookies = response.headers.get_list("set-cookie")
        session_cookie = next(value for value in cookies if value.startswith("repolens_session="))
        csrf_cookie = next(value for value in cookies if value.startswith("repolens_csrf="))
        assert "domain=.example.test" not in session_cookie.lower()
        assert "domain=.example.test" in csrf_cookie.lower()
        assert "httponly" in session_cookie.lower()
        assert "httponly" not in csrf_cookie.lower()
    finally:
        get_settings.cache_clear()


def _production_csrf_request(client, *, origin_headers=(), referer_headers=()):
    pairs = [(b"x-csrf-token", client.cookies["repolens_csrf"].encode())]
    pairs.extend((b"origin", value.encode()) for value in origin_headers)
    pairs.extend((b"referer", value.encode()) for value in referer_headers)

    class RequestStub:
        method = "POST"
        headers = Headers(raw=pairs)
        cookies = {
            "repolens_session": client.cookies["repolens_session"],
            "repolens_csrf": client.cookies["repolens_csrf"],
        }

    return RequestStub()


def test_production_csrf_requires_origin_or_referer_even_with_valid_session_and_token(client, db_session):
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://test:test@db.example/repolens",
        CHECKPOINT_BACKEND="POSTGRES",
        AUTH_COOKIE_SECURE=True,
        CSRF_COOKIE_DOMAIN=".example.com",
        ARTIFACT_DEPLOYMENT_MODE="single_persistent_local",
        CORS_ORIGINS=["https://app.example.com"],
        TRUSTED_HOSTS=["api.example.com"],
    )
    with pytest.raises(HTTPException) as raised:
        verify_csrf(request=_production_csrf_request(client), db=db_session, settings=settings)
    assert raised.value.detail["error_code"] == "CSRF_ORIGIN_REQUIRED"


def test_production_csrf_accepts_exact_origin_and_rejects_hostile_or_ambiguous_origin(client, db_session):
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://test:test@db.example/repolens",
        CHECKPOINT_BACKEND="POSTGRES",
        AUTH_COOKIE_SECURE=True,
        CSRF_COOKIE_DOMAIN=".example.com",
        ARTIFACT_DEPLOYMENT_MODE="single_persistent_local",
        CORS_ORIGINS=["https://app.example.com"],
        TRUSTED_HOSTS=["api.example.com"],
    )
    verify_csrf(
        request=_production_csrf_request(client, origin_headers=("https://app.example.com",)),
        db=db_session,
        settings=settings,
    )
    verify_csrf(
        request=_production_csrf_request(client, referer_headers=("https://app.example.com/security/settings",)),
        db=db_session,
        settings=settings,
    )
    for values in (
        ("https://example.com.evil.org",),
        ("https://app.example.com@evil.org",),
        ("https://app.example.com", "https://evil.org"),
        ("null",),
    ):
        with pytest.raises(HTTPException) as raised:
            verify_csrf(
                request=_production_csrf_request(client, origin_headers=values),
                db=db_session,
                settings=settings,
            )
        assert raised.value.status_code == 403
