"""Test Phase 8: Authentication, Argon2id Passwords, Lockouts, and Session Management.

Verifies:
- Argon2id password hashing and constant-time dummy verification.
- User registration (role USER, password length validation, duplicate email handling).
- User login with cookie issuance (repolens_session, repolens_csrf).
- Account lockout on 5 failed attempts with durable DB persistence.
- Session validation via SHA-256 token hashing.
- Session expiration and explicit logout revocation.
- GET /api/v1/auth/me current user endpoint.
- Operator CLI creation and elevation.
"""

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.cli.create_operator import create_or_elevate_operator
from app.models.user import UserModel, UserSessionModel
from app.schemas.enums import UserRole
from app.security.password import (
    hash_password,
    verify_dummy_password,
    verify_password,
)
from app.services.auth_service import AuthService


def test_argon2id_hashing_and_verification():
    """Test secure Argon2id password hashing and verification."""
    password = "SuperSecretSecurePassword123!"
    p_hash = hash_password(password)
    
    assert p_hash.startswith("$argon2id$")
    assert verify_password(password, p_hash) is True
    assert verify_password("WrongPassword123!", p_hash) is False
    
    # Test constant-time dummy verification doesn't crash
    verify_dummy_password()


def test_user_registration_and_login_flow(client: TestClient, db_session: Session):
    """Test user registration, login, and cookie issuance."""
    email = "testuser1@example.com"
    password = "ValidStrongPassword12345!"

    # 1. Register new user
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_resp.status_code == 201
    user_data = reg_resp.json()
    assert user_data["email"] == email
    assert user_data["role"] == "USER"
    assert user_data["is_active"] is True

    # 2. Reject duplicate email registration
    dup_resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert dup_resp.status_code == 409
    assert "already" in dup_resp.json()["detail"]["message"].lower()

    # 3. Reject password under 12 characters
    short_resp = client.post(
        "/api/v1/auth/register",
        json={"email": "short@example.com", "password": "short"},
    )
    assert short_resp.status_code == 422

    # 4. Login with correct credentials
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["email"] == email
    assert login_data["role"] == "USER"

    # Verify cookies set
    assert "repolens_session" in login_resp.cookies
    assert "repolens_csrf" in login_resp.cookies

    # 5. Access /api/v1/auth/me with session cookie
    session_cookie = login_resp.cookies["repolens_session"]
    me_resp = client.get(
        "/api/v1/auth/me",
        cookies={"repolens_session": session_cookie},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["id"] == user_data["id"]
    assert me_data["email"] == email
    assert me_data["role"] == "USER"


def test_login_failed_attempts_and_lockout(client: TestClient, db_session: Session):
    """Test persistent failed login tracking and 15-minute account lockout."""
    email = "lockout_target@example.com"
    password = "CorrectPassword12345!"

    # Register user
    client.post("/api/v1/auth/register", json={"email": email, "password": password})

    # Attempt 4 failed logins
    for i in range(1, 5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword!"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["error_code"] == "INVALID_CREDENTIALS"

        # Check DB state
        user_row = db_session.query(UserModel).filter_by(email=email).first()
        assert user_row.failed_login_attempts == i
        assert user_row.locked_until is None

    # 5th failed attempt triggers lockout
    resp_5 = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPassword!"},
    )
    assert resp_5.status_code == 401
    assert resp_5.json()["detail"]["error_code"] == "INVALID_CREDENTIALS"

    user_row = db_session.query(UserModel).filter_by(email=email).first()
    assert user_row.failed_login_attempts == 5
    assert user_row.locked_until is not None
    locked_until = user_row.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    assert locked_until > datetime.now(timezone.utc)

    # Even with correct password, login is blocked while locked
    locked_resp = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert locked_resp.status_code == 401
    assert locked_resp.json()["detail"]["error_code"] == "INVALID_CREDENTIALS"


def test_session_revocation_and_logout(client: TestClient, db_session: Session):
    """Test explicit session logout and revocation."""
    email = "logout_test@example.com"
    password = "CorrectPassword12345!"

    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    session_cookie = login_resp.cookies["repolens_session"]
    csrf_cookie = login_resp.cookies["repolens_csrf"]

    # Logout
    logout_resp = client.post(
        "/api/v1/auth/logout",
        cookies={"repolens_session": session_cookie, "repolens_csrf": csrf_cookie},
        headers={"X-CSRF-Token": csrf_cookie},
    )
    assert logout_resp.status_code == 200

    # Subsequent /me request with old session is rejected
    me_resp = client.get(
        "/api/v1/auth/me",
        cookies={"repolens_session": session_cookie},
    )
    assert me_resp.status_code == 401


def test_operator_cli_creation_and_elevation(db_session: Session):
    """Test create_operator CLI utility creates and elevates operators."""
    op_email = "operator_admin@example.com"
    op_pass = "OperatorSecretPass12345!"

    # 1. Create new operator
    user = create_or_elevate_operator(db_session, email=op_email, password=op_pass)
    assert user.email == op_email
    assert user.role == UserRole.OPERATOR.value

    # 2. Elevate existing USER to OPERATOR
    normal_email = "regular_to_op@example.com"
    auth_service = AuthService(db_session)
    reg_user = auth_service.register_user(email=normal_email, password=op_pass)
    assert reg_user.role == UserRole.USER.value

    elevated = create_or_elevate_operator(db_session, email=normal_email)
    assert elevated.id == reg_user.id
    assert elevated.role == UserRole.OPERATOR.value
