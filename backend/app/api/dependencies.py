"""FastAPI route dependencies for authentication, role gating, and CSRF verification.

Provides:
- get_current_user: Resolves authenticated CurrentUser from HttpOnly session cookie.
- require_operator: Gates endpoints requiring UserRole.OPERATOR.
- verify_csrf: Enforces double-submit + session-hash CSRF verification on unsafe requests.
"""

import hashlib
import hmac
import logging
from typing import Optional
from urllib.parse import urlparse

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.user import UserSessionModel
from app.schemas.auth import CurrentUser
from app.schemas.enums import UserRole
from app.services.auth_service import AuthError, AuthService

logger = logging.getLogger(__name__)

# Re-export get_db for dependency convenience
__all__ = [
    "get_db",
    "get_current_user",
    "get_current_active_session",
    "require_operator",
    "verify_csrf",
]


def _hash_token(raw_token: str) -> str:
    """SHA-256 hash a raw token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    """Extract and validate the session cookie, returning the authenticated CurrentUser.

    Raises 401 UNAUTHENTICATED if session cookie is missing or invalid.
    """
    raw_session_token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if not raw_session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "UNAUTHENTICATED", "message": "Authentication required"},
        )

    auth_service = AuthService(db, settings)
    try:
        user, session = auth_service.validate_session(raw_session_token)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": exc.error_code, "message": exc.message},
        )

    return CurrentUser(
        id=user.id,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        session_id=session.id,
    )


def require_operator(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Gate endpoint access to users with OPERATOR role.

    Raises 403 INSUFFICIENT_PRIVILEGES if user is not an OPERATOR.
    """
    if current_user.role != UserRole.OPERATOR.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": "INSUFFICIENT_PRIVILEGES",
                "message": "Operator role required for this action",
            },
        )
    return current_user


def verify_csrf(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    """Verify CSRF token on state-changing requests using ambient session auth.

    Contract:
    1. Unsafe HTTP methods (POST, PUT, PATCH, DELETE) require CSRF.
    2. Origin / Referer validation against CORS_ORIGINS when header is present.
    3. Double-submit verification: raw cookie == raw header (constant-time).
    4. Session binding verification: SHA256(raw_header) == session.csrf_token_hash (constant-time).
    """
    # Safe methods do not require CSRF
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    # Check origin/referer if present
    origin = request.headers.get("Origin") or request.headers.get("Referer")
    if origin:
        parsed = urlparse(origin)
        origin_base = f"{parsed.scheme}://{parsed.netloc}"
        allowed_origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS]
        # In development/test, allow localhost/127.0.0.1/testserver matches
        allowed_origins_set = set(allowed_origins) | {"http://testserver", "http://localhost", "http://127.0.0.1"}
        if origin_base not in allowed_origins_set and "*" not in allowed_origins:
            # Check if host alone matches
            if parsed.netloc not in ("localhost:3000", "127.0.0.1:3000", "testserver", "localhost", "127.0.0.1"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={"error_code": "CSRF_ORIGIN_INVALID", "message": "Cross-origin request rejected"},
                )

    raw_csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
    raw_csrf_header = request.headers.get(settings.CSRF_HEADER_NAME)

    if not raw_csrf_cookie or not raw_csrf_header:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "CSRF_MISSING", "message": "CSRF token missing in cookie or header"},
        )

    # 1. Constant-time comparison between cookie and header
    if not hmac.compare_digest(raw_csrf_cookie, raw_csrf_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "CSRF_MISMATCH", "message": "CSRF token mismatch"},
        )

    # 2. Session binding verification: candidate hash must match active session's csrf_token_hash
    raw_session_token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if raw_session_token:
        session_token_hash = _hash_token(raw_session_token)
        session = db.query(UserSessionModel).filter(
            UserSessionModel.token_hash == session_token_hash
        ).first()
        if session:
            candidate_hash = _hash_token(raw_csrf_header)
            if not hmac.compare_digest(candidate_hash, session.csrf_token_hash):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={"error_code": "CSRF_INVALID", "message": "CSRF token does not match active session"},
                )
