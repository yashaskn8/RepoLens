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
    2. Origin / Referer validation against CORS_ORIGINS (required in production).
    3. Double-submit verification: raw cookie == raw header (constant-time).
    4. Session binding verification: SHA256(raw_header) == session.csrf_token_hash (constant-time).
    """
    # Safe methods do not require CSRF
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    def values_for_header(name: str) -> list[str]:
        getlist = getattr(request.headers, "getlist", None)
        if getlist is not None:
            return list(getlist(name))
        value = request.headers.get(name) or request.headers.get(name.title())
        return [value] if value else []

    origin_values = values_for_header("origin")
    referer_values = values_for_header("referer")
    if len(origin_values) > 1 or len(referer_values) > 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "CSRF_ORIGIN_INVALID", "message": "Multiple origin headers are not accepted"},
        )
    supplied_origins = [(value, True) for value in origin_values]
    supplied_origins.extend((value, False) for value in referer_values)
    if settings.is_production and not supplied_origins:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "CSRF_ORIGIN_REQUIRED", "message": "Origin or Referer is required for mutations"},
        )
    allowed_origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS]
    dev_allowed = set(allowed_origins) | {
        "http://testserver", "http://localhost", "http://127.0.0.1",
        "http://localhost:3000", "http://127.0.0.1:3000",
    }
    for supplied, is_origin in supplied_origins:
        parsed = urlparse(supplied)
        try:
            _ = parsed.port
            valid_authority = bool(parsed.hostname) and parsed.username is None and parsed.password is None
        except ValueError:
            valid_authority = False
        if (
            not parsed.scheme
            or not parsed.netloc
            or parsed.scheme.lower() not in ("http", "https")
            or not valid_authority
            or parsed.fragment
            or (is_origin and (parsed.path not in ("", "/") or parsed.query))
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error_code": "CSRF_ORIGIN_INVALID", "message": "Invalid origin or referer header"},
            )
        origin_base = f"{parsed.scheme.lower()}://{parsed.netloc}"
        permitted = allowed_origins if settings.is_production else dev_allowed
        if origin_base not in permitted and not (not settings.is_production and "*" in allowed_origins):
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

    # 2. Session binding verification. A double-submit pair is not authority by
    # itself: it must belong to a currently valid, non-revoked session.
    raw_session_token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if not raw_session_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "CSRF_SESSION_INVALID", "message": "A valid authenticated session is required"},
        )
    try:
        _, session = AuthService(db, settings).validate_session(raw_session_token)
    except AuthError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "CSRF_SESSION_INVALID", "message": "A valid authenticated session is required"},
        ) from None
    candidate_hash = _hash_token(raw_csrf_header)
    if not hmac.compare_digest(candidate_hash, session.csrf_token_hash):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "CSRF_INVALID", "message": "CSRF token does not match active session"},
        )
