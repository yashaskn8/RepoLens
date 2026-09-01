"""Authentication service: registration, login, session management, and logout.

All authentication state changes (failed login counters, lockouts, session creation)
are durably committed before raising errors or setting cookies.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import uuid4

from sqlalchemy.orm import Session
from sqlalchemy import inspect

from app.core.config import Settings, get_settings
from app.models.user import UserModel, UserSessionModel
from app.schemas.enums import UserRole
from app.security.password import hash_password, verify_password, verify_dummy_password
from app.governance.events import AuditLedger

logger = logging.getLogger(__name__)


def _append_auth_audit(db: Session, **kwargs) -> None:
    """Append when the platform migration is present; support rolling upgrades."""
    if inspect(db.get_bind()).has_table("audit_chain_heads"):
        AuditLedger.append(db, **kwargs)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_dt(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime is timezone-aware (UTC). SQLite may return naive datetimes."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _hash_token(raw_token: str) -> str:
    """SHA-256 hash a raw token for DB persistence."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class AuthError(Exception):
    """Base authentication error."""

    def __init__(self, message: str, error_code: str = "AUTH_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class InvalidCredentialsError(AuthError):
    def __init__(self):
        super().__init__("Invalid email or password", "INVALID_CREDENTIALS")


class AccountDisabledError(AuthError):
    def __init__(self):
        super().__init__("Account is disabled", "ACCOUNT_DISABLED")


class AccountLockedError(AuthError):
    def __init__(self):
        super().__init__("Invalid email or password", "INVALID_CREDENTIALS")


class DuplicateEmailError(AuthError):
    def __init__(self):
        super().__init__("Email already registered", "DUPLICATE_EMAIL")


class AuthService:
    """Canonical authentication service with durable transaction semantics."""

    def __init__(self, db: Session, settings: Optional[Settings] = None):
        self.db = db
        self.settings = settings or get_settings()

    def register_user(self, email: str, password: str, *, request_id: str | None = None) -> UserModel:
        """Register a new user with USER role.

        Role is always USER — request body cannot specify role.
        Email is normalized to lowercase.
        """
        normalized_email = email.strip().lower()

        # Check for duplicate
        existing = self.db.query(UserModel).filter(UserModel.email == normalized_email).first()
        if existing:
            raise DuplicateEmailError()

        user = UserModel(
            id=str(uuid4()),
            email=normalized_email,
            password_hash=hash_password(password),
            role=UserRole.USER.value,
            is_active=True,
            failed_login_attempts=0,
            created_at=_utc_now(),
            updated_at=_utc_now(),
        )
        self.db.add(user)
        _append_auth_audit(
            self.db,
            tenant_id=user.id,
            actor_id=user.id,
            request_id=request_id,
            event_type="AUTH_ACCOUNT_REGISTERED",
            resource_type="USER",
            resource_id=user.id,
        )
        self.db.commit()
        self.db.refresh(user)
        return user

    def authenticate_user(self, email: str, password: str, *, request_id: str | None = None) -> UserModel:
        """Authenticate user with durable failure tracking.

        Failed login: increment counter / set lock -> COMMIT -> raise generic error.
        Successful login: clear failures / update last_login -> part of session commit.
        """
        normalized_email = email.strip().lower()
        user = self.db.query(UserModel).filter(UserModel.email == normalized_email).first()

        if user is None:
            # Constant-time dummy verification to prevent email enumeration
            verify_dummy_password()
            raise InvalidCredentialsError()

        # Check if account is active
        if not user.is_active:
            verify_dummy_password()
            _append_auth_audit(
                self.db,
                tenant_id=user.id,
                request_id=request_id,
                event_type="AUTH_LOGIN_REJECTED",
                resource_type="USER",
                resource_id=user.id,
                payload={"reason_code": "ACCOUNT_DISABLED"},
            )
            self.db.commit()
            raise AccountDisabledError()

        # Check lockout
        max_attempts = self.settings.AUTH_MAX_FAILED_LOGIN_ATTEMPTS
        lockout_seconds = self.settings.AUTH_LOCKOUT_SECONDS
        now = _utc_now()

        if user.locked_until and _normalize_dt(user.locked_until) > now:
            # Still locked — perform dummy verification for timing consistency
            verify_dummy_password()
            _append_auth_audit(
                self.db,
                tenant_id=user.id,
                request_id=request_id,
                event_type="AUTH_LOGIN_REJECTED",
                resource_type="USER",
                resource_id=user.id,
                payload={"reason_code": "ACCOUNT_LOCKED"},
            )
            self.db.commit()
            raise InvalidCredentialsError()

        # Verify password
        if not verify_password(user.password_hash, password):
            # FAILED: increment counter, possibly lock, COMMIT, then raise
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= max_attempts:
                user.locked_until = now + timedelta(seconds=lockout_seconds)
            user.updated_at = now
            _append_auth_audit(
                self.db,
                tenant_id=user.id,
                request_id=request_id,
                event_type="AUTH_LOGIN_REJECTED",
                resource_type="USER",
                resource_id=user.id,
                payload={
                    "reason_code": "INVALID_CREDENTIALS",
                    "account_locked": user.locked_until is not None,
                },
            )
            self.db.commit()
            raise InvalidCredentialsError()

        # SUCCESS: clear failures, update last_login (committed with session creation)
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now
        user.updated_at = now
        # NOTE: Do NOT commit here — caller commits atomically with session creation
        return user

    def create_session(
        self,
        user: UserModel,
        *,
        request_id: str | None = None,
    ) -> Tuple[str, str, UserSessionModel]:
        """Create a new server-side session with cryptographic tokens.

        Returns (raw_session_token, raw_csrf_token, session_model).
        Commits atomically: user state updates + new session.
        Caller must set cookies ONLY after this method returns successfully.
        """
        raw_session_token = secrets.token_urlsafe(32)
        raw_csrf_token = secrets.token_urlsafe(32)

        ttl = self.settings.AUTH_SESSION_TTL_SECONDS
        now = _utc_now()

        session = UserSessionModel(
            id=str(uuid4()),
            user_id=user.id,
            token_hash=_hash_token(raw_session_token),
            csrf_token_hash=_hash_token(raw_csrf_token),
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            last_seen_at=now,
        )
        self.db.add(session)
        _append_auth_audit(
            self.db,
            tenant_id=user.id,
            actor_id=user.id,
            request_id=request_id,
            event_type="AUTH_SESSION_CREATED",
            resource_type="USER_SESSION",
            resource_id=session.id,
        )
        # Atomic commit: user failure-clear + session creation
        self.db.commit()
        self.db.refresh(session)

        return raw_session_token, raw_csrf_token, session

    def validate_session(self, raw_session_token: str) -> Tuple[UserModel, UserSessionModel]:
        """Validate a session token and return (user, session).

        Raises AuthError if session is invalid, expired, or revoked.
        """
        token_hash = _hash_token(raw_session_token)
        session = self.db.query(UserSessionModel).filter(
            UserSessionModel.token_hash == token_hash
        ).first()

        if session is None:
            raise AuthError("Session not found", "SESSION_EXPIRED")

        now = _utc_now()

        if _normalize_dt(session.revoked_at) is not None:
            raise AuthError("Session revoked", "SESSION_EXPIRED")

        if _normalize_dt(session.expires_at) <= now:
            raise AuthError("Session expired", "SESSION_EXPIRED")

        user = self.db.query(UserModel).filter(UserModel.id == session.user_id).first()
        if user is None or not user.is_active:
            raise AuthError("Account not found or disabled", "ACCOUNT_DISABLED")

        # Bounded last_seen_at update (5-minute interval)
        last_seen = _normalize_dt(session.last_seen_at)
        if last_seen is None or (now - last_seen).total_seconds() > 300:
            session.last_seen_at = now
            self.db.commit()

        return user, session

    def revoke_session(self, raw_session_token: str, *, request_id: str | None = None) -> None:
        """Revoke a session (logout). Commits before returning."""
        token_hash = _hash_token(raw_session_token)
        session = self.db.query(UserSessionModel).filter(
            UserSessionModel.token_hash == token_hash
        ).first()

        if session and session.revoked_at is None:
            session.revoked_at = _utc_now()
            _append_auth_audit(
                self.db,
                tenant_id=session.user_id,
                actor_id=session.user_id,
                request_id=request_id,
                event_type="AUTH_SESSION_REVOKED",
                resource_type="USER_SESSION",
                resource_id=session.id,
            )
            self.db.commit()
