"""Authentication endpoints for registration, login, session inspection, and logout."""

import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db, verify_csrf
from app.core.config import Settings, get_settings
from app.models.user import UserModel
from app.schemas.auth import CurrentUser, UserLoginRequest, UserRegisterRequest, UserResponse
from app.services.auth_service import (
    AccountDisabledError,
    AuthError,
    AuthService,
    DuplicateEmailError,
    InvalidCredentialsError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserResponse:
    """Register a new user account with USER role.

    Always creates accounts with USER role. Request body cannot elevate privileges.
    """
    auth_service = AuthService(db, settings)
    try:
        user = auth_service.register_user(email=payload.email, password=payload.password)
    except DuplicateEmailError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_code": "DUPLICATE_EMAIL", "message": "An account with this email already exists"},
        )
    except Exception as exc:
        logger.error(f"Registration failed: {str(exc)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "REGISTRATION_FAILED", "message": "Failed to create account"},
        )

    return UserResponse.model_validate(user)


@router.post("/login", response_model=UserResponse)
def login(
    payload: UserLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserResponse:
    """Authenticate with email and password, establishing an opaque server-side session.

    Sets HttpOnly session cookie and client-accessible CSRF cookie only after DB commit succeeds.
    """
    auth_service = AuthService(db, settings)
    try:
        user = auth_service.authenticate_user(email=payload.email, password=payload.password)
        raw_session_token, raw_csrf_token, session = auth_service.create_session(user)
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "INVALID_CREDENTIALS", "message": "Invalid email or password"},
        )
    except AccountDisabledError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "ACCOUNT_DISABLED", "message": "Account is disabled"},
        )
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": exc.error_code, "message": exc.message},
        )

    # Set secure HttpOnly session cookie
    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=raw_session_token,
        max_age=settings.AUTH_SESSION_TTL_SECONDS,
        httponly=True,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite=settings.AUTH_COOKIE_SAMESITE,
        domain=settings.AUTH_COOKIE_DOMAIN,
        path="/",
    )

    # Set client-accessible CSRF token cookie
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=raw_csrf_token,
        max_age=settings.AUTH_SESSION_TTL_SECONDS,
        httponly=False,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite=settings.AUTH_COOKIE_SAMESITE,
        domain=settings.AUTH_COOKIE_DOMAIN,
        path="/",
    )

    return UserResponse.model_validate(user)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    current_user: CurrentUser = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Revoke the current user session and clear authentication cookies."""
    raw_session_token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if raw_session_token:
        auth_service = AuthService(db, settings)
        auth_service.revoke_session(raw_session_token)

    response.delete_cookie(
        key=settings.AUTH_COOKIE_NAME,
        domain=settings.AUTH_COOKIE_DOMAIN,
        path="/",
    )
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        domain=settings.AUTH_COOKIE_DOMAIN,
        path="/",
    )

    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
def get_me(
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Return the profile of the currently authenticated user."""
    user = db.query(UserModel).filter(UserModel.id == current_user.id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "USER_NOT_FOUND", "message": "User record not found"},
        )
    return UserResponse.model_validate(user)
