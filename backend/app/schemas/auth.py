"""Pydantic schemas for authentication request/response contracts."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, EmailStr, field_validator

from app.schemas.enums import UserRole


class UserRegisterRequest(BaseModel):
    """Registration request — always creates USER role."""

    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_length(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if len(v) > 128:
            raise ValueError("Password must be at most 128 characters")
        return v


class UserLoginRequest(BaseModel):
    """Login request."""

    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Safe user profile response — never includes password hash or tokens."""

    id: str
    email: str
    role: str
    is_active: bool
    created_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class CurrentUser(BaseModel):
    """Authenticated user context resolved from session cookie."""

    id: str
    email: str
    role: str
    is_active: bool
    session_id: str


def get_user_id(current_user: Any) -> Optional[str]:
    """Extract authenticated user ID if a valid CurrentUser or UserModel is present, or None."""
    if isinstance(current_user, CurrentUser):
        return current_user.id
    if current_user is not None and getattr(current_user, "__class__", None) is not None:
        if current_user.__class__.__name__ == "UserModel" and hasattr(current_user, "id") and isinstance(current_user.id, str):
            return current_user.id
    return None
