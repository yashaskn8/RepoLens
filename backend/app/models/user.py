"""SQLAlchemy ORM models for User, UserSession, and UsageCounter entities."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.schemas.enums import UserRole


def _utc_now():
    return datetime.now(timezone.utc)


class UserModel(Base):
    """SQLAlchemy model for registered RepoLens users."""

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default=UserRole.USER.value, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False)

    # Relationships
    sessions = relationship("UserSessionModel", back_populates="user", cascade="all, delete-orphan")
    usage_counters = relationship("UsageCounterModel", back_populates="user", cascade="all, delete-orphan")


class UserSessionModel(Base):
    """SQLAlchemy model for opaque server-side user sessions."""

    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    csrf_token_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    user = relationship("UserModel", back_populates="sessions")


class UsageCounterModel(Base):
    """SQLAlchemy model for daily durable usage quotas per user."""

    __tablename__ = "usage_counters"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    bucket_date = Column(Date, nullable=False)
    operation = Column(String(64), nullable=False)
    count = Column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("user_id", "bucket_date", "operation", name="uq_usage_user_date_op"),
    )

    # Relationships
    user = relationship("UserModel", back_populates="usage_counters")
