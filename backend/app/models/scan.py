"""SQLAlchemy ORM model for Scans."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import relationship
from app.models.base import Base
from app.schemas.enums import ScanStatus


def _utc_now():
    return datetime.now(timezone.utc)


class ScanModel(Base):
    """SQLAlchemy model for repository scan executions."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    repository_url = Column(String(512), nullable=False, index=True)
    branch = Column(String(128), nullable=True, default=None)
    commit_hash = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default=ScanStatus.PENDING.value, index=True)
    model_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("WorkflowEventModel", back_populates="scan", cascade="all, delete-orphan")
