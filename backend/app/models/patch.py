"""SQLAlchemy ORM model for remediation patches and human approvals."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.schemas.enums import PatchStatus


def _utc_now():
    return datetime.now(timezone.utc)


class PatchModel(Base):
    """SQLAlchemy model for remediation patches and human review workflows."""

    __tablename__ = "patches"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id = Column(String(36), nullable=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), nullable=False, default=PatchStatus.DRAFT.value, index=True)
    unified_diff = Column(Text, nullable=False)
    files_modified = Column(JSON, nullable=False)
    explanation = Column(Text, nullable=False)
    expected_behavior_change = Column(Text, nullable=False)
    generated_tests_or_test_plan = Column(JSON, nullable=True)
    verification_report = Column(JSON, nullable=True)
    critic_report = Column(JSON, nullable=True)
    user_feedback = Column(Text, nullable=True)
    approved_by = Column(String(128), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    rejected_reason = Column(Text, nullable=True)
    model_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False)

    # Relationships
    finding = relationship("FindingModel")
    scan = relationship("ScanModel")
