"""SQLAlchemy ORM models for Findings and Evidences."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from app.models.base import Base
from app.schemas.enums import FindingStatus, Severity


def _utc_now():
    return datetime.now(timezone.utc)


class FindingModel(Base):
    """SQLAlchemy model for detected findings."""

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False, default=Severity.INFO.value, index=True)
    status = Column(String(32), nullable=False, default=FindingStatus.OPEN.value, index=True)
    rule_id = Column(String(128), nullable=True, index=True)
    category = Column(String(128), nullable=True, index=True)
    mitigation_guidance = Column(Text, nullable=True)
    verification_verdict = Column(String(32), nullable=True)
    verification_reason = Column(Text, nullable=True)
    source_tool = Column(String(64), nullable=True, index=True)
    detector_id = Column(String(512), nullable=True, index=True)
    detector_kind = Column(String(64), nullable=True, index=True)
    model_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False)

    # Relationships
    scan = relationship("ScanModel", back_populates="findings")
    evidences = relationship("EvidenceModel", back_populates="finding", cascade="all, delete-orphan")


class EvidenceModel(Base):
    """SQLAlchemy model for code evidence snippets."""

    __tablename__ = "evidences"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    file_path = Column(String(512), nullable=False)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    context_notes = Column(Text, nullable=True)

    # Relationships
    finding = relationship("FindingModel", back_populates="evidences")
