"""SQLAlchemy ORM models for Change Intelligence and PR Impact Analysis."""

from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship

from app.models.base import Base


def _utc_now():
    return datetime.now(timezone.utc)


class ChangeAnalysisModel(Base):
    """SQLAlchemy model representing a semantic change analysis between two exact repository revisions."""

    __tablename__ = "change_analyses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()), index=True)
    repository_url = Column(String(512), nullable=False)
    repository_owner = Column(String(256), nullable=False)
    repository_name = Column(String(256), nullable=False)

    base_ref = Column(String(128), nullable=True)
    base_commit_sha = Column(String(40), nullable=False, index=True)

    head_ref = Column(String(128), nullable=True)
    head_commit_sha = Column(String(40), nullable=False, index=True)

    status = Column(String(32), nullable=False, default="PENDING", index=True)

    changed_files_count = Column(Integer, nullable=False, default=0)
    changed_symbols_count = Column(Integer, nullable=False, default=0)
    impacted_symbols_count = Column(Integer, nullable=False, default=0)

    risk_level = Column(String(32), nullable=True)
    failure_code = Column(String(64), nullable=True)
    failure_message = Column(String(512), nullable=True)

    model_metadata = Column(JSON, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    impacts = relationship(
        "ChangeImpactModel",
        back_populates="analysis",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    events = relationship(
        "WorkflowEventModel",
        back_populates="change_analysis",
    )


class ChangeImpactModel(Base):
    """SQLAlchemy model representing a discrete, evidence-backed semantic change impact."""

    __tablename__ = "change_impacts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()), index=True)
    analysis_id = Column(
        String(36),
        ForeignKey("change_analyses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    impact_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="MEDIUM")

    title = Column(String(256), nullable=False)
    description = Column(String(2048), nullable=False)

    source_file = Column(String(512), nullable=True)
    source_symbol = Column(String(256), nullable=True)

    affected_file = Column(String(512), nullable=True)
    affected_symbol = Column(String(256), nullable=True)

    evidence_payload = Column(JSON, nullable=False, default=dict)

    confidence = Column(Float, nullable=False, default=1.0)
    verification_status = Column(String(32), nullable=False, default="FACT")

    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False)

    # Relationship
    analysis = relationship("ChangeAnalysisModel", back_populates="impacts")
