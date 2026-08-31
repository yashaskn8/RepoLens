"""SQLAlchemy ORM model for durable workflow events and audit telemetry."""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship
from app.models.base import Base


def _utc_now():
    return datetime.now(timezone.utc)


class WorkflowEventModel(Base):
    """SQLAlchemy model for durable workflow events and audit trail."""

    __tablename__ = "workflow_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(64), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    change_analysis_id = Column(String(36), ForeignKey("change_analyses.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    patch_id = Column(String(36), ForeignKey("patches.id", ondelete="SET NULL"), nullable=True, index=True)
    delivery_id = Column(String(36), ForeignKey("deliveries.id", ondelete="SET NULL"), nullable=True, index=True)
    pr_review_publication_id = Column(String(36), ForeignKey("pr_review_publications.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    thread_id = Column(String(128), nullable=True)
    commit_sha = Column(String(64), nullable=True)
    stage = Column(String(64), nullable=True)
    tool_name = Column(String(64), nullable=True)
    provider = Column(String(64), nullable=True)
    model_name = Column(String(128), nullable=True)
    message = Column(String(1024), nullable=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False, index=True)

    # Relationships
    scan = relationship("ScanModel", back_populates="events")
    change_analysis = relationship("ChangeAnalysisModel", back_populates="events")
    finding = relationship("FindingModel")
    patch = relationship("PatchModel")
    delivery = relationship("DeliveryModel", back_populates="events")
    pr_review_publication = relationship("PullRequestReviewPublicationModel", back_populates="events")
