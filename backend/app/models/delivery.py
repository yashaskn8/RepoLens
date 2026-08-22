"""SQLAlchemy ORM model for safe GitHub patch delivery and pull request tracking."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.schemas.enums import DeliveryStatus


def _utc_now():
    return datetime.now(timezone.utc)


class DeliveryModel(Base):
    """SQLAlchemy model for tracking external repository delivery and pull requests."""

    __tablename__ = "deliveries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="RESTRICT"), nullable=False, index=True)
    patch_id = Column(String(36), ForeignKey("patches.id", ondelete="RESTRICT"), nullable=False, index=True)
    provider = Column(String(32), default="github", nullable=False)
    repository_url = Column(String(512), nullable=False)
    repository_owner = Column(String(256), nullable=False)
    repository_name = Column(String(256), nullable=False)
    base_branch = Column(String(128), nullable=False)
    scanned_base_sha = Column(String(64), nullable=False)
    observed_base_sha = Column(String(64), nullable=True)
    head_branch = Column(String(256), nullable=True)
    head_sha = Column(String(64), nullable=True)
    pr_number = Column(Integer, nullable=True)
    pr_url = Column(String(512), nullable=True)
    status = Column(String(32), default=DeliveryStatus.PENDING.value, nullable=False, index=True)
    failure_code = Column(String(64), nullable=True)
    failure_message = Column(String(512), nullable=True)
    idempotency_key = Column(String(128), unique=True, nullable=False, index=True)
    requested_by = Column(String(128), default="user", nullable=False)
    attempt_count = Column(Integer, default=1, nullable=False)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_deliveries_idempotency_key"),
    )

    # Relationships
    scan = relationship("ScanModel")
    finding = relationship("FindingModel")
    patch = relationship("PatchModel")
    events = relationship("WorkflowEventModel", back_populates="delivery")
