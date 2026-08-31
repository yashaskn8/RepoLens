"""SQLAlchemy ORM model for Human-Authorized Pull Request Review Publication."""

from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.models.base import Base


def _utc_now():
    return datetime.now(timezone.utc)


class PullRequestReviewPublicationModel(Base):
    """SQLAlchemy model representing a human-authorized GitHub pull request review publication."""

    __tablename__ = "pr_review_publications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()), index=True)
    analysis_id = Column(
        String(36),
        ForeignKey("change_analyses.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
        index=True,
    )

    repository_owner = Column(String(256), nullable=False)
    repository_name = Column(String(256), nullable=False)
    pr_number = Column(Integer, nullable=False)

    base_commit_sha = Column(String(40), nullable=False)
    head_commit_sha = Column(String(40), nullable=False)

    status = Column(String(32), nullable=False, default="PENDING", index=True)

    preview_body = Column(Text, nullable=True)
    preview_digest = Column(String(64), nullable=True, index=True)
    inline_comments_payload = Column(JSON, nullable=True)

    is_truncated = Column(Boolean, nullable=False, default=False)
    truncation_reason = Column(String(256), nullable=True)

    approved_at = Column(DateTime(timezone=True), nullable=True)

    github_review_id = Column(BigInteger, nullable=True)
    github_review_url = Column(String(1024), nullable=True)

    reconciliation_occurred = Column(Boolean, nullable=False, default=False)

    failure_code = Column(String(64), nullable=True)
    failure_message = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False)
    published_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    analysis = relationship("ChangeAnalysisModel", back_populates="review_publication")
    events = relationship("WorkflowEventModel", back_populates="pr_review_publication")
