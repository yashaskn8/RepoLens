"""Durable immutable report metadata and database-backed execution lease."""

from datetime import datetime, timezone
import uuid

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint

from app.models.base import Base
from app.reporting.schemas import REPORT_TYPE_SCAN, ReportStatus


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ReportModel(Base):
    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint(
            "owner_user_id", "scan_id", "input_digest", "report_schema_version", "renderer_version",
            name="uq_report_canonical_input",
        ),
        CheckConstraint(
            "status IN ('REQUESTED','ASSEMBLING','RENDERING','READY','FAILED')",
            name="ck_reports_status",
        ),
        CheckConstraint(
            "status != 'READY' OR (pdf_digest IS NOT NULL AND payload_locator IS NOT NULL AND generated_at IS NOT NULL)",
            name="ck_reports_ready_artifact",
        ),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(32), nullable=False, default=REPORT_TYPE_SCAN)
    status = Column(String(32), nullable=False, default=ReportStatus.REQUESTED.value, index=True)

    input_digest = Column(String(64), nullable=False, index=True)
    evidence_digest = Column(String(64), nullable=False)
    coverage_digest = Column(String(64), nullable=False)
    document_digest = Column(String(64), nullable=False)
    document_locator = Column(String(1024), nullable=False)
    pdf_digest = Column(String(64), nullable=True)
    payload_locator = Column(String(1024), nullable=True)
    payload_size_bytes = Column(Integer, nullable=True)
    page_count = Column(Integer, nullable=True)

    repository_url = Column(String(512), nullable=False)
    branch = Column(String(128), nullable=True)
    commit_sha = Column(String(64), nullable=True)
    report_schema_version = Column(String(32), nullable=False)
    renderer_version = Column(String(128), nullable=False)
    analysis_policy_version = Column(String(128), nullable=False)
    application_version = Column(String(32), nullable=False)
    coverage_artifact_id = Column(String(128), nullable=True)
    finding_ids = Column(JSON, nullable=False, default=list)
    artifact_lineage = Column(JSON, nullable=False, default=list)

    attempt_count = Column(Integer, nullable=False, default=0)
    lease_owner = Column(String(128), nullable=True, index=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    retryable = Column(Boolean, nullable=False, default=True)
    failure_code = Column(String(64), nullable=True)
    failure_message = Column(Text, nullable=True)

    requested_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    started_at = Column(DateTime(timezone=True), nullable=True)
    generated_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

