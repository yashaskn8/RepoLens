"""Append-oriented persistence for canonical artifacts and provenance.

Artifact rows and lineage edges are immutable metadata.  Payload deletion is
represented by durable tombstones and append-only deletion attempts; artifact
rows remain available so historical provenance never becomes a dangling ID.
"""

from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)

from app.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


_ARTIFACT_TYPES = (
    "REPOSITORY_REVISION",
    "ANALYZER_RUN",
    "SCANNER",
    "SYMBOL_INDEX",
    "CONTRACT",
    "COVERAGE",
    "EVIDENCE",
    "CLAIM",
    "FINDING",
    "AI_EXECUTION",
    "REPORT_DOCUMENT",
    "PDF_REPORT",
)
_LINEAGE_RELATIONS = ("DERIVED_FROM", "PRODUCED_BY", "INVALIDATES", "SUPERSEDES")
_SENSITIVITY_CLASSES = ("INTERNAL", "SOURCE_DERIVED", "SECURITY_SENSITIVE", "RESTRICTED")
_RETENTION_CLASSES = (
    "EPHEMERAL_REPOSITORY_SNAPSHOT",
    "SOURCE_BEARING_ARTIFACT",
    "EMBEDDING",
    "ANALYSIS_ARTIFACT",
    "PDF_REPORT",
    "WORKFLOW_EVENT",
    "AUDIT_RECORD",
    "GITHUB_PUBLICATION_RECORD",
)


def _sql_values(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


class ArtifactModel(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "identity_digest", name="uq_artifact_tenant_identity"),
        UniqueConstraint("tenant_id", "payload_locator", name="uq_artifact_tenant_locator"),
        CheckConstraint(f"artifact_type IN ({_sql_values(_ARTIFACT_TYPES)})", name="ck_artifact_type"),
        CheckConstraint(
            f"sensitivity IN ({_sql_values(_SENSITIVITY_CLASSES)})",
            name="ck_artifact_sensitivity",
        ),
        CheckConstraint(
            f"retention_class IN ({_sql_values(_RETENTION_CLASSES)})",
            name="ck_artifact_retention_class",
        ),
        CheckConstraint("length(content_digest) = 64", name="ck_artifact_content_digest_length"),
        CheckConstraint("length(identity_digest) = 64", name="ck_artifact_identity_digest_length"),
        CheckConstraint("payload_size_bytes >= 0", name="ck_artifact_payload_size"),
        Index("ix_artifact_revision_type", "tenant_id", "repository_id", "revision_id", "artifact_type"),
    )

    id = Column(String(128), primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    repository_id = Column(String(128), nullable=True, index=True)
    revision_id = Column(String(128), nullable=True, index=True)
    artifact_type = Column(String(64), nullable=False, index=True)
    schema_version = Column(String(64), nullable=False)
    identity_digest = Column(String(64), nullable=False)
    content_digest = Column(String(64), nullable=False, index=True)
    payload_locator = Column(String(1024), nullable=False)
    payload_size_bytes = Column(Integer, nullable=False)
    media_type = Column(String(128), nullable=False)
    producer = Column(String(128), nullable=False, index=True)
    producer_version = Column(String(128), nullable=False)
    producer_config_digest = Column(String(64), nullable=False)
    policy_snapshot_id = Column(String(128), nullable=False, index=True)
    coverage_status = Column(String(32), nullable=False, index=True)
    coverage_payload = Column(JSON, nullable=False)
    sensitivity = Column(String(32), nullable=False)
    retention_class = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)


class ArtifactLineageModel(Base):
    __tablename__ = "artifact_lineage"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "artifact_id", "relation", "related_artifact_id",
            name="uq_artifact_lineage_edge",
        ),
        CheckConstraint(
            f"relation IN ({_sql_values(_LINEAGE_RELATIONS)})",
            name="ck_artifact_lineage_relation",
        ),
        CheckConstraint("artifact_id != related_artifact_id", name="ck_artifact_lineage_no_self_edge"),
        Index("ix_artifact_lineage_incoming", "tenant_id", "related_artifact_id", "relation"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(128), nullable=False, index=True)
    artifact_id = Column(
        String(128), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    relation = Column(String(32), nullable=False)
    related_artifact_id = Column(
        String(128), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class ArtifactReferenceModel(Base):
    """Durable reference from another domain resource to an artifact."""

    __tablename__ = "artifact_references"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "artifact_id", "referrer_kind", "referrer_id",
            name="uq_artifact_reference_owner",
        ),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(128), nullable=False, index=True)
    artifact_id = Column(
        String(128), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    referrer_kind = Column(String(64), nullable=False)
    referrer_id = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class ArtifactReferenceReleaseModel(Base):
    """Append-only release marker; references themselves are never rewritten."""

    __tablename__ = "artifact_reference_releases"
    __table_args__ = (
        UniqueConstraint("reference_id", name="uq_artifact_reference_release"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    reference_id = Column(
        String(36), ForeignKey("artifact_references.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    reason_code = Column(String(64), nullable=False)
    released_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class ArtifactTombstoneModel(Base):
    """Immutable request to make one artifact payload permanently unavailable."""

    __tablename__ = "artifact_tombstones"
    __table_args__ = (
        UniqueConstraint("artifact_id", name="uq_artifact_tombstone"),
        CheckConstraint("length(request_digest) = 64", name="ck_artifact_tombstone_digest_length"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(128), nullable=False, index=True)
    artifact_id = Column(
        String(128), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    reason_code = Column(String(64), nullable=False)
    requested_by = Column(String(128), nullable=False)
    request_id = Column(String(128), nullable=False, index=True)
    request_digest = Column(String(64), nullable=False)
    requested_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    eligible_at = Column(DateTime(timezone=True), nullable=False, index=True)


class ArtifactDeletionAttemptModel(Base):
    """Append-only reconciliation outcome for an artifact tombstone."""

    __tablename__ = "artifact_deletion_attempts"
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('DELETED','BLOCKED','RETRYABLE_FAILURE','PERMANENT_FAILURE')",
            name="ck_artifact_deletion_outcome",
        ),
        Index("ix_artifact_deletion_tombstone_time", "tombstone_id", "attempted_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tombstone_id = Column(
        String(36), ForeignKey("artifact_tombstones.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    outcome = Column(String(32), nullable=False, index=True)
    observed_digest = Column(String(64), nullable=True)
    blocker_codes = Column(JSON, nullable=False, default=list)
    failure_code = Column(String(64), nullable=True)
    attempted_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
