"""Operational policy, transactional outbox, audit-chain, and telemetry models."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)

from app.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class OperationalPolicyModel(Base):
    __tablename__ = "operational_policies"
    __table_args__ = (
        UniqueConstraint("tenant_scope", "version", name="uq_operational_policy_scope_version"),
        UniqueConstraint("tenant_scope", "content_digest", name="uq_operational_policy_scope_digest"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_scope = Column(String(64), nullable=False, default="GLOBAL", index=True)
    version = Column(Integer, nullable=False)
    content_digest = Column(String(64), nullable=False, index=True)
    policy_payload = Column(JSON, nullable=False)
    active = Column(Boolean, nullable=False, default=True, index=True)
    created_by = Column(String(36), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    superseded_at = Column(DateTime(timezone=True), nullable=True)


class OutboxEventModel(Base):
    """Domain event committed in the same transaction as its state change."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "deduplication_key", name="uq_outbox_tenant_dedupe"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String(36), nullable=False, index=True)
    aggregate_type = Column(String(64), nullable=False, index=True)
    aggregate_id = Column(String(128), nullable=False, index=True)
    event_type = Column(String(128), nullable=False, index=True)
    deduplication_key = Column(String(128), nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    payload_digest = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="PENDING", index=True)
    available_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    lease_owner = Column(String(128), nullable=True, index=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    failure_code = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    published_at = Column(DateTime(timezone=True), nullable=True)


class AuditChainHeadModel(Base):
    """Serialized per-tenant head for an append-only audit hash chain."""

    __tablename__ = "audit_chain_heads"

    tenant_id = Column(String(36), primary_key=True)
    sequence = Column(Integer, nullable=False, default=0)
    head_hash = Column(String(64), nullable=False, default="0" * 64)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class AuditEventModel(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "sequence", name="uq_audit_tenant_sequence"),
        UniqueConstraint("tenant_id", "event_hash", name="uq_audit_tenant_hash"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String(36), nullable=False, index=True)
    sequence = Column(Integer, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False, index=True)
    event_type = Column(String(128), nullable=False, index=True)
    actor_id = Column(String(36), nullable=True, index=True)
    request_id = Column(String(128), nullable=True, index=True)
    resource_type = Column(String(64), nullable=False, index=True)
    resource_id = Column(String(128), nullable=False, index=True)
    artifact_digest = Column(String(64), nullable=True)
    state_digest = Column(String(64), nullable=True)
    payload_digest = Column(String(64), nullable=False)
    safe_payload = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)


class TelemetryMetricModel(Base):
    """Structured, low-cardinality operational measurement."""

    __tablename__ = "telemetry_metrics"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String(36), nullable=True, index=True)
    request_id = Column(String(128), nullable=True, index=True)
    work_item_id = Column(String(36), nullable=True, index=True)
    metric_name = Column(String(128), nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    unit = Column(String(32), nullable=False)
    dimensions = Column(JSON, nullable=False, default=dict)
    recorded_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)


class ReconciliationRecordModel(Base):
    """Durable record for externally uncertain or eventually deleted state."""

    __tablename__ = "reconciliation_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "resource_type", "resource_id", "operation", name="uq_reconcile_resource_op"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String(36), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False, index=True)
    resource_id = Column(String(128), nullable=False, index=True)
    operation = Column(String(64), nullable=False)
    expected_digest = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="PENDING", index=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    failure_code = Column(String(64), nullable=True)
    failure_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    completed_at = Column(DateTime(timezone=True), nullable=True)
