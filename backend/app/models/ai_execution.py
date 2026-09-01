"""Durable AI execution provenance, provider health, and quota reservation state."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    event,
)

from app.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AIExecutionModel(Base):
    """Append-only, content-minimized provenance for one provider attempt."""

    __tablename__ = "ai_executions"
    __table_args__ = (
        CheckConstraint(
            "validation_result IN ('NOT_REQUESTED','VALID','INVALID','UNCERTAIN')",
            name="ck_ai_execution_validation_result",
        ),
        UniqueConstraint("record_digest", name="uq_ai_execution_record_digest"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String(36), nullable=True, index=True)
    request_id = Column(String(128), nullable=True, index=True)
    work_item_id = Column(String(36), nullable=True, index=True)
    attempt_id = Column(String(36), nullable=True, index=True)
    parent_execution_id = Column(String(36), nullable=True, index=True)
    sequence = Column(Integer, nullable=False, default=1)

    provider = Column(String(32), nullable=False, index=True)
    model = Column(String(256), nullable=False, index=True)
    model_revision = Column(String(128), nullable=True)
    capability = Column(String(64), nullable=False, index=True)
    prompt_template_version = Column(String(128), nullable=False)
    prompt_digest = Column(String(64), nullable=False, index=True)
    output_schema_version = Column(String(128), nullable=True)
    output_schema_digest = Column(String(64), nullable=True)
    evidence_digest = Column(String(64), nullable=True, index=True)
    policy_snapshot_id = Column(String(36), nullable=True, index=True)
    artifact_id = Column(String(128), nullable=True, index=True)

    generation_settings = Column(JSON, nullable=False, default=dict)
    request_budget = Column(JSON, nullable=False, default=dict)
    estimated_input_tokens = Column(Integer, nullable=False)
    input_tokens = Column(Integer, nullable=True)
    output_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)
    latency_ms = Column(Float, nullable=False)
    validation_result = Column(String(32), nullable=False)
    success = Column(Boolean, nullable=False)
    failure_code = Column(String(64), nullable=True)
    fallback_reason = Column(String(128), nullable=True)
    escalation_reason = Column(String(128), nullable=True)
    quota_reservation_id = Column(String(36), nullable=True, index=True)
    output_digest = Column(String(64), nullable=True)
    routing_policy_version = Column(String(128), nullable=False)
    model_registry_version = Column(String(64), nullable=False)
    record_digest = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)


@event.listens_for(AIExecutionModel, "before_update", propagate=True)
def _prevent_ai_execution_update(*_: object) -> None:
    raise ValueError("AIExecutionModel is append-only and cannot be updated")


@event.listens_for(AIExecutionModel, "before_delete", propagate=True)
def _prevent_ai_execution_delete(*_: object) -> None:
    raise ValueError("AIExecutionModel is append-only and cannot be deleted directly")


class AIProviderHealthModel(Base):
    """Durable circuit state; database ownership supports multiple gateway workers."""

    __tablename__ = "ai_provider_health"
    __table_args__ = (
        UniqueConstraint("provider", "model", name="uq_ai_provider_health_endpoint"),
        CheckConstraint("circuit_state IN ('CLOSED','OPEN','HALF_OPEN')", name="ck_ai_provider_circuit_state"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    provider = Column(String(32), nullable=False, index=True)
    model = Column(String(256), nullable=False, index=True)
    circuit_state = Column(String(16), nullable=False, default="CLOSED", index=True)
    consecutive_failures = Column(Integer, nullable=False, default=0)
    successes = Column(Integer, nullable=False, default=0)
    failures = Column(Integer, nullable=False, default=0)
    last_failure_code = Column(String(64), nullable=True)
    opened_until = Column(DateTime(timezone=True), nullable=True, index=True)
    probe_claimed_until = Column(DateTime(timezone=True), nullable=True)
    version = Column(Integer, nullable=False, default=1)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class AIQuotaBucketModel(Base):
    """Provider/model allowance for a fixed time window."""

    __tablename__ = "ai_quota_buckets"
    __table_args__ = (
        UniqueConstraint(
            "scope_id", "provider", "model", "window_key",
            name="uq_ai_quota_bucket_window",
        ),
        CheckConstraint("reserved_calls >= 0 AND consumed_calls >= 0", name="ck_ai_quota_nonnegative_calls"),
        CheckConstraint(
            "reserved_input_tokens >= 0 AND consumed_input_tokens >= 0",
            name="ck_ai_quota_nonnegative_input",
        ),
        CheckConstraint(
            "reserved_output_tokens >= 0 AND consumed_output_tokens >= 0",
            name="ck_ai_quota_nonnegative_output",
        ),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scope_id = Column(String(64), nullable=False, default="*", index=True)
    provider = Column(String(32), nullable=False, index=True)
    model = Column(String(256), nullable=False, index=True)
    window_key = Column(String(64), nullable=False, index=True)
    window_starts_at = Column(DateTime(timezone=True), nullable=False)
    window_ends_at = Column(DateTime(timezone=True), nullable=False, index=True)
    call_limit = Column(Integer, nullable=True)
    input_token_limit = Column(Integer, nullable=True)
    output_token_limit = Column(Integer, nullable=True)
    reserved_calls = Column(Integer, nullable=False, default=0)
    reserved_input_tokens = Column(Integer, nullable=False, default=0)
    reserved_output_tokens = Column(Integer, nullable=False, default=0)
    consumed_calls = Column(Integer, nullable=False, default=0)
    consumed_input_tokens = Column(Integer, nullable=False, default=0)
    consumed_output_tokens = Column(Integer, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class AIQuotaReservationModel(Base):
    """Durable reservation settled with provider-reported usage after an attempt."""

    __tablename__ = "ai_quota_reservations"
    __table_args__ = (
        CheckConstraint("state IN ('RESERVED','COMMITTED','RELEASED','EXPIRED')", name="ck_ai_quota_reservation_state"),
        UniqueConstraint("execution_id", name="uq_ai_quota_reservation_execution"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    bucket_id = Column(String(36), ForeignKey("ai_quota_buckets.id", ondelete="CASCADE"), nullable=False, index=True)
    execution_id = Column(String(36), nullable=False, index=True)
    request_id = Column(String(128), nullable=True, index=True)
    tenant_id = Column(String(36), nullable=True, index=True)
    state = Column(String(16), nullable=False, default="RESERVED", index=True)
    estimated_input_tokens = Column(Integer, nullable=False)
    estimated_output_tokens = Column(Integer, nullable=False)
    actual_input_tokens = Column(Integer, nullable=True)
    actual_output_tokens = Column(Integer, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    settled_at = Column(DateTime(timezone=True), nullable=True)
