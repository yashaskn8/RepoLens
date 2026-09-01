"""Database authority for bounded, durable background execution.

These tables deliberately contain infrastructure state only. Domain workflows keep
their own status while linking to a work item and recording the final domain
outcome on that work item.
"""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    text,
)

from app.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


_WORK_STATES = (
    "QUEUED",
    "ADMITTED",
    "READY",
    "LEASED",
    "RUNNING",
    "RETRY_WAIT",
    "SUCCEEDED",
    "FAILED",
    "CANCELLED",
    "TIMED_OUT",
)
_DOMAIN_OUTCOMES = ("COMPLETE", "DEGRADED", "BOUNDED")
_ATTEMPT_STATES = ("LEASED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT")
_LEASE_STATES = ("ACTIVE", "RELEASED", "EXPIRED", "REVOKED")
_RESERVATION_STATES = ("ACTIVE", "RELEASED", "EXPIRED", "REVOKED")


class WorkItemModel(Base):
    """One idempotent unit of execution, independent of workflow implementation."""

    __tablename__ = "execution_work_items"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "work_kind",
            "idempotency_key",
            name="uq_execution_work_idempotency",
        ),
        UniqueConstraint(
            "tenant_id",
            "work_kind",
            "external_idempotency_key",
            name="uq_execution_external_idempotency",
        ),
        CheckConstraint(
            f"state IN ({','.join(repr(value) for value in _WORK_STATES)})",
            name="ck_execution_work_state",
        ),
        CheckConstraint(
            "domain_outcome IS NULL OR domain_outcome IN ('COMPLETE','DEGRADED','BOUNDED')",
            name="ck_execution_domain_outcome",
        ),
        CheckConstraint(
            "side_effect_class IN ('SAFE_RECOMPUTATION','EXTERNAL_SIDE_EFFECT')",
            name="ck_execution_side_effect_class",
        ),
        CheckConstraint(
            "side_effect_class != 'EXTERNAL_SIDE_EFFECT' OR external_idempotency_key IS NOT NULL",
            name="ck_execution_external_identity",
        ),
        CheckConstraint("attempt_count >= 0 AND max_attempts > 0", name="ck_execution_attempt_bounds"),
        CheckConstraint("priority >= 0 AND priority <= 100", name="ck_execution_priority"),
        CheckConstraint("version >= 0", name="ck_execution_work_version"),
        CheckConstraint(
            "state NOT IN ('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT') OR terminal_at IS NOT NULL",
            name="ck_execution_terminal_timestamp",
        ),
        Index("ix_execution_claim", "state", "available_at", "priority", "created_at"),
        Index("ix_execution_tenant_active", "tenant_id", "state"),
        Index("ix_execution_subject", "tenant_id", "resource_type", "resource_id"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    request_id = Column(String(128), nullable=False, index=True)
    requested_by = Column(String(128), nullable=False)
    policy_snapshot_id = Column(String(128), nullable=False, index=True)

    work_kind = Column(String(64), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(128), nullable=False)
    state = Column(String(32), nullable=False, default="QUEUED", index=True)
    domain_outcome = Column(String(32), nullable=True)
    outcome_detail = Column(JSON, nullable=False, default=dict)
    coverage_artifact_id = Column(String(128), nullable=True, index=True)
    coverage_summary = Column(JSON, nullable=False, default=dict)

    idempotency_key = Column(String(256), nullable=False)
    request_digest = Column(String(64), nullable=False)
    side_effect_class = Column(String(32), nullable=False, default="SAFE_RECOMPUTATION")
    external_idempotency_key = Column(String(256), nullable=True)
    reconciliation_required = Column(Boolean, nullable=False, default=False)

    resource_profile = Column(String(64), nullable=False, index=True)
    priority = Column(Integer, nullable=False, default=50)
    max_attempts = Column(Integer, nullable=False, default=3)
    attempt_count = Column(Integer, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=0)

    input_artifact_id = Column(String(128), nullable=True)
    output_artifact_id = Column(String(128), nullable=True)
    checkpoint_artifact_id = Column(String(128), nullable=True)

    available_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    deadline_at = Column(DateTime(timezone=True), nullable=False, index=True)
    cancel_requested_at = Column(DateTime(timezone=True), nullable=True)
    cancel_reason = Column(String(256), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    admitted_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    terminal_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)


class WorkAttemptModel(Base):
    """Immutable attempt identity plus its bounded lifecycle."""

    __tablename__ = "execution_attempts"
    __table_args__ = (
        UniqueConstraint("work_item_id", "attempt_number", name="uq_execution_attempt_number"),
        CheckConstraint(
            f"state IN ({','.join(repr(value) for value in _ATTEMPT_STATES)})",
            name="ck_execution_attempt_state",
        ),
        CheckConstraint("attempt_number > 0", name="ck_execution_attempt_positive"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    work_item_id = Column(
        String(36), ForeignKey("execution_work_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt_number = Column(Integer, nullable=False)
    worker_id = Column(String(128), nullable=False, index=True)
    state = Column(String(32), nullable=False, default="LEASED", index=True)
    policy_snapshot_id = Column(String(128), nullable=False)
    failure_code = Column(String(64), nullable=True)
    checkpoint_sequence = Column(Integer, nullable=False, default=0)
    side_effect_started_at = Column(DateTime(timezone=True), nullable=True)
    side_effect_completed_at = Column(DateTime(timezone=True), nullable=True)
    external_operation_id = Column(String(256), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)


class WorkLeaseModel(Base):
    """Opaque-token lease. Only a token digest is persisted."""

    __tablename__ = "execution_leases"
    __table_args__ = (
        UniqueConstraint("attempt_id", name="uq_execution_lease_attempt"),
        CheckConstraint(
            f"state IN ({','.join(repr(value) for value in _LEASE_STATES)})",
            name="ck_execution_lease_state",
        ),
        Index(
            "uq_execution_active_lease_per_work_item",
            "work_item_id",
            unique=True,
            sqlite_where=text("state = 'ACTIVE'"),
            postgresql_where=text("state = 'ACTIVE'"),
        ),
        Index("ix_execution_lease_recovery", "state", "expires_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    work_item_id = Column(
        String(36), ForeignKey("execution_work_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt_id = Column(
        String(36), ForeignKey("execution_attempts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    worker_id = Column(String(128), nullable=False, index=True)
    token_digest = Column(String(64), nullable=False)
    state = Column(String(16), nullable=False, default="ACTIVE", index=True)
    acquired_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    heartbeat_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    released_at = Column(DateTime(timezone=True), nullable=True)


class WorkCheckpointModel(Base):
    """Immutable checkpoint pointer; large workflow state belongs in artifact storage."""

    __tablename__ = "execution_checkpoints"
    __table_args__ = (
        UniqueConstraint("work_item_id", "sequence", name="uq_execution_checkpoint_sequence"),
        CheckConstraint("sequence > 0", name="ck_execution_checkpoint_sequence"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    work_item_id = Column(
        String(36), ForeignKey("execution_work_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt_id = Column(
        String(36), ForeignKey("execution_attempts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    sequence = Column(Integer, nullable=False)
    stage = Column(String(128), nullable=False)
    schema_version = Column(String(64), nullable=False)
    artifact_id = Column(String(128), nullable=False)
    content_digest = Column(String(64), nullable=False)
    coverage_artifact_id = Column(String(128), nullable=True)
    checkpoint_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class FailureRecordModel(Base):
    """Sanitized immutable failure record; raw exception text is not persisted."""

    __tablename__ = "execution_failure_records"
    __table_args__ = (
        CheckConstraint(
            "category IN ('USER','REPOSITORY','ANALYZER','PROVIDER','MODEL','BUDGET','WORKFLOW','WORKER','EXTERNAL','INTERNAL')",
            name="ck_execution_failure_category",
        ),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    work_item_id = Column(
        String(36), ForeignKey("execution_work_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt_id = Column(
        String(36), ForeignKey("execution_attempts.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    code = Column(String(64), nullable=False, index=True)
    category = Column(String(32), nullable=False)
    stage = Column(String(128), nullable=True)
    retryable = Column(Boolean, nullable=False)
    infrastructure_state = Column(String(32), nullable=False)
    public_message = Column(String(512), nullable=False)
    internal_detail_digest = Column(String(64), nullable=True)
    failure_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class ResourcePoolModel(Base):
    """Capacity ledger locked and updated by the relational database."""

    __tablename__ = "execution_resource_pools"
    __table_args__ = (
        UniqueConstraint("resource_type", "scope_id", name="uq_execution_resource_pool_scope"),
        CheckConstraint("capacity_units > 0", name="ck_execution_pool_capacity"),
        CheckConstraint(
            "reserved_units >= 0 AND reserved_units <= capacity_units",
            name="ck_execution_pool_reserved",
        ),
        CheckConstraint("version >= 0", name="ck_execution_pool_version"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    resource_type = Column(String(64), nullable=False, index=True)
    scope_id = Column(String(128), nullable=False, default="*", index=True)
    capacity_units = Column(Integer, nullable=False)
    reserved_units = Column(Integer, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=0)
    policy_snapshot_id = Column(String(128), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)


class ResourceReservationModel(Base):
    """Lease-bound resource reservation used for backpressure."""

    __tablename__ = "execution_resource_reservations"
    __table_args__ = (
        UniqueConstraint("lease_id", "pool_id", name="uq_execution_reservation_lease_pool"),
        CheckConstraint("units > 0", name="ck_execution_reservation_units"),
        CheckConstraint(
            f"state IN ({','.join(repr(value) for value in _RESERVATION_STATES)})",
            name="ck_execution_reservation_state",
        ),
        Index("ix_execution_reservation_recovery", "state", "expires_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    work_item_id = Column(
        String(36), ForeignKey("execution_work_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt_id = Column(
        String(36), ForeignKey("execution_attempts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    lease_id = Column(
        String(36), ForeignKey("execution_leases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    pool_id = Column(
        String(36), ForeignKey("execution_resource_pools.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    resource_type = Column(String(64), nullable=False)
    scope_id = Column(String(128), nullable=False)
    units = Column(Integer, nullable=False)
    state = Column(String(16), nullable=False, default="ACTIVE", index=True)
    reserved_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    released_at = Column(DateTime(timezone=True), nullable=True)


class RequestBudgetModel(Base):
    """One database-authoritative budget ledger per work item."""

    __tablename__ = "execution_request_budgets"
    __table_args__ = (
        UniqueConstraint("work_item_id", name="uq_execution_budget_work_item"),
        CheckConstraint(
            "max_wall_clock_seconds > 0 AND max_analyzer_seconds >= 0 AND max_ai_calls >= 0 "
            "AND max_input_tokens >= 0 AND max_output_tokens >= 0 AND max_escalation_tier >= 0 "
            "AND max_retrieval_context_tokens >= 0 AND max_embedding_calls >= 0 "
            "AND max_report_bytes >= 0 AND max_report_pages >= 0",
            name="ck_execution_budget_limits",
        ),
        CheckConstraint(
            "used_analyzer_seconds >= 0 AND used_ai_calls >= 0 AND used_input_tokens >= 0 "
            "AND used_output_tokens >= 0 AND used_escalation_tier >= 0 "
            "AND used_retrieval_context_tokens >= 0 AND used_embedding_calls >= 0 "
            "AND used_report_bytes >= 0 AND used_report_pages >= 0",
            name="ck_execution_budget_usage",
        ),
        CheckConstraint("version >= 0", name="ck_execution_budget_version"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    work_item_id = Column(
        String(36), ForeignKey("execution_work_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    max_wall_clock_seconds = Column(Integer, nullable=False)
    max_analyzer_seconds = Column(Integer, nullable=False)
    max_ai_calls = Column(Integer, nullable=False)
    max_input_tokens = Column(Integer, nullable=False)
    max_output_tokens = Column(Integer, nullable=False)
    max_escalation_tier = Column(Integer, nullable=False)
    max_retrieval_context_tokens = Column(Integer, nullable=False)
    max_embedding_calls = Column(Integer, nullable=False)
    max_report_bytes = Column(Integer, nullable=False)
    max_report_pages = Column(Integer, nullable=False)

    used_analyzer_seconds = Column(Integer, nullable=False, default=0)
    used_ai_calls = Column(Integer, nullable=False, default=0)
    used_input_tokens = Column(Integer, nullable=False, default=0)
    used_output_tokens = Column(Integer, nullable=False, default=0)
    used_escalation_tier = Column(Integer, nullable=False, default=0)
    used_retrieval_context_tokens = Column(Integer, nullable=False, default=0)
    used_embedding_calls = Column(Integer, nullable=False, default=0)
    used_report_bytes = Column(Integer, nullable=False, default=0)
    used_report_pages = Column(Integer, nullable=False, default=0)

    exhausted_dimension = Column(String(64), nullable=True)
    exhausted_at = Column(DateTime(timezone=True), nullable=True)
    coverage_explanation = Column(Text, nullable=True)
    wall_clock_started_at = Column(DateTime(timezone=True), nullable=True)
    version = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)


__all__ = [
    "FailureRecordModel",
    "RequestBudgetModel",
    "ResourcePoolModel",
    "ResourceReservationModel",
    "WorkAttemptModel",
    "WorkCheckpointModel",
    "WorkItemModel",
    "WorkLeaseModel",
]
