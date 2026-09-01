"""Database-authoritative execution, leasing, budgets, and backpressure."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Callable, Iterable, Mapping, Optional
from uuid import uuid4

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.execution.errors import (
    ExecutionInvariantViolation,
    IdempotencyConflict,
    InvalidExecutionTransition,
    LeaseLost,
    ResourceCapacityUnavailable,
)
from app.execution.types import (
    ACTIVE_STATES,
    DEFAULT_RESOURCE_CAPACITIES,
    FAILURE_CATEGORIES,
    RESOURCE_PROFILE_REQUIREMENTS,
    TERMINAL_STATES,
    BudgetConsumption,
    BudgetDecision,
    ClaimedWork,
    DomainOutcome,
    EnqueueRequest,
    EnqueueResult,
    ExecutionState,
    FailureCode,
    HeartbeatResult,
    LeaseState,
    RecoveryResult,
    ReservationState,
    ResourceDimension,
    ResourceProfile,
    SideEffectClass,
    WorkKind,
)
from app.models.execution import (
    FailureRecordModel,
    RequestBudgetModel,
    ResourcePoolModel,
    ResourceReservationModel,
    WorkAttemptModel,
    WorkCheckpointModel,
    WorkItemModel,
    WorkLeaseModel,
)


_GLOBAL_SCOPE = "*"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _enum_value(value: object) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DurableExecutionEngine:
    """Session-bound durable execution application service.

    With ``auto_commit=True`` (the default), every public mutation commits its
    complete transition before returning. Set it to ``False`` when enqueueing a
    work item and a domain/outbox record in one caller-owned transaction.

    PostgreSQL claims candidates with ``FOR UPDATE SKIP LOCKED`` and all dialects
    use a versioned compare-and-swap plus conditional resource-ledger updates.
    SQLite is deliberately constrained to one active WORKER reservation.
    """

    def __init__(
        self,
        db: Session,
        *,
        lease_seconds: int = 60,
        per_tenant_active_jobs: int = 1,
        resource_capacities: Optional[Mapping[ResourceDimension | str, int]] = None,
        auto_commit: bool = True,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if per_tenant_active_jobs <= 0:
            raise ValueError("per_tenant_active_jobs must be positive")
        self.db = db
        self.lease_seconds = lease_seconds
        self.per_tenant_active_jobs = per_tenant_active_jobs
        self.auto_commit = auto_commit
        self.clock = clock
        supplied = resource_capacities or DEFAULT_RESOURCE_CAPACITIES
        self.resource_capacities = {
            ResourceDimension(_enum_value(key)): int(value) for key, value in supplied.items()
        }
        if any(value <= 0 for value in self.resource_capacities.values()):
            raise ValueError("resource capacities must be positive")
        if self._dialect == "sqlite":
            self.resource_capacities[ResourceDimension.WORKER] = 1

    @property
    def _dialect(self) -> str:
        return self.db.get_bind().dialect.name

    def _persist(self) -> None:
        if self.auto_commit:
            self.db.commit()
        else:
            self.db.flush()

    def _rollback_on_error(self) -> None:
        if self.auto_commit:
            self.db.rollback()

    def configure_capacity(
        self,
        resource_type: ResourceDimension | str,
        capacity_units: int,
        *,
        policy_snapshot_id: str,
        scope_id: str = _GLOBAL_SCOPE,
    ) -> ResourcePoolModel:
        """Create or update a bounded resource pool without overcommitting it."""
        resource_value = _enum_value(resource_type)
        if capacity_units <= 0:
            raise ValueError("capacity_units must be positive")
        if self._dialect == "sqlite" and resource_value == ResourceDimension.WORKER.value:
            capacity_units = 1
        try:
            pool = (
                self.db.query(ResourcePoolModel)
                .filter(
                    ResourcePoolModel.resource_type == resource_value,
                    ResourcePoolModel.scope_id == scope_id,
                )
                .with_for_update()
                .first()
            )
            if pool is None:
                pool = ResourcePoolModel(
                    resource_type=resource_value,
                    scope_id=scope_id,
                    capacity_units=capacity_units,
                    reserved_units=0,
                    policy_snapshot_id=policy_snapshot_id,
                )
                self.db.add(pool)
            else:
                if capacity_units < pool.reserved_units:
                    raise InvalidExecutionTransition(
                        f"cannot reduce {resource_value} below {pool.reserved_units} active units"
                    )
                pool.capacity_units = capacity_units
                pool.policy_snapshot_id = policy_snapshot_id
                pool.version += 1
                pool.updated_at = self.clock()
            self._persist()
            return pool
        except Exception:
            self._rollback_on_error()
            raise

    def enqueue(self, request: EnqueueRequest) -> EnqueueResult:
        """Idempotently create one work item and its immutable request budget."""
        self._validate_enqueue_request(request)
        kind = WorkKind(_enum_value(request.work_kind))
        profile = ResourceProfile(_enum_value(request.resource_profile))
        side_effect = SideEffectClass(_enum_value(request.side_effect_class))
        existing = self._find_idempotent(request.tenant_id, kind, request.idempotency_key)
        if existing is None and request.external_idempotency_key:
            existing = self._find_external_idempotent(
                request.tenant_id,
                kind,
                request.external_idempotency_key,
            )
        if existing is not None:
            self._verify_idempotent_match(existing, request)
            return EnqueueResult(existing.id, ExecutionState(existing.state), reused=True)

        now = self.clock()
        work_id = str(uuid4())
        work = WorkItemModel(
            id=work_id,
            tenant_id=request.tenant_id,
            request_id=request.request_id,
            requested_by=request.requested_by,
            policy_snapshot_id=request.policy_snapshot_id,
            work_kind=kind.value,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            state=ExecutionState.QUEUED.value,
            idempotency_key=request.idempotency_key,
            request_digest=request.request_digest.lower(),
            request_payload=dict(request.request_payload),
            side_effect_class=side_effect.value,
            external_idempotency_key=request.external_idempotency_key,
            resource_profile=profile.value,
            priority=request.priority,
            max_attempts=request.max_attempts,
            attempt_count=0,
            input_artifact_id=request.input_artifact_id,
            coverage_artifact_id=request.coverage_artifact_id,
            available_at=now,
            deadline_at=now + timedelta(seconds=request.budget.max_wall_clock_seconds),
            created_at=now,
            updated_at=now,
        )
        budget = RequestBudgetModel(
            work_item_id=work_id,
            **vars(request.budget),
            created_at=now,
            updated_at=now,
        )
        try:
            try:
                with self.db.begin_nested():
                    self.db.add(work)
                    self.db.add(budget)
                    self.db.flush()
            except IntegrityError:
                existing = self._find_idempotent(request.tenant_id, kind, request.idempotency_key)
                if existing is None and request.external_idempotency_key:
                    existing = self._find_external_idempotent(
                        request.tenant_id,
                        kind,
                        request.external_idempotency_key,
                    )
                if existing is None:
                    raise
                self._verify_idempotent_match(existing, request)
                self._persist()
                return EnqueueResult(existing.id, ExecutionState(existing.state), reused=True)
            self._persist()
            return EnqueueResult(work_id, ExecutionState.QUEUED, reused=False)
        except Exception:
            self._rollback_on_error()
            raise

    def admit_ready(self, *, limit: int = 100) -> list[str]:
        """Promote eligible work through admission to READY without reserving capacity."""
        if limit <= 0:
            return []
        now = self.clock()
        try:
            self._expire_unstarted_deadlines(now, limit)
            self._promote_retries(now, limit)
            candidates = (
                self.db.query(WorkItemModel)
                .filter(
                    WorkItemModel.state == ExecutionState.QUEUED.value,
                    WorkItemModel.available_at <= now,
                    WorkItemModel.deadline_at > now,
                    WorkItemModel.cancel_requested_at.is_(None),
                )
                .order_by(WorkItemModel.priority.desc(), WorkItemModel.created_at.asc())
                .limit(limit)
                .all()
            )
            ready: list[str] = []
            for work in candidates:
                self._ensure_work_pools(work)
                if not self._profile_has_available_capacity(work):
                    continue
                work.state = ExecutionState.ADMITTED.value
                work.admitted_at = now
                work.updated_at = now
                work.version += 1
                self.db.flush()
                work.state = ExecutionState.READY.value
                work.version += 1
                ready.append(work.id)
            self._persist()
            return ready
        except Exception:
            self._rollback_on_error()
            raise

    def claim_next(
        self,
        worker_id: str,
        *,
        allowed_kinds: Optional[Iterable[WorkKind | str]] = None,
        scan_limit: int = 50,
    ) -> Optional[ClaimedWork]:
        """Atomically claim the highest-priority work whose resources fit."""
        if not worker_id or len(worker_id) > 128:
            raise ValueError("worker_id must be 1-128 characters")
        now = self.clock()
        kind_values = [_enum_value(kind) for kind in allowed_kinds] if allowed_kinds else None
        try:
            self._expire_unstarted_deadlines(now, scan_limit)
            self._promote_retries(now, scan_limit)
            self._admit_ready_internal(now, scan_limit)
            query = self.db.query(WorkItemModel).filter(
                WorkItemModel.state == ExecutionState.READY.value,
                WorkItemModel.available_at <= now,
                WorkItemModel.deadline_at > now,
                WorkItemModel.cancel_requested_at.is_(None),
            )
            if kind_values:
                query = query.filter(WorkItemModel.work_kind.in_(kind_values))
            query = query.order_by(WorkItemModel.priority.desc(), WorkItemModel.created_at.asc())
            if self._dialect == "postgresql":
                query = query.with_for_update(skip_locked=True)
            candidates = query.limit(max(1, scan_limit)).all()
            for candidate in candidates:
                self._ensure_work_pools(candidate)
                claim = self._try_claim(candidate, worker_id, now)
                if claim is not None:
                    self._persist()
                    return claim
            self._persist()
            return None
        except Exception:
            self._rollback_on_error()
            raise

    def claim_specific(self, work_item_id: str, worker_id: str) -> Optional[ClaimedWork]:
        """Atomically claim one submitted item for request-coupled compatibility execution.

        This uses the same attempt, lease, budget, and reservation authority as
        background dispatch.  It exists only so older synchronous API contracts
        can migrate without maintaining a second execution implementation.
        """
        if not worker_id or len(worker_id) > 128:
            raise ValueError("worker_id must be 1-128 characters")
        now = self.clock()
        try:
            self._expire_unstarted_deadlines(now, 1)
            self._promote_retries(now, 1)
            work = self.db.query(WorkItemModel).filter(WorkItemModel.id == work_item_id)
            if self._dialect == "postgresql":
                work = work.with_for_update(skip_locked=True)
            candidate = work.first()
            if candidate is None:
                return None
            if candidate.state == ExecutionState.QUEUED.value:
                self._ensure_work_pools(candidate)
                if not self._profile_has_available_capacity(candidate):
                    self._persist()
                    return None
                candidate.state = ExecutionState.ADMITTED.value
                candidate.admitted_at = now
                candidate.updated_at = now
                candidate.version += 1
                self.db.flush()
                candidate.state = ExecutionState.READY.value
                candidate.version += 1
            if (
                candidate.state != ExecutionState.READY.value
                or _aware(candidate.available_at) > _aware(now)
                or _aware(candidate.deadline_at) <= _aware(now)
                or candidate.cancel_requested_at is not None
            ):
                self._persist()
                return None
            self._ensure_work_pools(candidate)
            claim = self._try_claim(candidate, worker_id, now)
            self._persist()
            return claim
        except Exception:
            self._rollback_on_error()
            raise

    def start(self, work_item_id: str, lease_token: str) -> None:
        """Move an owned LEASED work item to RUNNING."""
        now = self.clock()
        try:
            work, attempt, lease = self._owned_execution(work_item_id, lease_token, now)
            if work.state != ExecutionState.LEASED.value or attempt.state != ExecutionState.LEASED.value:
                raise InvalidExecutionTransition(f"cannot start work in {work.state}")
            work.state = ExecutionState.RUNNING.value
            work.started_at = work.started_at or now
            work.updated_at = now
            work.version += 1
            attempt.state = ExecutionState.RUNNING.value
            attempt.started_at = attempt.started_at or now
            budget = self._budget_for(work.id, lock=True)
            budget.wall_clock_started_at = budget.wall_clock_started_at or now
            budget.updated_at = now
            budget.version += 1
            lease.heartbeat_at = now
            self._persist()
        except Exception:
            self._rollback_on_error()
            raise

    def heartbeat(self, work_item_id: str, lease_token: str) -> HeartbeatResult:
        """Renew a lease and report cancellation or wall-clock exhaustion."""
        now = self.clock()
        try:
            work, attempt, lease = self._owned_execution(work_item_id, lease_token, now)
            if ExecutionState(work.state) not in ACTIVE_STATES:
                raise InvalidExecutionTransition(f"cannot heartbeat work in {work.state}")
            budget = self._budget_for(work.id, lock=True)
            wall_started = budget.wall_clock_started_at or work.started_at or lease.acquired_at
            if _aware(work.deadline_at) <= _aware(now) or (
                wall_started is not None
                and (_aware(now) - _aware(wall_started)).total_seconds() >= budget.max_wall_clock_seconds
            ):
                explanation = "Analysis stopped after its wall-clock budget was exhausted; remaining scope was not analyzed."
                self._finish_bounded(
                    work,
                    attempt,
                    lease,
                    budget,
                    now,
                    dimension="wall_clock_seconds",
                    explanation=explanation,
                    infrastructure_state=ExecutionState.TIMED_OUT,
                )
                self._persist()
                return HeartbeatResult(
                    active=False,
                    budget_exhausted=True,
                    state=ExecutionState.TIMED_OUT,
                )
            new_expiry = now + timedelta(seconds=self.lease_seconds)
            lease.heartbeat_at = now
            lease.expires_at = new_expiry
            self.db.query(ResourceReservationModel).filter(
                ResourceReservationModel.lease_id == lease.id,
                ResourceReservationModel.state == ReservationState.ACTIVE.value,
            ).update(
                {ResourceReservationModel.expires_at: new_expiry},
                synchronize_session=False,
            )
            work.updated_at = now
            work.version += 1
            self._persist()
            return HeartbeatResult(
                active=True,
                cancel_requested=work.cancel_requested_at is not None,
                state=ExecutionState(work.state),
            )
        except Exception:
            self._rollback_on_error()
            raise

    def consume_budget(
        self,
        work_item_id: str,
        lease_token: str,
        consumption: BudgetConsumption,
        *,
        coverage_explanation: Optional[str] = None,
    ) -> BudgetDecision:
        """Atomically charge a request budget or terminate it truthfully as BOUNDED."""
        now = self.clock()
        try:
            work, attempt, lease = self._owned_execution(work_item_id, lease_token, now)
            budget = self._budget_for(work.id, lock=True)
            changes, exceeded = self._budget_changes(budget, consumption)
            if exceeded is not None:
                explanation = coverage_explanation or (
                    f"Analysis stopped because the {exceeded} request budget was exhausted; "
                    "remaining scope was not analyzed."
                )
                self._finish_bounded(
                    work,
                    attempt,
                    lease,
                    budget,
                    now,
                    dimension=exceeded,
                    explanation=explanation[:2000],
                    infrastructure_state=ExecutionState.SUCCEEDED,
                )
                self._persist()
                return BudgetDecision(False, exceeded, ExecutionState.SUCCEEDED)
            for field_name, value in changes.items():
                setattr(budget, field_name, value)
            budget.updated_at = now
            budget.version += 1
            self._persist()
            return BudgetDecision(True, state=ExecutionState(work.state))
        except Exception:
            self._rollback_on_error()
            raise

    def checkpoint(
        self,
        work_item_id: str,
        lease_token: str,
        *,
        stage: str,
        schema_version: str,
        artifact_id: str,
        content_digest: str,
        coverage_artifact_id: Optional[str] = None,
        checkpoint_metadata: Optional[dict] = None,
    ) -> WorkCheckpointModel:
        """Persist an immutable, monotonic pointer to externally stored state."""
        if len(content_digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in content_digest):
            raise ValueError("content_digest must be a SHA-256 hex digest")
        now = self.clock()
        try:
            work, attempt, _ = self._owned_execution(work_item_id, lease_token, now)
            current_sequence = (
                self.db.query(func.max(WorkCheckpointModel.sequence))
                .filter(WorkCheckpointModel.work_item_id == work.id)
                .scalar()
                or 0
            )
            sequence = current_sequence + 1
            metadata = checkpoint_metadata or {}
            if len(json.dumps(metadata, sort_keys=True, separators=(",", ":"), default=str)) > 4096:
                raise ValueError("checkpoint_metadata must be no larger than 4096 encoded characters")
            record = WorkCheckpointModel(
                work_item_id=work.id,
                attempt_id=attempt.id,
                sequence=sequence,
                stage=stage[:128],
                schema_version=schema_version[:64],
                artifact_id=artifact_id[:128],
                content_digest=content_digest.lower(),
                coverage_artifact_id=coverage_artifact_id,
                checkpoint_metadata=metadata,
                created_at=now,
            )
            self.db.add(record)
            attempt.checkpoint_sequence = sequence
            work.checkpoint_artifact_id = artifact_id[:128]
            work.updated_at = now
            work.version += 1
            self._persist()
            return record
        except Exception:
            self._rollback_on_error()
            raise

    def mark_side_effect_started(
        self,
        work_item_id: str,
        lease_token: str,
        *,
        external_operation_id: Optional[str] = None,
    ) -> None:
        """Record the point after which blind retry of an external effect is unsafe."""
        now = self.clock()
        try:
            work, attempt, _ = self._owned_execution(work_item_id, lease_token, now)
            if work.side_effect_class != SideEffectClass.EXTERNAL_SIDE_EFFECT.value:
                raise InvalidExecutionTransition("work item is not an external side effect")
            attempt.side_effect_started_at = attempt.side_effect_started_at or now
            if external_operation_id:
                attempt.external_operation_id = external_operation_id[:256]
            work.updated_at = now
            work.version += 1
            self._persist()
        except Exception:
            self._rollback_on_error()
            raise

    def mark_side_effect_completed(
        self,
        work_item_id: str,
        lease_token: str,
        *,
        external_operation_id: str,
    ) -> None:
        now = self.clock()
        try:
            work, attempt, _ = self._owned_execution(work_item_id, lease_token, now)
            if work.side_effect_class != SideEffectClass.EXTERNAL_SIDE_EFFECT.value:
                raise InvalidExecutionTransition("work item is not an external side effect")
            attempt.side_effect_started_at = attempt.side_effect_started_at or now
            attempt.side_effect_completed_at = now
            attempt.external_operation_id = external_operation_id[:256]
            work.updated_at = now
            work.version += 1
            self._persist()
        except Exception:
            self._rollback_on_error()
            raise

    def complete(
        self,
        work_item_id: str,
        lease_token: str,
        *,
        outcome: DomainOutcome | str,
        coverage_summary: Mapping[str, object],
        coverage_artifact_id: Optional[str] = None,
        output_artifact_id: Optional[str] = None,
        outcome_detail: Optional[Mapping[str, object]] = None,
    ) -> None:
        """Finalize successful infrastructure execution with an explicit domain outcome."""
        domain_outcome = DomainOutcome(_enum_value(outcome))
        if domain_outcome != DomainOutcome.COMPLETE and not coverage_summary:
            raise ValueError("degraded and bounded outcomes require an explicit coverage summary")
        now = self.clock()
        try:
            work, attempt, lease = self._owned_execution(work_item_id, lease_token, now)
            if (
                work.side_effect_class == SideEffectClass.EXTERNAL_SIDE_EFFECT.value
                and attempt.side_effect_completed_at is None
            ):
                raise InvalidExecutionTransition(
                    "external side effects must be marked completed before work finalization"
                )
            work.state = ExecutionState.SUCCEEDED.value
            work.domain_outcome = domain_outcome.value
            work.coverage_summary = dict(coverage_summary)
            work.coverage_artifact_id = coverage_artifact_id or work.coverage_artifact_id
            work.output_artifact_id = output_artifact_id
            work.outcome_detail = dict(outcome_detail or {})
            work.terminal_at = now
            work.updated_at = now
            work.version += 1
            attempt.state = ExecutionState.SUCCEEDED.value
            attempt.finished_at = now
            self._release_resources(lease, ReservationState.RELEASED, now)
            lease.state = LeaseState.RELEASED.value
            lease.released_at = now
            self._persist()
        except Exception:
            self._rollback_on_error()
            raise

    def fail(
        self,
        work_item_id: str,
        lease_token: str,
        *,
        code: FailureCode | str,
        public_message: str,
        retryable: bool,
        stage: Optional[str] = None,
        internal_detail_digest: Optional[str] = None,
        retry_delay_seconds: int = 0,
        may_have_started_external_effect: bool = False,
    ) -> ExecutionState:
        """Record a sanitized failure and either schedule a safe retry or terminate."""
        failure_code = FailureCode(_enum_value(code))
        if retry_delay_seconds < 0 or retry_delay_seconds > 86400:
            raise ValueError("retry_delay_seconds must be between 0 and 86400")
        now = self.clock()
        try:
            work, attempt, lease = self._owned_execution(work_item_id, lease_token, now)
            external_uncertain = (
                work.side_effect_class == SideEffectClass.EXTERNAL_SIDE_EFFECT.value
                and (may_have_started_external_effect or attempt.side_effect_started_at is not None)
                and attempt.side_effect_completed_at is None
            )
            if external_uncertain:
                failure_code = FailureCode.EXTERNAL_STATE_UNCERTAIN
                retryable = False
                work.reconciliation_required = True
            safe_to_recompute = work.side_effect_class == SideEffectClass.SAFE_RECOMPUTATION.value or (
                work.side_effect_class == SideEffectClass.EXTERNAL_SIDE_EFFECT.value
                and attempt.side_effect_started_at is None
                and not may_have_started_external_effect
            )
            can_retry = (
                retryable
                and safe_to_recompute
                and work.attempt_count < work.max_attempts
                and _aware(work.deadline_at) > _aware(now)
                and work.cancel_requested_at is None
            )
            next_state = ExecutionState.RETRY_WAIT if can_retry else ExecutionState.FAILED
            work.state = next_state.value
            work.available_at = now + timedelta(seconds=retry_delay_seconds)
            work.terminal_at = None if can_retry else now
            work.updated_at = now
            work.version += 1
            attempt.state = ExecutionState.FAILED.value
            attempt.failure_code = failure_code.value
            attempt.finished_at = now
            self._add_failure(
                work,
                attempt,
                failure_code,
                retryable=can_retry,
                public_message=public_message,
                stage=stage,
                internal_detail_digest=internal_detail_digest,
                infrastructure_state=next_state,
            )
            self._release_resources(lease, ReservationState.RELEASED, now)
            lease.state = LeaseState.RELEASED.value
            lease.released_at = now
            self._persist()
            return next_state
        except Exception:
            self._rollback_on_error()
            raise

    def request_cancel(self, work_item_id: str, *, tenant_id: str, reason: str) -> ExecutionState:
        """Request cancellation; active workers must acknowledge at a safe point."""
        now = self.clock()
        try:
            work = (
                self.db.query(WorkItemModel)
                .filter(WorkItemModel.id == work_item_id, WorkItemModel.tenant_id == tenant_id)
                .with_for_update()
                .first()
            )
            if work is None:
                raise LookupError("work item not found")
            state = ExecutionState(work.state)
            if state in TERMINAL_STATES:
                return state
            work.cancel_requested_at = work.cancel_requested_at or now
            work.cancel_reason = reason[:256]
            work.updated_at = now
            work.version += 1
            if state not in ACTIVE_STATES:
                work.state = ExecutionState.CANCELLED.value
                work.terminal_at = now
                self._add_failure(
                    work,
                    None,
                    FailureCode.CANCELLED_BY_USER,
                    retryable=False,
                    public_message="The work item was cancelled before execution.",
                    infrastructure_state=ExecutionState.CANCELLED,
                )
                state = ExecutionState.CANCELLED
            self._persist()
            return state
        except Exception:
            self._rollback_on_error()
            raise

    def acknowledge_cancel(self, work_item_id: str, lease_token: str) -> ExecutionState:
        """Release an active lease after the worker reaches a cancellation safe point."""
        now = self.clock()
        try:
            work, attempt, lease = self._owned_execution(work_item_id, lease_token, now)
            if work.cancel_requested_at is None:
                raise InvalidExecutionTransition("cancellation has not been requested")
            external_completed = (
                work.side_effect_class == SideEffectClass.EXTERNAL_SIDE_EFFECT.value
                and attempt.side_effect_completed_at is not None
            )
            if external_completed:
                work.state = ExecutionState.SUCCEEDED.value
                work.domain_outcome = DomainOutcome.COMPLETE.value
                work.coverage_summary = {
                    "schema_version": "1.0",
                    "outcome": "COMPLETE",
                    "units": [{"component": "external_side_effect", "state": "SUCCESSFULLY_ANALYZED"}],
                    "explanation": "The external operation completed before cancellation was acknowledged.",
                }
                work.outcome_detail = {
                    "external_operation_id": attempt.external_operation_id,
                    "cancellation_arrived_after_completion": True,
                }
                work.terminal_at = now
                work.updated_at = now
                work.version += 1
                work.reconciliation_required = False
                attempt.state = ExecutionState.SUCCEEDED.value
                attempt.finished_at = now
                self._release_resources(lease, ReservationState.RELEASED, now)
                lease.state = LeaseState.RELEASED.value
                lease.released_at = now
                self._persist()
                return ExecutionState.SUCCEEDED
            external_uncertain = (
                work.side_effect_class == SideEffectClass.EXTERNAL_SIDE_EFFECT.value
                and attempt.side_effect_started_at is not None
                and attempt.side_effect_completed_at is None
            )
            next_state = ExecutionState.FAILED if external_uncertain else ExecutionState.CANCELLED
            failure_code = (
                FailureCode.EXTERNAL_STATE_UNCERTAIN
                if external_uncertain
                else FailureCode.CANCELLED_BY_USER
            )
            work.state = next_state.value
            work.terminal_at = now
            work.updated_at = now
            work.version += 1
            work.reconciliation_required = external_uncertain
            attempt.state = (
                ExecutionState.FAILED.value if external_uncertain else ExecutionState.CANCELLED.value
            )
            attempt.failure_code = failure_code.value
            attempt.finished_at = now
            self._add_failure(
                work,
                attempt,
                failure_code,
                retryable=False,
                public_message=(
                    "Cancellation arrived after an external write boundary; remote state requires reconciliation."
                    if external_uncertain
                    else "The worker acknowledged cancellation at a safe point."
                ),
                infrastructure_state=next_state,
            )
            self._release_resources(lease, ReservationState.REVOKED, now)
            lease.state = LeaseState.REVOKED.value
            lease.released_at = now
            self._persist()
            return next_state
        except Exception:
            self._rollback_on_error()
            raise

    def recover_expired(self, *, limit: int = 100) -> RecoveryResult:
        """Recover expired leases without blindly replaying uncertain side effects."""
        if limit <= 0:
            return RecoveryResult()
        now = self.clock()
        recovered_ids: list[str] = []
        retry_wait = cancelled = timed_out = uncertain = 0
        try:
            query = (
                self.db.query(WorkLeaseModel)
                .filter(
                    WorkLeaseModel.state == LeaseState.ACTIVE.value,
                    WorkLeaseModel.expires_at <= now,
                )
                .order_by(WorkLeaseModel.expires_at.asc())
            )
            if self._dialect == "postgresql":
                query = query.with_for_update(skip_locked=True)
            leases = query.limit(limit).all()
            for lease in leases:
                work = (
                    self.db.query(WorkItemModel)
                    .filter(WorkItemModel.id == lease.work_item_id)
                    .with_for_update()
                    .first()
                )
                attempt = self.db.query(WorkAttemptModel).filter(WorkAttemptModel.id == lease.attempt_id).first()
                if work is None or attempt is None:
                    raise ExecutionInvariantViolation("active lease has no work item or attempt")
                if ExecutionState(work.state) not in ACTIVE_STATES:
                    self._release_resources(lease, ReservationState.EXPIRED, now)
                    lease.state = LeaseState.EXPIRED.value
                    lease.released_at = now
                    continue
                attempt.state = ExecutionState.TIMED_OUT.value
                attempt.finished_at = now
                self._release_resources(lease, ReservationState.EXPIRED, now)
                lease.state = LeaseState.EXPIRED.value
                lease.released_at = now

                if (
                    work.side_effect_class == SideEffectClass.EXTERNAL_SIDE_EFFECT.value
                    and attempt.side_effect_completed_at is not None
                ):
                    attempt.state = ExecutionState.SUCCEEDED.value
                    attempt.failure_code = None
                    work.state = ExecutionState.SUCCEEDED.value
                    work.domain_outcome = DomainOutcome.COMPLETE.value
                    work.coverage_summary = {
                        "schema_version": "1.0",
                        "outcome": "COMPLETE",
                        "units": [{"component": "external_side_effect", "state": "SUCCESSFULLY_ANALYZED"}],
                        "explanation": "The external operation was durably completed before the worker lease expired.",
                    }
                    work.outcome_detail = {
                        "external_operation_id": attempt.external_operation_id,
                        "recovered_after_worker_loss": True,
                    }
                    work.reconciliation_required = False
                    work.terminal_at = now
                    work.updated_at = now
                    work.version += 1
                    recovered_ids.append(work.id)
                    continue

                if (
                    work.side_effect_class == SideEffectClass.EXTERNAL_SIDE_EFFECT.value
                    and attempt.side_effect_started_at is not None
                    and attempt.side_effect_completed_at is None
                ):
                    next_state = ExecutionState.FAILED
                    failure_code = FailureCode.EXTERNAL_STATE_UNCERTAIN
                    work.reconciliation_required = True
                    uncertain += 1
                elif work.cancel_requested_at is not None:
                    next_state = ExecutionState.CANCELLED
                    failure_code = FailureCode.CANCELLED_BY_USER
                    cancelled += 1
                elif _aware(work.deadline_at) <= _aware(now):
                    next_state = ExecutionState.TIMED_OUT
                    failure_code = FailureCode.WORKFLOW_TIMEOUT
                    work.domain_outcome = DomainOutcome.BOUNDED.value
                    work.coverage_summary = {
                        "status": "TRUNCATED",
                        "reason": "The workflow deadline expired before full coverage was completed.",
                    }
                    timed_out += 1
                elif work.attempt_count < work.max_attempts:
                    next_state = ExecutionState.RETRY_WAIT
                    failure_code = FailureCode.WORKER_LOST
                    work.available_at = now
                    retry_wait += 1
                else:
                    next_state = ExecutionState.FAILED
                    failure_code = FailureCode.WORKER_LOST

                attempt.failure_code = failure_code.value

                work.state = next_state.value
                work.terminal_at = now if next_state in TERMINAL_STATES else None
                work.updated_at = now
                work.version += 1
                self._add_failure(
                    work,
                    attempt,
                    failure_code,
                    retryable=next_state == ExecutionState.RETRY_WAIT,
                    public_message=(
                        "The worker lease expired. External state requires reconciliation."
                        if failure_code == FailureCode.EXTERNAL_STATE_UNCERTAIN
                        else "The worker lease expired before the attempt completed."
                    ),
                    infrastructure_state=next_state,
                )
                recovered_ids.append(work.id)
            self._expire_unstarted_deadlines(now, limit)
            self._persist()
            return RecoveryResult(
                recovered=len(recovered_ids),
                retry_wait=retry_wait,
                cancelled=cancelled,
                timed_out=timed_out,
                uncertain=uncertain,
                recovered_work_item_ids=tuple(recovered_ids),
            )
        except Exception:
            self._rollback_on_error()
            raise

    def resolve_external_reconciliation(
        self,
        work_item_id: str,
        *,
        completed: bool,
        safe_to_retry: bool = False,
        outcome_detail: Optional[Mapping[str, object]] = None,
    ) -> ExecutionState:
        """Resolve a terminal uncertain side effect after a read-only remote check."""
        if completed and safe_to_retry:
            raise ValueError("reconciliation cannot be both completed and retryable")
        now = self.clock()
        try:
            work = (
                self.db.query(WorkItemModel)
                .filter(WorkItemModel.id == work_item_id)
                .with_for_update()
                .first()
            )
            if work is None:
                raise LookupError("work item not found")
            if work.side_effect_class != SideEffectClass.EXTERNAL_SIDE_EFFECT.value:
                raise InvalidExecutionTransition("work item is not an external side effect")
            if not work.reconciliation_required:
                return ExecutionState(work.state)
            if completed:
                work.state = ExecutionState.SUCCEEDED.value
                work.domain_outcome = DomainOutcome.COMPLETE.value
                work.coverage_summary = {
                    "schema_version": "1.0",
                    "outcome": "COMPLETE",
                    "units": [{"component": "external_reconciliation", "state": "SUCCESSFULLY_ANALYZED"}],
                    "explanation": "Remote side-effect state was reconciled to a completed operation.",
                }
                work.outcome_detail = dict(outcome_detail or {})
                work.terminal_at = now
                next_state = ExecutionState.SUCCEEDED
            elif safe_to_retry and work.attempt_count < work.max_attempts and _aware(work.deadline_at) > _aware(now):
                work.state = ExecutionState.RETRY_WAIT.value
                work.available_at = now
                work.terminal_at = None
                next_state = ExecutionState.RETRY_WAIT
            else:
                return ExecutionState(work.state)
            work.reconciliation_required = False
            work.updated_at = now
            work.version += 1
            self._persist()
            return next_state
        except Exception:
            self._rollback_on_error()
            raise

    def _find_idempotent(self, tenant_id: str, kind: WorkKind, key: str) -> Optional[WorkItemModel]:
        return (
            self.db.query(WorkItemModel)
            .filter(
                WorkItemModel.tenant_id == tenant_id,
                WorkItemModel.work_kind == kind.value,
                WorkItemModel.idempotency_key == key,
            )
            .first()
        )

    def _find_external_idempotent(
        self,
        tenant_id: str,
        kind: WorkKind,
        key: str,
    ) -> Optional[WorkItemModel]:
        return (
            self.db.query(WorkItemModel)
            .filter(
                WorkItemModel.tenant_id == tenant_id,
                WorkItemModel.work_kind == kind.value,
                WorkItemModel.external_idempotency_key == key,
            )
            .first()
        )

    @staticmethod
    def _validate_enqueue_request(request: EnqueueRequest) -> None:
        required = {
            "tenant_id": request.tenant_id,
            "request_id": request.request_id,
            "requested_by": request.requested_by,
            "policy_snapshot_id": request.policy_snapshot_id,
            "resource_type": request.resource_type,
            "resource_id": request.resource_id,
            "idempotency_key": request.idempotency_key,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"missing execution identity fields: {', '.join(missing)}")
        if not 0 <= request.priority <= 100:
            raise ValueError("priority must be between 0 and 100")
        if request.max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if len(request.request_digest) != 64 or any(
            ch not in "0123456789abcdefABCDEF" for ch in request.request_digest
        ):
            raise ValueError("request_digest must be a SHA-256 hex digest")
        try:
            encoded_payload = json.dumps(
                dict(request.request_payload), sort_keys=True, separators=(",", ":"), default=str
            ).encode("utf-8")
        except Exception as exc:
            raise ValueError("request_payload must be JSON serializable") from exc
        if len(encoded_payload) > 64 * 1024:
            raise ValueError("request_payload exceeds the 64 KiB execution input limit")
        side_effect = SideEffectClass(_enum_value(request.side_effect_class))
        if side_effect == SideEffectClass.EXTERNAL_SIDE_EFFECT and not request.external_idempotency_key:
            raise ValueError("external side effects require an external_idempotency_key")

    @staticmethod
    def _verify_idempotent_match(existing: WorkItemModel, request: EnqueueRequest) -> None:
        expected = (
            request.request_digest.lower(),
            request.resource_type,
            request.resource_id,
            _enum_value(request.resource_profile),
            _enum_value(request.side_effect_class),
            request.external_idempotency_key,
        )
        actual = (
            existing.request_digest,
            existing.resource_type,
            existing.resource_id,
            existing.resource_profile,
            existing.side_effect_class,
            existing.external_idempotency_key,
        )
        if not hmac.compare_digest(existing.request_digest, request.request_digest.lower()) or actual[1:] != expected[1:]:
            raise IdempotencyConflict("idempotency key is already bound to different work input")

    def _get_or_create_pool(
        self,
        resource_type: ResourceDimension,
        scope_id: str,
        capacity: int,
        policy_snapshot_id: str,
    ) -> ResourcePoolModel:
        pool = (
            self.db.query(ResourcePoolModel)
            .filter(
                ResourcePoolModel.resource_type == resource_type.value,
                ResourcePoolModel.scope_id == scope_id,
            )
            .first()
        )
        if pool is not None:
            return pool
        try:
            with self.db.begin_nested():
                pool = ResourcePoolModel(
                    resource_type=resource_type.value,
                    scope_id=scope_id,
                    capacity_units=capacity,
                    reserved_units=0,
                    policy_snapshot_id=policy_snapshot_id,
                )
                self.db.add(pool)
                self.db.flush()
                return pool
        except IntegrityError:
            winner = (
                self.db.query(ResourcePoolModel)
                .filter(
                    ResourcePoolModel.resource_type == resource_type.value,
                    ResourcePoolModel.scope_id == scope_id,
                )
                .first()
            )
            if winner is None:
                raise
            return winner

    def _ensure_work_pools(self, work: WorkItemModel) -> None:
        profile = ResourceProfile(work.resource_profile)
        requirements = RESOURCE_PROFILE_REQUIREMENTS[profile]
        for dimension in sorted(requirements, key=lambda value: value.value):
            capacity = self.resource_capacities.get(dimension, 1)
            if self._dialect == "sqlite" and dimension == ResourceDimension.WORKER:
                capacity = 1
            self._get_or_create_pool(dimension, _GLOBAL_SCOPE, capacity, work.policy_snapshot_id)
        self._get_or_create_pool(
            ResourceDimension.TENANT_ACTIVE_JOB,
            work.tenant_id,
            self.per_tenant_active_jobs,
            work.policy_snapshot_id,
        )

    def _required_pools(self, work: WorkItemModel) -> list[tuple[ResourcePoolModel, int]]:
        requirements = dict(RESOURCE_PROFILE_REQUIREMENTS[ResourceProfile(work.resource_profile)])
        requirements[ResourceDimension.TENANT_ACTIVE_JOB] = 1
        pools: list[tuple[ResourcePoolModel, int]] = []
        for dimension, units in sorted(requirements.items(), key=lambda item: item[0].value):
            scope_id = work.tenant_id if dimension == ResourceDimension.TENANT_ACTIVE_JOB else _GLOBAL_SCOPE
            pool = (
                self.db.query(ResourcePoolModel)
                .filter(
                    ResourcePoolModel.resource_type == dimension.value,
                    ResourcePoolModel.scope_id == scope_id,
                )
                .first()
            )
            if pool is None:
                raise ExecutionInvariantViolation(f"resource pool {dimension.value}/{scope_id} is missing")
            pools.append((pool, units))
        return pools

    def _profile_has_available_capacity(self, work: WorkItemModel) -> bool:
        return all(pool.reserved_units + units <= pool.capacity_units for pool, units in self._required_pools(work))

    def _reserve_for_lease(
        self,
        work: WorkItemModel,
        attempt: WorkAttemptModel,
        lease: WorkLeaseModel,
        expires_at: datetime,
    ) -> None:
        for pool, units in self._required_pools(work):
            updated = (
                self.db.query(ResourcePoolModel)
                .filter(
                    ResourcePoolModel.id == pool.id,
                    ResourcePoolModel.reserved_units + units <= ResourcePoolModel.capacity_units,
                )
                .update(
                    {
                        ResourcePoolModel.reserved_units: ResourcePoolModel.reserved_units + units,
                        ResourcePoolModel.version: ResourcePoolModel.version + 1,
                        ResourcePoolModel.updated_at: self.clock(),
                    },
                    synchronize_session="fetch",
                )
            )
            if updated != 1:
                raise ResourceCapacityUnavailable(pool.resource_type)
            self.db.add(
                ResourceReservationModel(
                    work_item_id=work.id,
                    attempt_id=attempt.id,
                    lease_id=lease.id,
                    pool_id=pool.id,
                    resource_type=pool.resource_type,
                    scope_id=pool.scope_id,
                    units=units,
                    state=ReservationState.ACTIVE.value,
                    reserved_at=self.clock(),
                    expires_at=expires_at,
                )
            )

    def _try_claim(self, candidate: WorkItemModel, worker_id: str, now: datetime) -> Optional[ClaimedWork]:
        token = secrets.token_urlsafe(32)
        attempt_id = str(uuid4())
        lease_id = str(uuid4())
        expires_at = now + timedelta(seconds=self.lease_seconds)
        try:
            with self.db.begin_nested():
                expected_version = candidate.version
                attempt_number = candidate.attempt_count + 1
                claimed = (
                    self.db.query(WorkItemModel)
                    .filter(
                        WorkItemModel.id == candidate.id,
                        WorkItemModel.state == ExecutionState.READY.value,
                        WorkItemModel.version == expected_version,
                        WorkItemModel.cancel_requested_at.is_(None),
                        WorkItemModel.deadline_at > now,
                    )
                    .update(
                        {
                            WorkItemModel.state: ExecutionState.LEASED.value,
                            WorkItemModel.attempt_count: WorkItemModel.attempt_count + 1,
                            WorkItemModel.updated_at: now,
                            WorkItemModel.version: WorkItemModel.version + 1,
                        },
                        synchronize_session="fetch",
                    )
                )
                if claimed != 1:
                    return None
                attempt = WorkAttemptModel(
                    id=attempt_id,
                    work_item_id=candidate.id,
                    attempt_number=attempt_number,
                    worker_id=worker_id,
                    state=ExecutionState.LEASED.value,
                    policy_snapshot_id=candidate.policy_snapshot_id,
                    created_at=now,
                )
                lease = WorkLeaseModel(
                    id=lease_id,
                    work_item_id=candidate.id,
                    attempt_id=attempt_id,
                    worker_id=worker_id,
                    token_digest=_token_digest(token),
                    state=LeaseState.ACTIVE.value,
                    acquired_at=now,
                    heartbeat_at=now,
                    expires_at=expires_at,
                )
                self.db.add(attempt)
                self.db.add(lease)
                self.db.flush()
                self._reserve_for_lease(candidate, attempt, lease, expires_at)
                self.db.flush()
            return ClaimedWork(
                work_item_id=candidate.id,
                attempt_id=attempt_id,
                attempt_number=attempt_number,
                lease_token=token,
                lease_expires_at=expires_at,
                tenant_id=candidate.tenant_id,
                work_kind=WorkKind(candidate.work_kind),
                resource_type=candidate.resource_type,
                resource_id=candidate.resource_id,
                policy_snapshot_id=candidate.policy_snapshot_id,
                input_artifact_id=candidate.input_artifact_id,
            )
        except ResourceCapacityUnavailable:
            self.db.expire_all()
            return None

    def _admit_ready_internal(self, now: datetime, limit: int) -> list[str]:
        candidates = (
            self.db.query(WorkItemModel)
            .filter(
                WorkItemModel.state == ExecutionState.QUEUED.value,
                WorkItemModel.available_at <= now,
                WorkItemModel.deadline_at > now,
                WorkItemModel.cancel_requested_at.is_(None),
            )
            .order_by(WorkItemModel.priority.desc(), WorkItemModel.created_at.asc())
            .limit(limit)
            .all()
        )
        ready: list[str] = []
        for work in candidates:
            self._ensure_work_pools(work)
            if not self._profile_has_available_capacity(work):
                continue
            work.state = ExecutionState.ADMITTED.value
            work.admitted_at = now
            work.updated_at = now
            work.version += 1
            self.db.flush()
            work.state = ExecutionState.READY.value
            work.version += 1
            ready.append(work.id)
        return ready

    def _promote_retries(self, now: datetime, limit: int) -> None:
        retry_ids = [
            row[0]
            for row in (
                self.db.query(WorkItemModel.id)
                .filter(
                    WorkItemModel.state == ExecutionState.RETRY_WAIT.value,
                    WorkItemModel.available_at <= now,
                    WorkItemModel.deadline_at > now,
                    WorkItemModel.cancel_requested_at.is_(None),
                )
                .order_by(WorkItemModel.available_at.asc())
                .limit(limit)
                .all()
            )
        ]
        if retry_ids:
            self.db.query(WorkItemModel).filter(
                WorkItemModel.id.in_(retry_ids),
                WorkItemModel.state == ExecutionState.RETRY_WAIT.value,
            ).update(
                {
                    WorkItemModel.state: ExecutionState.READY.value,
                    WorkItemModel.updated_at: now,
                    WorkItemModel.version: WorkItemModel.version + 1,
                },
                synchronize_session="fetch",
            )

    def _expire_unstarted_deadlines(self, now: datetime, limit: int) -> None:
        candidates = (
            self.db.query(WorkItemModel)
            .filter(
                WorkItemModel.state.in_(
                    [
                        ExecutionState.QUEUED.value,
                        ExecutionState.ADMITTED.value,
                        ExecutionState.READY.value,
                        ExecutionState.RETRY_WAIT.value,
                    ]
                ),
                WorkItemModel.deadline_at <= now,
            )
            .order_by(WorkItemModel.deadline_at.asc())
            .limit(limit)
            .all()
        )
        for work in candidates:
            work.state = ExecutionState.TIMED_OUT.value
            work.domain_outcome = DomainOutcome.BOUNDED.value
            work.coverage_summary = {
                "status": "TRUNCATED",
                "reason": "The workflow deadline expired before execution completed.",
            }
            work.terminal_at = now
            work.updated_at = now
            work.version += 1
            self._add_failure(
                work,
                None,
                FailureCode.WORKFLOW_TIMEOUT,
                retryable=False,
                public_message="The work item exceeded its wall-clock deadline.",
                infrastructure_state=ExecutionState.TIMED_OUT,
            )

    def _owned_execution(
        self, work_item_id: str, lease_token: str, now: datetime
    ) -> tuple[WorkItemModel, WorkAttemptModel, WorkLeaseModel]:
        lease = (
            self.db.query(WorkLeaseModel)
            .filter(
                WorkLeaseModel.work_item_id == work_item_id,
                WorkLeaseModel.state == LeaseState.ACTIVE.value,
            )
            .with_for_update()
            .first()
        )
        if lease is None or not hmac.compare_digest(lease.token_digest, _token_digest(lease_token)):
            raise LeaseLost("active lease not owned")
        if _aware(lease.expires_at) <= _aware(now):
            raise LeaseLost("lease expired")
        work = (
            self.db.query(WorkItemModel)
            .filter(WorkItemModel.id == work_item_id)
            .with_for_update()
            .first()
        )
        attempt = (
            self.db.query(WorkAttemptModel)
            .filter(WorkAttemptModel.id == lease.attempt_id)
            .with_for_update()
            .first()
        )
        if work is None or attempt is None:
            raise ExecutionInvariantViolation("lease is missing its work item or attempt")
        return work, attempt, lease

    def _budget_for(self, work_item_id: str, *, lock: bool) -> RequestBudgetModel:
        query = self.db.query(RequestBudgetModel).filter(RequestBudgetModel.work_item_id == work_item_id)
        if lock:
            query = query.with_for_update()
        budget = query.first()
        if budget is None:
            raise ExecutionInvariantViolation("work item has no request budget")
        return budget

    @staticmethod
    def _budget_changes(
        budget: RequestBudgetModel, consumption: BudgetConsumption
    ) -> tuple[dict[str, int], Optional[str]]:
        additive = (
            ("used_analyzer_seconds", "max_analyzer_seconds", consumption.analyzer_seconds, "analyzer_seconds"),
            ("used_ai_calls", "max_ai_calls", consumption.ai_calls, "ai_calls"),
            ("used_input_tokens", "max_input_tokens", consumption.input_tokens, "input_tokens"),
            ("used_output_tokens", "max_output_tokens", consumption.output_tokens, "output_tokens"),
            (
                "used_retrieval_context_tokens",
                "max_retrieval_context_tokens",
                consumption.retrieval_context_tokens,
                "retrieval_context_tokens",
            ),
            ("used_embedding_calls", "max_embedding_calls", consumption.embedding_calls, "embedding_calls"),
            ("used_report_bytes", "max_report_bytes", consumption.report_bytes, "report_bytes"),
            ("used_report_pages", "max_report_pages", consumption.report_pages, "report_pages"),
        )
        changes: dict[str, int] = {}
        for used_field, max_field, increment, dimension in additive:
            proposed = getattr(budget, used_field) + increment
            if proposed > getattr(budget, max_field):
                return {}, dimension
            changes[used_field] = proposed
        escalation = max(budget.used_escalation_tier, consumption.escalation_tier)
        if escalation > budget.max_escalation_tier:
            return {}, "escalation_tier"
        changes["used_escalation_tier"] = escalation
        return changes, None

    def _finish_bounded(
        self,
        work: WorkItemModel,
        attempt: WorkAttemptModel,
        lease: WorkLeaseModel,
        budget: RequestBudgetModel,
        now: datetime,
        *,
        dimension: str,
        explanation: str,
        infrastructure_state: ExecutionState,
    ) -> None:
        budget.exhausted_dimension = dimension
        budget.exhausted_at = now
        budget.coverage_explanation = explanation
        budget.updated_at = now
        budget.version += 1
        work.state = infrastructure_state.value
        work.domain_outcome = DomainOutcome.BOUNDED.value
        work.coverage_summary = {
            "status": "TRUNCATED",
            "reason": explanation,
            "budget_dimension": dimension,
        }
        work.outcome_detail = {"budget_exhausted": dimension}
        work.terminal_at = now
        work.updated_at = now
        work.version += 1
        attempt.state = (
            ExecutionState.TIMED_OUT.value
            if infrastructure_state == ExecutionState.TIMED_OUT
            else ExecutionState.SUCCEEDED.value
        )
        attempt.failure_code = FailureCode.BUDGET_EXHAUSTED.value
        attempt.finished_at = now
        self._add_failure(
            work,
            attempt,
            FailureCode.BUDGET_EXHAUSTED,
            retryable=False,
            public_message=explanation[:512],
            infrastructure_state=infrastructure_state,
            failure_metadata={"dimension": dimension},
        )
        reservation_state = (
            ReservationState.EXPIRED
            if infrastructure_state == ExecutionState.TIMED_OUT
            else ReservationState.RELEASED
        )
        self._release_resources(lease, reservation_state, now)
        lease.state = (
            LeaseState.EXPIRED.value
            if infrastructure_state == ExecutionState.TIMED_OUT
            else LeaseState.RELEASED.value
        )
        lease.released_at = now

    def _release_resources(
        self, lease: WorkLeaseModel, reservation_state: ReservationState, now: datetime
    ) -> None:
        reservations = (
            self.db.query(ResourceReservationModel)
            .filter(
                ResourceReservationModel.lease_id == lease.id,
                ResourceReservationModel.state == ReservationState.ACTIVE.value,
            )
            .with_for_update()
            .all()
        )
        for reservation in reservations:
            released = (
                self.db.query(ResourcePoolModel)
                .filter(
                    ResourcePoolModel.id == reservation.pool_id,
                    ResourcePoolModel.reserved_units >= reservation.units,
                )
                .update(
                    {
                        ResourcePoolModel.reserved_units: ResourcePoolModel.reserved_units - reservation.units,
                        ResourcePoolModel.version: ResourcePoolModel.version + 1,
                        ResourcePoolModel.updated_at: now,
                    },
                    synchronize_session="fetch",
                )
            )
            if released != 1:
                raise ExecutionInvariantViolation("resource reservation exceeds pool ledger")
            reservation.state = reservation_state.value
            reservation.released_at = now

    def _add_failure(
        self,
        work: WorkItemModel,
        attempt: Optional[WorkAttemptModel],
        code: FailureCode,
        *,
        retryable: bool,
        public_message: str,
        infrastructure_state: ExecutionState,
        stage: Optional[str] = None,
        internal_detail_digest: Optional[str] = None,
        failure_metadata: Optional[dict] = None,
    ) -> FailureRecordModel:
        if internal_detail_digest is not None and (
            len(internal_detail_digest) != 64
            or any(ch not in "0123456789abcdefABCDEF" for ch in internal_detail_digest)
        ):
            raise ValueError("internal_detail_digest must be a SHA-256 hex digest")
        record = FailureRecordModel(
            work_item_id=work.id,
            attempt_id=attempt.id if attempt else None,
            code=code.value,
            category=FAILURE_CATEGORIES[code],
            stage=stage[:128] if stage else None,
            retryable=retryable,
            infrastructure_state=infrastructure_state.value,
            public_message=(public_message or "Execution failed safely.")[:512],
            internal_detail_digest=internal_detail_digest.lower() if internal_detail_digest else None,
            failure_metadata=failure_metadata or {},
            created_at=self.clock(),
        )
        self.db.add(record)
        return record


__all__ = ["DurableExecutionEngine"]
