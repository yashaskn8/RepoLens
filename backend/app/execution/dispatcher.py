"""Single database-authoritative dispatcher for all long-running RepoLens work."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import logging
import os
import socket
import time
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.execution.context import new_execution_session as SessionLocal
from app.execution.application import WorkSubmissionService
from app.execution.engine import DurableExecutionEngine
from app.execution.errors import LeaseLost
from app.execution.types import (
    ClaimedWork,
    DomainOutcome,
    ExecutionState,
    FailureCode,
    RequestBudget,
    ResourceProfile,
    SideEffectClass,
    WorkKind,
)
from app.governance.events import AuditLedger, DomainOutbox
from app.governance.taxonomy import AnalysisCoverage, CoverageState, CoverageUnit
from app.governance.telemetry import TelemetryRecorder
from app.models.execution import FailureRecordModel, WorkItemModel, WorkLeaseModel


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkHandlerResult:
    outcome: DomainOutcome
    coverage_summary: dict[str, Any]
    coverage_artifact_id: str | None = None
    output_artifact_id: str | None = None
    outcome_detail: dict[str, Any] = field(default_factory=dict)


class DomainWorkFailed(RuntimeError):
    def __init__(
        self,
        code: FailureCode,
        message: str,
        *,
        retryable: bool,
        may_have_started_external_effect: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message
        self.retryable = retryable
        self.may_have_started_external_effect = may_have_started_external_effect


@dataclass
class _AttemptControl:
    cancel_requested: bool = False
    budget_stopped: bool = False
    lease_lost: bool = False


class DurableWorkDispatcher:
    """Local worker runtime whose only durable authority is the relational database.

    The task registry and wake event reduce polling; losing either is harmless because
    leases, attempts, checkpoints, budgets, and resource reservations live in SQL.
    """

    _loop_task: asyncio.Task | None = None
    _wake_event: asyncio.Event | None = None
    _active_tasks: dict[str, asyncio.Task] = {}
    _inline_active: set[str] = set()
    _worker_prefix = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
    _stopping = False

    @classmethod
    def start(cls) -> asyncio.Task | None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return None
        if cls._loop_task is not None and not cls._loop_task.done():
            return cls._loop_task
        cls._stopping = False
        cls._wake_event = asyncio.Event()
        cls._loop_task = asyncio.create_task(cls._dispatch_loop(), name="durable-work-dispatcher")
        cls._wake_event.set()
        return cls._loop_task

    @classmethod
    def nudge(cls) -> asyncio.Task | None:
        task = cls.start()
        if cls._wake_event is not None:
            cls._wake_event.set()
        return task

    @classmethod
    async def execute_specific(
        cls,
        work_item_id: str,
        *,
        session_factory=None,
    ) -> dict[str, Any]:
        """Execute one item through canonical leases for synchronous API compatibility."""
        try:
            from app.execution.context import bind_execution_session_factory, reset_execution_session_factory

            factory_token = bind_execution_session_factory(session_factory)
            db = SessionLocal()
            try:
                cls._reconcile_missing_active_work(db, limit=100)
                claim = DurableExecutionEngine(
                    db,
                    lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
                ).claim_specific(work_item_id, f"{cls._worker_prefix}:inline")
            finally:
                db.close()
            if claim is not None:
                cls._inline_active.add(claim.work_item_id)
                try:
                    await cls._run_claim(claim)
                finally:
                    cls._inline_active.discard(claim.work_item_id)
            result_db = SessionLocal()
            try:
                work = result_db.query(WorkItemModel).filter(WorkItemModel.id == work_item_id).first()
                if work is None:
                    raise LookupError("work item not found after execution")
                failure = (
                    result_db.query(FailureRecordModel)
                    .filter(FailureRecordModel.work_item_id == work_item_id)
                    .order_by(FailureRecordModel.created_at.desc(), FailureRecordModel.id.desc())
                    .first()
                )
                return {
                    "id": work.id,
                    "state": work.state,
                    "domain_outcome": work.domain_outcome,
                    "output_artifact_id": work.output_artifact_id,
                    "outcome_detail": dict(work.outcome_detail or {}),
                    "reconciliation_required": bool(work.reconciliation_required),
                    "failure_code": failure.code if failure is not None else None,
                    "failure_message": failure.public_message if failure is not None else None,
                }
            finally:
                result_db.close()
        finally:
            if "factory_token" in locals():
                reset_execution_session_factory(factory_token)

    @classmethod
    async def stop(cls) -> None:
        cls._stopping = True
        if cls._wake_event is not None:
            cls._wake_event.set()
        if cls._loop_task is not None and not cls._loop_task.done():
            cls._loop_task.cancel()
        for task in list(cls._active_tasks.values()):
            if not task.done():
                task.cancel()
        pending = [task for task in cls._active_tasks.values() if not task.done()]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if cls._loop_task is not None:
            await asyncio.gather(cls._loop_task, return_exceptions=True)
        cls._active_tasks.clear()
        cls._inline_active.clear()
        cls._loop_task = None
        cls._wake_event = None

    @classmethod
    async def _dispatch_loop(cls) -> None:
        settings = get_settings()
        last_recovery = 0.0
        while not cls._stopping:
            try:
                now = time.monotonic()
                run_recovery = now - last_recovery >= settings.EXECUTION_RECOVERY_INTERVAL_SECONDS
                claim = await asyncio.to_thread(cls._recover_and_claim, run_recovery)
                if run_recovery:
                    last_recovery = now
                    await asyncio.to_thread(cls._reconcile_expired_ai_quota, limit=500)
                    await cls._reconcile_uncertain_side_effects(limit=20)
                if claim is not None:
                    task = asyncio.create_task(
                        cls._run_claim(claim),
                        name=f"work:{claim.work_item_id}:{claim.attempt_number}",
                    )
                    cls._active_tasks[claim.work_item_id] = task
                    task.add_done_callback(lambda _, wid=claim.work_item_id: cls._on_attempt_done(wid))
                    continue

                if cls._wake_event is None:
                    return
                cls._wake_event.clear()
                try:
                    await asyncio.wait_for(cls._wake_event.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Durable execution dispatch sweep failed.")
                await asyncio.sleep(1.0)

    @classmethod
    def _on_attempt_done(cls, work_item_id: str) -> None:
        cls._active_tasks.pop(work_item_id, None)
        if cls._wake_event is not None:
            cls._wake_event.set()

    @classmethod
    def _recover_and_claim(cls, run_recovery: bool) -> ClaimedWork | None:
        db = SessionLocal()
        try:
            if not inspect(db.get_bind()).has_table("execution_work_items"):
                return None
            cls._reconcile_missing_active_work(db, limit=100)
            engine = DurableExecutionEngine(
                db,
                lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
            )
            if run_recovery:
                result = engine.recover_expired(limit=100)
                if result.recovered:
                    logger.warning("Recovered %s expired durable work leases.", result.recovered)
            return engine.claim_next(cls._worker_prefix)
        finally:
            db.close()

    @classmethod
    def _reconcile_missing_active_work(cls, db, *, limit: int) -> int:
        """Release safe-work leases whose tenant-owned domain row disappeared.

        Domain rows can be rolled back or deleted independently of an execution
        lease (for example, after a worker crash). Such a lease must not hold the
        global WORKER/AI/PATCH pools until its normal timeout. Unknown resource
        types and all external side-effect work are intentionally left alone.
        """
        if limit <= 0:
            return 0
        candidates = (
            db.query(WorkItemModel, WorkLeaseModel)
            .join(WorkLeaseModel, WorkLeaseModel.work_item_id == WorkItemModel.id)
            .filter(
                WorkLeaseModel.state == "ACTIVE",
                WorkItemModel.state.in_((ExecutionState.LEASED.value, ExecutionState.RUNNING.value)),
                WorkItemModel.side_effect_class == SideEffectClass.SAFE_RECOMPUTATION.value,
                WorkItemModel.resource_type.in_(
                    ("SCAN", "FINDING", "CHANGE_ANALYSIS", "REPORT", "PATCH", "PATCH_REVISION")
                ),
            )
            .order_by(WorkItemModel.updated_at.asc())
            .limit(limit)
            .all()
        )
        reconciled = 0
        for work, lease in candidates:
            local_worker_abandoned = (
                lease.worker_id.startswith(cls._worker_prefix)
                and work.id not in cls._active_tasks
                and work.id not in cls._inline_active
            )
            if not local_worker_abandoned and cls._domain_resource_exists(db, work):
                continue
            try:
                if DurableExecutionEngine(
                    db,
                    lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
                ).fail_orphaned(work.id):
                    reconciled += 1
                    logger.warning(
                        "Failed orphaned durable work %s (%s/%s) and released its reservations.",
                        work.id,
                        work.work_kind,
                        work.resource_id,
                    )
            except Exception:
                db.rollback()
                logger.exception("Orphaned durable work reconciliation failed for %s.", work.id)
        return reconciled

    @staticmethod
    def _domain_resource_exists(db, work: WorkItemModel) -> bool:
        """Check a known domain resource under the work item's tenant boundary."""
        if work.resource_type == "SCAN":
            from app.models.scan import ScanModel

            return db.query(ScanModel.id).filter(
                ScanModel.id == work.resource_id,
                ScanModel.owner_user_id == work.tenant_id,
            ).first() is not None
        if work.resource_type == "FINDING":
            from app.models.finding import FindingModel
            from app.models.scan import ScanModel

            return db.query(FindingModel.id).join(
                ScanModel, ScanModel.id == FindingModel.scan_id
            ).filter(
                FindingModel.id == work.resource_id,
                ScanModel.owner_user_id == work.tenant_id,
            ).first() is not None
        if work.resource_type == "CHANGE_ANALYSIS":
            from app.models.change_analysis import ChangeAnalysisModel

            return db.query(ChangeAnalysisModel.id).filter(
                ChangeAnalysisModel.id == work.resource_id,
                ChangeAnalysisModel.owner_user_id == work.tenant_id,
            ).first() is not None
        if work.resource_type == "REPORT":
            from app.models.report import ReportModel

            return db.query(ReportModel.id).filter(
                ReportModel.id == work.resource_id,
                ReportModel.owner_user_id == work.tenant_id,
            ).first() is not None
        if work.resource_type in {"PATCH", "PATCH_REVISION"}:
            from app.models.patch import PatchModel
            from app.models.scan import ScanModel

            return db.query(PatchModel.id).join(
                ScanModel, ScanModel.id == PatchModel.scan_id
            ).filter(
                PatchModel.id == work.resource_id,
                ScanModel.owner_user_id == work.tenant_id,
            ).first() is not None
        return True

    @classmethod
    def _reconcile_expired_ai_quota(cls, *, limit: int) -> int:
        """Best-effort recovery of provider capacity abandoned by dead attempts."""
        try:
            from app.llm.router import get_llm_router

            released = get_llm_router().reconcile_expired_quota(limit=limit)
        except Exception:
            logger.exception("Expired AI quota reservation reconciliation failed.")
            return 0
        if not released:
            return 0

        logger.warning("Released %s expired AI quota reservations.", released)
        db = SessionLocal()
        try:
            if inspect(db.get_bind()).has_table("telemetry_metrics"):
                TelemetryRecorder.record(
                    db,
                    metric_name="ai.quota_reservations_reclaimed",
                    value=float(released),
                    unit="reservations",
                    dimensions={"worker": cls._worker_prefix},
                )
                db.commit()
        except Exception:
            db.rollback()
            logger.debug("AI quota recovery telemetry persistence failed.", exc_info=True)
        finally:
            db.close()
        return released

    @classmethod
    async def _reconcile_uncertain_side_effects(cls, *, limit: int) -> int:
        """Read remote state for uncertain writes and resolve SQL work authority.

        Reconciliation is deliberately read-only at the provider boundary.  The
        database row lock prevents concurrent state resolution while the remote
        lookup itself remains safe to repeat across hosts after a crash.
        """
        db = SessionLocal()
        try:
            from app.models.platform import ReconciliationRecordModel

            if not inspect(db.get_bind()).has_table("execution_work_items"):
                return 0

            now = datetime.now(timezone.utc)
            rows = (
                db.query(WorkItemModel)
                .filter(
                    WorkItemModel.state == ExecutionState.FAILED.value,
                    WorkItemModel.reconciliation_required.is_(True),
                    WorkItemModel.work_kind.in_([
                        WorkKind.GITHUB_DELIVERY.value,
                        WorkKind.REVIEW_PUBLICATION.value,
                    ]),
                )
                .order_by(WorkItemModel.updated_at.asc())
                .limit(limit)
                .all()
            )
            identities = [
                (row.id, row.tenant_id, row.work_kind, row.resource_id, row.attempt_count)
                for row in rows
            ]
        finally:
            db.close()

        reconciled = 0
        for work_id, tenant_id, work_kind, resource_id, work_attempt_count in identities:
            record_db = SessionLocal()
            record_id: str | None = None
            try:
                from app.models.platform import ReconciliationRecordModel

                attempt_identity = str(work_attempt_count)
                record_id = cls._claim_reconciliation_record(
                    record_db,
                    tenant_id=tenant_id,
                    work_id=work_id,
                    attempt_identity=attempt_identity,
                )
                if record_id is None:
                    continue

                completed = False
                safe_to_retry = False
                outcome_detail: dict[str, Any] = {"reconciliation": "UNCERTAIN"}
                if work_kind == WorkKind.GITHUB_DELIVERY.value:
                    from app.delivery.service import DeliveryService

                    outcome = await DeliveryService().reconcile_delivery(record_db, resource_id)
                    completed = outcome == "COMPLETED"
                    safe_to_retry = outcome == "ABSENT_SAFE_TO_RETRY"
                    outcome_detail = {"delivery_id": resource_id, "reconciliation": outcome}
                elif work_kind == WorkKind.REVIEW_PUBLICATION.value:
                    from app.models.review_publication import PullRequestReviewPublicationModel
                    from app.services.review_publication_service import ReviewPublicationService

                    publication = record_db.query(PullRequestReviewPublicationModel).filter(
                        PullRequestReviewPublicationModel.id == resource_id
                    ).first()
                    if publication is None:
                        outcome_detail = {"publication_id": resource_id, "reconciliation": "MISSING"}
                    else:
                        publication = await ReviewPublicationService(record_db).reconcile_publication(publication)
                        completed = publication.status == "PUBLISHED"
                        outcome_detail = {
                            "publication_id": resource_id,
                            "github_review_id": publication.github_review_id,
                            "github_review_url": publication.github_review_url,
                            "reconciliation": "COMPLETED" if completed else "UNCERTAIN",
                        }

                record_db.expire_all()
                record = (
                    record_db.query(ReconciliationRecordModel)
                    .filter(
                        ReconciliationRecordModel.id == record_id,
                        ReconciliationRecordModel.lease_owner == cls._worker_prefix,
                    )
                    .with_for_update()
                    .first()
                )
                if (
                    record is None
                    or record.lease_expires_at is None
                    or _aware(record.lease_expires_at) <= datetime.now(timezone.utc)
                ):
                    record_db.rollback()
                    continue
                state = cls._engine(record_db).resolve_external_reconciliation(
                    work_id,
                    completed=completed,
                    safe_to_retry=safe_to_retry,
                    outcome_detail=outcome_detail,
                )
                record.status = "COMPLETED" if completed or safe_to_retry else "PENDING"
                record.next_attempt_at = datetime.now(timezone.utc) + timedelta(
                    seconds=min(3600, 30 * (2 ** min(record.attempt_count, 7)))
                )
                record.completed_at = datetime.now(timezone.utc) if record.status == "COMPLETED" else None
                record.lease_owner = None
                record.lease_expires_at = None
                record.updated_at = datetime.now(timezone.utc)
                if record.status == "PENDING":
                    record.failure_code = FailureCode.EXTERNAL_STATE_UNCERTAIN.value
                    record.failure_message = "Remote state remains uncertain; no write was replayed."
                DomainOutbox.append(
                    record_db,
                    tenant_id=tenant_id,
                    aggregate_type="WORK_ITEM",
                    aggregate_id=work_id,
                    event_type="EXTERNAL_STATE_RECONCILED" if record.status == "COMPLETED" else "EXTERNAL_STATE_STILL_UNCERTAIN",
                    deduplication_key=f"work:{work_id}:reconcile:{record.attempt_count}:{state.value}",
                    payload={"state": state.value, **outcome_detail},
                )
                AuditLedger.append(
                    record_db,
                    tenant_id=tenant_id,
                    event_type="EXTERNAL_STATE_RECONCILIATION",
                    resource_type="WORK_ITEM",
                    resource_id=work_id,
                    payload={"state": state.value, **outcome_detail},
                )
                TelemetryRecorder.record(
                    record_db,
                    tenant_id=tenant_id,
                    work_item_id=work_id,
                    metric_name="external.reconciliation",
                    value=1.0,
                    unit="attempt",
                    dimensions={"work_kind": work_kind, "result": outcome_detail["reconciliation"]},
                )
                record_db.commit()
                reconciled += 1
            except Exception as exc:
                record_db.rollback()
                if record_id is not None:
                    try:
                        record = record_db.query(ReconciliationRecordModel).filter(
                            ReconciliationRecordModel.id == record_id,
                            ReconciliationRecordModel.lease_owner == cls._worker_prefix,
                        ).with_for_update().first()
                        if record is not None:
                            record.status = "PENDING"
                            record.lease_owner = None
                            record.lease_expires_at = None
                            record.failure_code = "RECONCILIATION_CHECK_FAILED"
                            record.failure_message = "The read-only provider reconciliation check failed."
                            record.next_attempt_at = datetime.now(timezone.utc) + timedelta(
                                seconds=min(3600, 30 * (2 ** min(record.attempt_count, 7)))
                            )
                            record.updated_at = datetime.now(timezone.utc)
                            record_db.commit()
                    except Exception:
                        record_db.rollback()
                logger.warning("External reconciliation failed for work %s: %s", work_id, type(exc).__name__)
            finally:
                record_db.close()
        return reconciled

    @classmethod
    def _claim_reconciliation_record(
        cls,
        db,
        *,
        tenant_id: str,
        work_id: str,
        attempt_identity: str,
    ) -> str | None:
        """Acquire one crash-recoverable ownership lease for a remote state check."""
        from app.models.platform import ReconciliationRecordModel

        now = datetime.now(timezone.utc)
        query = db.query(ReconciliationRecordModel).filter(
            ReconciliationRecordModel.tenant_id == tenant_id,
            ReconciliationRecordModel.resource_type == "WORK_ITEM",
            ReconciliationRecordModel.resource_id == work_id,
            ReconciliationRecordModel.operation == "EXTERNAL_SIDE_EFFECT",
        )
        if db.get_bind().dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        record = query.first()
        if record is None:
            record = ReconciliationRecordModel(
                tenant_id=tenant_id,
                resource_type="WORK_ITEM",
                resource_id=work_id,
                operation="EXTERNAL_SIDE_EFFECT",
            )
            db.add(record)
        else:
            if record.status == "COMPLETED" and record.expected_digest == attempt_identity:
                db.rollback()
                return None
            lease_active = (
                record.status == "RUNNING"
                and record.lease_expires_at is not None
                and _aware(record.lease_expires_at) > now
            )
            if lease_active:
                db.rollback()
                return None
            if record.status == "PENDING" and _aware(record.next_attempt_at) > now:
                db.rollback()
                return None

        record.expected_digest = attempt_identity
        record.status = "RUNNING"
        record.attempt_count = int(record.attempt_count or 0) + 1
        record.lease_owner = cls._worker_prefix
        record.lease_expires_at = now + timedelta(
            seconds=max(30, get_settings().EXECUTION_LEASE_SECONDS)
        )
        record.next_attempt_at = now
        record.failure_code = None
        record.failure_message = None
        record.completed_at = None
        record.updated_at = now
        try:
            db.commit()
        except IntegrityError:
            # Another host won first-record creation; its lease owns this sweep.
            db.rollback()
            return None
        return str(record.id)

    @classmethod
    async def _run_claim(cls, claim: ClaimedWork) -> None:
        from app.execution.context import bind_claim, reset_claim

        control = _AttemptControl()
        await asyncio.to_thread(cls._start_transition, claim)
        context_token = bind_claim(claim)
        try:
            handler_task = asyncio.create_task(cls._execute_domain(claim))
        finally:
            reset_claim(context_token)
        heartbeat_task = asyncio.create_task(cls._heartbeat_loop(claim, handler_task, control))
        try:
            result = await handler_task
            if control.cancel_requested:
                state = await asyncio.to_thread(cls._acknowledge_cancel, claim)
                if state == ExecutionState.CANCELLED:
                    await asyncio.to_thread(cls._mark_domain_cancelled, claim)
                elif state == ExecutionState.FAILED:
                    await asyncio.to_thread(cls._mark_external_state_uncertain, claim)
                return
            if control.budget_stopped or control.lease_lost:
                return
            await asyncio.to_thread(cls._complete_transition, claim, result)
        except asyncio.CancelledError:
            if control.cancel_requested:
                state = await asyncio.to_thread(cls._acknowledge_cancel, claim)
                if state == ExecutionState.CANCELLED:
                    await asyncio.to_thread(cls._mark_domain_cancelled, claim)
                else:
                    await asyncio.to_thread(cls._mark_external_state_uncertain, claim)
                return
            if control.budget_stopped or control.lease_lost:
                return
            # Shutdown deliberately leaves the SQL lease active. A later worker
            # recovers it after expiry instead of claiming false completion.
            raise
        except DomainWorkFailed as exc:
            logger.warning(
                "Domain work %s failed with %s (retryable=%s): %s",
                claim.work_item_id,
                exc.code.value,
                exc.retryable,
                exc.public_message,
            )
            await asyncio.to_thread(cls._fail_transition, claim, exc)
        except Exception as exc:
            logger.exception("Unhandled domain handler failure for work %s", claim.work_item_id)
            failure = DomainWorkFailed(
                FailureCode.INTERNAL_INVARIANT_VIOLATION,
                "The work attempt failed safely; inspect diagnostics using the request ID.",
                retryable=False,
            )
            await asyncio.to_thread(cls._fail_transition, claim, failure, type(exc).__name__)
        finally:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)

    @classmethod
    async def _heartbeat_loop(
        cls,
        claim: ClaimedWork,
        handler_task: asyncio.Task,
        control: _AttemptControl,
    ) -> None:
        interval = max(1.0, get_settings().EXECUTION_LEASE_SECONDS / 3.0)
        while not handler_task.done():
            await asyncio.sleep(interval)
            try:
                result = await asyncio.to_thread(cls._heartbeat, claim)
            except LeaseLost:
                control.lease_lost = True
                handler_task.cancel()
                return
            if result.cancel_requested:
                control.cancel_requested = True
                handler_task.cancel()
                return
            if not result.active or result.budget_exhausted:
                control.budget_stopped = True
                handler_task.cancel()
                return

    @classmethod
    def _engine(cls, db) -> DurableExecutionEngine:
        return DurableExecutionEngine(
            db,
            lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
            auto_commit=False,
        )

    @classmethod
    def _start_transition(cls, claim: ClaimedWork) -> None:
        db = SessionLocal()
        try:
            engine = cls._engine(db)
            engine.start(claim.work_item_id, claim.lease_token)
            work = db.query(WorkItemModel).filter(WorkItemModel.id == claim.work_item_id).one()
            queue_wait = max(
                0.0,
                (datetime.now(timezone.utc) - _aware(work.created_at)).total_seconds(),
            )
            DomainOutbox.append(
                db,
                tenant_id=claim.tenant_id,
                aggregate_type="WORK_ITEM",
                aggregate_id=claim.work_item_id,
                event_type="WORK_ATTEMPT_STARTED",
                deduplication_key=f"work:{claim.work_item_id}:attempt:{claim.attempt_number}:started",
                payload={"attempt_id": claim.attempt_id, "attempt_number": claim.attempt_number},
            )
            AuditLedger.append(
                db,
                tenant_id=claim.tenant_id,
                event_type="LEASE_TRANSITION",
                resource_type="WORK_ITEM",
                resource_id=claim.work_item_id,
                state_digest=work.request_digest,
                payload={"state": "RUNNING", "attempt_number": claim.attempt_number},
            )
            TelemetryRecorder.record(
                db,
                tenant_id=claim.tenant_id,
                request_id=work.request_id,
                work_item_id=claim.work_item_id,
                metric_name="job.queue_wait",
                value=queue_wait,
                unit="seconds",
                dimensions={"work_kind": claim.work_kind.value},
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @classmethod
    def _heartbeat(cls, claim: ClaimedWork):
        db = SessionLocal()
        try:
            return DurableExecutionEngine(
                db,
                lease_seconds=get_settings().EXECUTION_LEASE_SECONDS,
            ).heartbeat(claim.work_item_id, claim.lease_token)
        finally:
            db.close()

    @classmethod
    def _complete_transition(cls, claim: ClaimedWork, result: WorkHandlerResult) -> None:
        db = SessionLocal()
        try:
            engine = cls._engine(db)
            engine.complete(
                claim.work_item_id,
                claim.lease_token,
                outcome=result.outcome,
                coverage_summary=result.coverage_summary,
                coverage_artifact_id=result.coverage_artifact_id,
                output_artifact_id=result.output_artifact_id,
                outcome_detail=result.outcome_detail,
            )
            work = db.query(WorkItemModel).filter(WorkItemModel.id == claim.work_item_id).one()
            DomainOutbox.append(
                db,
                tenant_id=claim.tenant_id,
                aggregate_type="WORK_ITEM",
                aggregate_id=claim.work_item_id,
                event_type="WORK_ITEM_SUCCEEDED",
                deduplication_key=f"work:{claim.work_item_id}:terminal",
                payload={"domain_outcome": result.outcome.value, "work_kind": claim.work_kind.value},
            )
            AuditLedger.append(
                db,
                tenant_id=claim.tenant_id,
                event_type="JOB_COMPLETED",
                resource_type="WORK_ITEM",
                resource_id=claim.work_item_id,
                state_digest=work.request_digest,
                artifact_digest=None,
                payload={"domain_outcome": result.outcome.value},
            )
            if work.started_at is not None:
                TelemetryRecorder.record(
                    db,
                    tenant_id=claim.tenant_id,
                    request_id=work.request_id,
                    work_item_id=claim.work_item_id,
                    metric_name="job.stage_duration",
                    value=max(0.0, (datetime.now(timezone.utc) - _aware(work.started_at)).total_seconds()),
                    unit="seconds",
                    dimensions={"work_kind": claim.work_kind.value, "outcome": result.outcome.value},
                )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @classmethod
    def _fail_transition(
        cls,
        claim: ClaimedWork,
        failure: DomainWorkFailed,
        internal_failure_name: str | None = None,
    ) -> None:
        db = SessionLocal()
        try:
            digest = None
            if internal_failure_name:
                import hashlib

                digest = hashlib.sha256(internal_failure_name.encode("utf-8")).hexdigest()
            engine = cls._engine(db)
            next_state = engine.fail(
                claim.work_item_id,
                claim.lease_token,
                code=failure.code,
                public_message=failure.public_message,
                retryable=failure.retryable,
                internal_detail_digest=digest,
                retry_delay_seconds=min(30, 2 ** min(claim.attempt_number, 5)),
                may_have_started_external_effect=failure.may_have_started_external_effect,
            )
            work = db.query(WorkItemModel).filter(WorkItemModel.id == claim.work_item_id).one()
            DomainOutbox.append(
                db,
                tenant_id=claim.tenant_id,
                aggregate_type="WORK_ITEM",
                aggregate_id=claim.work_item_id,
                event_type="WORK_ATTEMPT_FAILED",
                deduplication_key=f"work:{claim.work_item_id}:attempt:{claim.attempt_number}:failed",
                payload={"failure_code": failure.code.value, "next_state": next_state.value},
            )
            AuditLedger.append(
                db,
                tenant_id=claim.tenant_id,
                event_type="JOB_ATTEMPT_FAILED",
                resource_type="WORK_ITEM",
                resource_id=claim.work_item_id,
                state_digest=work.request_digest,
                payload={"failure_code": failure.code.value, "next_state": next_state.value},
            )
            TelemetryRecorder.record(
                db,
                tenant_id=claim.tenant_id,
                request_id=work.request_id,
                work_item_id=claim.work_item_id,
                metric_name="job.retry_count",
                value=float(claim.attempt_number - 1),
                unit="count",
                dimensions={"work_kind": claim.work_kind.value, "next_state": next_state.value},
            )
            db.commit()
        except LeaseLost:
            db.rollback()
            logger.warning("Lease was lost before failure finalization for %s", claim.work_item_id)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @classmethod
    def _acknowledge_cancel(cls, claim: ClaimedWork) -> ExecutionState | None:
        db = SessionLocal()
        try:
            engine = cls._engine(db)
            next_state = engine.acknowledge_cancel(claim.work_item_id, claim.lease_token)
            event_type = {
                ExecutionState.FAILED: "EXTERNAL_STATE_RECONCILIATION_REQUIRED",
                ExecutionState.SUCCEEDED: "WORK_ITEM_COMPLETED_BEFORE_LATE_CANCEL",
                ExecutionState.CANCELLED: "WORK_ITEM_CANCELLED",
            }[next_state]
            audit_type = {
                ExecutionState.FAILED: "EXTERNAL_STATE_RECONCILIATION_REQUIRED",
                ExecutionState.SUCCEEDED: "JOB_COMPLETED_BEFORE_LATE_CANCEL",
                ExecutionState.CANCELLED: "JOB_CANCELLED",
            }[next_state]
            DomainOutbox.append(
                db,
                tenant_id=claim.tenant_id,
                aggregate_type="WORK_ITEM",
                aggregate_id=claim.work_item_id,
                event_type=event_type,
                deduplication_key=(
                    f"work:{claim.work_item_id}:reconciliation-required"
                    if next_state == ExecutionState.FAILED
                    else f"work:{claim.work_item_id}:{next_state.value.lower()}"
                ),
                payload={"attempt_number": claim.attempt_number, "state": next_state.value},
            )
            AuditLedger.append(
                db,
                tenant_id=claim.tenant_id,
                event_type=audit_type,
                resource_type="WORK_ITEM",
                resource_id=claim.work_item_id,
                payload={"attempt_number": claim.attempt_number},
            )
            db.commit()
            return next_state
        except LeaseLost:
            db.rollback()
            return None
        finally:
            db.close()

    @staticmethod
    def _mark_external_state_uncertain(claim: ClaimedWork) -> None:
        db = SessionLocal()
        try:
            if claim.work_kind == WorkKind.GITHUB_DELIVERY:
                from app.models.delivery import DeliveryModel

                model = db.query(DeliveryModel).filter(DeliveryModel.id == claim.resource_id).first()
                if model is not None and model.status != "PR_CREATED":
                    model.status = "FAILED"
                    model.failure_code = FailureCode.EXTERNAL_STATE_UNCERTAIN.value
                    model.failure_message = "Remote GitHub state requires reconciliation."
                    model.completed_at = datetime.now(timezone.utc)
            elif claim.work_kind == WorkKind.REVIEW_PUBLICATION:
                from app.models.review_publication import PullRequestReviewPublicationModel

                model = db.query(PullRequestReviewPublicationModel).filter(
                    PullRequestReviewPublicationModel.id == claim.resource_id
                ).first()
                if model is not None and model.status != "PUBLISHED":
                    model.failure_code = FailureCode.EXTERNAL_STATE_UNCERTAIN.value
                    model.failure_message = "Remote GitHub state requires reconciliation."
            db.commit()
        finally:
            db.close()

    @staticmethod
    def _mark_domain_cancelled(claim: ClaimedWork) -> None:
        db = SessionLocal()
        try:
            if claim.work_kind == WorkKind.SCAN:
                from app.models.scan import ScanModel

                model = db.query(ScanModel).filter(ScanModel.id == claim.resource_id).first()
                if model is not None and model.status not in ("COMPLETED", "FAILED"):
                    model.status = "FAILED"
                    model.completed_at = datetime.now(timezone.utc)
                    metadata = dict(model.model_metadata or {})
                    metadata["failure_code"] = FailureCode.CANCELLED_BY_USER.value
                    model.model_metadata = metadata
            elif claim.work_kind == WorkKind.CHANGE_ANALYSIS:
                from app.models.change_analysis import ChangeAnalysisModel

                model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == claim.resource_id).first()
                if model is not None and model.status not in ("COMPLETED", "FAILED"):
                    model.status = "FAILED"
                    model.failure_code = FailureCode.CANCELLED_BY_USER.value
                    model.failure_message = "The analysis was cancelled by the user."
                    model.completed_at = datetime.now(timezone.utc)
            elif claim.work_kind == WorkKind.REPORT_GENERATION:
                from app.models.report import ReportModel

                model = db.query(ReportModel).filter(ReportModel.id == claim.resource_id).first()
                if model is not None and model.status != "READY":
                    model.status = "FAILED"
                    model.failure_code = FailureCode.CANCELLED_BY_USER.value
                    model.failure_message = "The report was cancelled by the user."
                    model.retryable = False
            db.commit()
        finally:
            db.close()

    @classmethod
    async def _execute_domain(cls, claim: ClaimedWork) -> WorkHandlerResult:
        if claim.work_kind == WorkKind.SCAN:
            from app.api.routes.scans import execute_background_scan

            payload = await asyncio.to_thread(cls._scan_payload, claim.resource_id)
            await execute_background_scan(
                scan_id=claim.resource_id,
                repo_url=payload[0],
                branch=payload[1],
            )
            return await asyncio.to_thread(cls._scan_result, claim.resource_id)

        if claim.work_kind == WorkKind.CHANGE_ANALYSIS:
            from app.analysis.workflow import execute_background_change_analysis

            await execute_background_change_analysis(analysis_id=claim.resource_id)
            return await asyncio.to_thread(cls._change_result, claim.resource_id)

        if claim.work_kind == WorkKind.REPORT_GENERATION:
            from app.services.report_generation import ReportGenerationService

            await asyncio.to_thread(
                ReportGenerationService.execute_report_under_work_item,
                claim.resource_id,
            )
            return await asyncio.to_thread(cls._report_result, claim.resource_id)

        if claim.work_kind in {WorkKind.RESEARCH, WorkKind.FIX_PLAN, WorkKind.PATCH_GENERATION}:
            from app.ingestion.snapshot import SnapshotError
            from app.remediation.service import (
                RemediationExecutionService,
                RemediationInvariantError,
                RemediationModelOutputError,
            )

            try:
                result = await RemediationExecutionService().execute(claim.work_item_id)
            except SnapshotError as exc:
                raise DomainWorkFailed(
                    FailureCode.REPOSITORY_UNAVAILABLE,
                    "The exact repository revision could not be materialized for remediation.",
                    retryable=True,
                ) from exc
            except RemediationModelOutputError as exc:
                raise DomainWorkFailed(
                    FailureCode.MODEL_INVALID_OUTPUT,
                    str(exc),
                    retryable=False,
                ) from exc
            except RemediationInvariantError as exc:
                raise DomainWorkFailed(
                    FailureCode.INTERNAL_INVARIANT_VIOLATION,
                    str(exc),
                    retryable=False,
                ) from exc
            return WorkHandlerResult(
                outcome=DomainOutcome.COMPLETE,
                coverage_summary={
                    "schema_version": "1.0",
                    "outcome": "COMPLETE",
                    "units": [{"component": result.result_kind.lower(), "state": "SUCCESSFULLY_ANALYZED"}],
                    "explanation": "Remediation output was generated against the pinned revision and published as an immutable artifact.",
                },
                output_artifact_id=result.artifact_id,
                outcome_detail={
                    "result_kind": result.result_kind,
                    "patch_id": result.patch_id,
                    "artifact_digest": result.artifact_digest,
                    "artifact_reused": result.reused,
                },
            )

        if claim.work_kind == WorkKind.GITHUB_DELIVERY:
            from app.delivery.service import DeliveryService
            from app.execution.context import mark_current_side_effect_completed
            from app.models.delivery import DeliveryModel
            from app.models.scan import ScanModel
            from app.schemas.delivery import DeliveryRequest

            await asyncio.to_thread(cls._assert_github_write_authorized, claim)
            db = SessionLocal()
            try:
                delivery = (
                    db.query(DeliveryModel)
                    .join(ScanModel, ScanModel.id == DeliveryModel.scan_id)
                    .filter(
                        DeliveryModel.id == claim.resource_id,
                        ScanModel.owner_user_id == claim.tenant_id,
                    )
                    .first()
                )
                if delivery is None:
                    raise DomainWorkFailed(
                        FailureCode.INTERNAL_INVARIANT_VIOLATION,
                        "The delivery resource is missing or violates its tenant boundary.",
                        retryable=False,
                    )
                result = await DeliveryService().deliver_patch(
                    db=db,
                    patch_id=delivery.patch_id,
                    payload=DeliveryRequest(
                        requested_by=delivery.requested_by,
                        notes=delivery.request_notes,
                    ),
                )
                if result.status == "PR_CREATED":
                    mark_current_side_effect_completed(
                        db=db,
                        external_operation_id=f"github-pr:{result.repository_owner}/{result.repository_name}:{result.pr_number}",
                    )
                    db.commit()
                    return WorkHandlerResult(
                        outcome=DomainOutcome.COMPLETE,
                        coverage_summary={
                            "schema_version": "1.0",
                            "outcome": "COMPLETE",
                            "units": [{"component": "github_delivery", "state": "SUCCESSFULLY_ANALYZED"}],
                            "explanation": "The approved patch was delivered or reconciled to one GitHub pull request.",
                        },
                        outcome_detail={
                            "delivery_id": result.id,
                            "pr_number": result.pr_number,
                            "pr_url": result.pr_url,
                            "reconciliation_occurred": bool(result.reconciliation_occurred),
                        },
                    )
                if result.status == "BLOCKED":
                    mark_current_side_effect_completed(
                        db=db,
                        external_operation_id=f"no-effect:delivery-blocked:{result.id}",
                    )
                    db.commit()
                    return WorkHandlerResult(
                        outcome=DomainOutcome.DEGRADED,
                        coverage_summary={
                            "schema_version": "1.0",
                            "outcome": "DEGRADED",
                            "units": [{"component": "github_delivery", "state": "SKIPPED"}],
                            "explanation": "GitHub delivery was safely blocked before publication.",
                        },
                        outcome_detail={"delivery_id": result.id, "failure_code": result.failure_code},
                    )
                from app.models.execution import WorkAttemptModel

                attempt = db.query(WorkAttemptModel).filter(WorkAttemptModel.id == claim.attempt_id).first()
                external_started = bool(
                    attempt
                    and attempt.side_effect_started_at is not None
                    and attempt.side_effect_completed_at is None
                )
                failure_map = {
                    "GITHUB_RATE_LIMITED": FailureCode.PROVIDER_RATE_LIMITED,
                    "GITHUB_AUTH_FAILED": FailureCode.PROVIDER_AUTH_FAILURE,
                    "HEAD_BRANCH_COLLISION": FailureCode.INTERNAL_INVARIANT_VIOLATION,
                    "HEAD_BRANCH_SHA_MISMATCH": FailureCode.INTERNAL_INVARIANT_VIOLATION,
                    "TREE_BUILD_APPLY_FAILED": FailureCode.INTERNAL_INVARIANT_VIOLATION,
                }
                known_retryable = {
                    "DELIVERY_FAILED",
                    "LOCAL_STATE_PERSISTENCE_FAILED",
                    "GITHUB_RATE_LIMITED",
                }
                domain_code = failure_map.get(
                    result.failure_code or "",
                    FailureCode.PROVIDER_UNAVAILABLE,
                )
                raise DomainWorkFailed(
                    FailureCode.EXTERNAL_STATE_UNCERTAIN if external_started else domain_code,
                    (
                        "GitHub delivery may have changed remote state and requires reconciliation."
                        if external_started
                        else f"GitHub delivery failed with {result.failure_code or 'DELIVERY_FAILED'}."
                    ),
                    retryable=not external_started and (result.failure_code or "DELIVERY_FAILED") in known_retryable,
                    may_have_started_external_effect=external_started,
                )
            finally:
                db.close()

        if claim.work_kind == WorkKind.REVIEW_PUBLICATION:
            from app.execution.context import mark_current_side_effect_completed
            from app.models.change_analysis import ChangeAnalysisModel
            from app.models.execution import WorkAttemptModel
            from app.models.review_publication import PullRequestReviewPublicationModel
            from app.schemas.review_publication import ReviewPublicationError
            from app.services.review_publication_service import ReviewPublicationService

            await asyncio.to_thread(cls._assert_github_write_authorized, claim)
            db = SessionLocal()
            try:
                publication = (
                    db.query(PullRequestReviewPublicationModel)
                    .join(ChangeAnalysisModel, ChangeAnalysisModel.id == PullRequestReviewPublicationModel.analysis_id)
                    .filter(
                        PullRequestReviewPublicationModel.id == claim.resource_id,
                        ChangeAnalysisModel.owner_user_id == claim.tenant_id,
                    )
                    .first()
                )
                if publication is None or not publication.preview_digest:
                    raise DomainWorkFailed(
                        FailureCode.INTERNAL_INVARIANT_VIOLATION,
                        "The review publication is missing or violates its tenant boundary.",
                        retryable=False,
                    )
                try:
                    result = await ReviewPublicationService(db=db).publish_review(
                        UUID(publication.analysis_id),
                        publication.preview_digest,
                    )
                except ReviewPublicationError as exc:
                    db.expire_all()
                    current = db.query(PullRequestReviewPublicationModel).filter(
                        PullRequestReviewPublicationModel.id == claim.resource_id
                    ).first()
                    if current is not None and current.status == "BLOCKED":
                        mark_current_side_effect_completed(
                            db=db,
                            external_operation_id=f"no-effect:review-blocked:{current.id}",
                        )
                        db.commit()
                        return WorkHandlerResult(
                            outcome=DomainOutcome.DEGRADED,
                            coverage_summary={
                                "schema_version": "1.0",
                                "outcome": "DEGRADED",
                                "units": [{"component": "github_review_publication", "state": "SKIPPED"}],
                                "explanation": "Review publication was safely blocked by final drift validation.",
                            },
                            outcome_detail={"publication_id": current.id, "failure_code": current.failure_code},
                        )
                    attempt = db.query(WorkAttemptModel).filter(WorkAttemptModel.id == claim.attempt_id).first()
                    external_started = bool(
                        attempt
                        and attempt.side_effect_started_at is not None
                        and attempt.side_effect_completed_at is None
                    )
                    failure_map = {
                        "GITHUB_RATE_LIMITED": FailureCode.PROVIDER_RATE_LIMITED,
                        "GITHUB_AUTH_FAILED": FailureCode.PROVIDER_AUTH_FAILURE,
                        "GITHUB_REVIEW_WRITE_DISABLED": FailureCode.PROVIDER_UNAVAILABLE,
                        "GITHUB_REVIEW_STATE_UNCERTAIN": FailureCode.EXTERNAL_STATE_UNCERTAIN,
                    }
                    code = failure_map.get(exc.error_code, FailureCode.PROVIDER_UNAVAILABLE)
                    retryable = exc.error_code in {"GITHUB_RATE_LIMITED", "GITHUB_REVIEW_CREATE_FAILED"}
                    raise DomainWorkFailed(
                        FailureCode.EXTERNAL_STATE_UNCERTAIN if external_started else code,
                        (
                            "GitHub review state requires reconciliation."
                            if external_started
                            else "GitHub review publication failed before a remote write."
                        ),
                        retryable=retryable and not external_started,
                        may_have_started_external_effect=external_started,
                    ) from exc
                mark_current_side_effect_completed(
                    db=db,
                    external_operation_id=f"github-review:{result.github_review_id}",
                )
                db.commit()
                return WorkHandlerResult(
                    outcome=DomainOutcome.COMPLETE,
                    coverage_summary={
                        "schema_version": "1.0",
                        "outcome": "COMPLETE",
                        "units": [{"component": "github_review_publication", "state": "SUCCESSFULLY_ANALYZED"}],
                        "explanation": "The approved review was published or reconciled exactly once.",
                    },
                    outcome_detail={
                        "publication_id": result.id,
                        "github_review_id": result.github_review_id,
                        "github_review_url": result.github_review_url,
                        "reconciliation_occurred": bool(result.reconciliation_occurred),
                    },
                )
            finally:
                db.close()

        raise DomainWorkFailed(
            FailureCode.INTERNAL_INVARIANT_VIOLATION,
            f"No durable handler is registered for {claim.work_kind.value}.",
            retryable=False,
        )

    @staticmethod
    def _assert_github_write_authorized(claim: ClaimedWork) -> None:
        from app.governance.policies import OperationalPolicy, OperationalPolicyService
        from app.models.platform import OperationalPolicyModel

        db = SessionLocal()
        try:
            pinned = db.query(OperationalPolicyModel).filter(
                OperationalPolicyModel.id == claim.policy_snapshot_id
            ).first()
            active = OperationalPolicyService.active(db, claim.tenant_id)
            if pinned is None or active is None:
                raise DomainWorkFailed(
                    FailureCode.INTERNAL_INVARIANT_VIOLATION,
                    "The GitHub write policy snapshot cannot be resolved.",
                    retryable=False,
                )
            pinned_policy = OperationalPolicy.model_validate(pinned.policy_payload)
            active_policy = OperationalPolicy.model_validate(active.policy_payload)
            if not pinned_policy.github_writes_enabled or not active_policy.github_writes_enabled:
                raise DomainWorkFailed(
                    FailureCode.PROVIDER_UNAVAILABLE,
                    "GitHub writes are disabled by operational policy.",
                    retryable=False,
                )
        finally:
            db.close()

    @staticmethod
    def _scan_payload(scan_id: str) -> tuple[str, str | None]:
        from app.models.scan import ScanModel

        db = SessionLocal()
        try:
            scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if scan is None:
                raise DomainWorkFailed(
                    FailureCode.INTERNAL_INVARIANT_VIOLATION,
                    "The scan resource no longer exists.",
                    retryable=False,
                )
            metadata = scan.model_metadata if isinstance(scan.model_metadata, dict) else {}
            return scan.repository_url, metadata.get("requested_branch") or scan.branch
        finally:
            db.close()

    @staticmethod
    def _scan_result(scan_id: str) -> WorkHandlerResult:
        from app.models.scan import ScanModel

        db = SessionLocal()
        try:
            scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if scan is None or scan.status != "COMPLETED":
                raise DomainWorkFailed(
                    FailureCode.REPOSITORY_UNAVAILABLE,
                    "Repository analysis did not complete successfully.",
                    retryable=True,
                )
            metadata = scan.model_metadata if isinstance(scan.model_metadata, dict) else {}
            coverage = AnalysisCoverage.from_analyzers(metadata.get("scanner_coverage") or [])
            if not coverage.units:
                coverage = AnalysisCoverage.from_units([
                    CoverageUnit(component="analysis_workflow", state=CoverageState.SUCCESSFULLY_ANALYZED)
                ])
            coverage_payload = coverage.model_dump(mode="json")
            return WorkHandlerResult(
                outcome=DomainOutcome(coverage.outcome.value),
                coverage_summary=coverage_payload,
                coverage_artifact_id=metadata.get("coverage_artifact_id"),
                outcome_detail={"scan_id": scan.id, "commit_sha": scan.commit_hash},
            )
        finally:
            db.close()

    @staticmethod
    def _change_result(analysis_id: str) -> WorkHandlerResult:
        from app.models.change_analysis import ChangeAnalysisModel

        db = SessionLocal()
        try:
            model = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id).first()
            if model is None or model.status != "COMPLETED":
                raise DomainWorkFailed(
                    FailureCode.REPOSITORY_UNAVAILABLE,
                    "Change analysis did not complete successfully.",
                    retryable=True,
                )
            metadata = model.model_metadata if isinstance(model.model_metadata, dict) else {}
            units = [
                CoverageUnit(
                    component="structural_diff",
                    state=(
                        CoverageState.SUCCESSFULLY_ANALYZED
                        if metadata.get("diff_result") is not None
                        else CoverageState.FAILED
                    ),
                ),
                CoverageUnit(
                    component="blast_radius",
                    state=(
                        CoverageState.SUCCESSFULLY_ANALYZED
                        if metadata.get("blast_radius") is not None
                        else CoverageState.SKIPPED
                    ),
                ),
            ]
            coverage = AnalysisCoverage.from_units(units)
            return WorkHandlerResult(
                outcome=DomainOutcome(coverage.outcome.value),
                coverage_summary=coverage.model_dump(mode="json"),
                coverage_artifact_id=metadata.get("coverage_artifact_id"),
                outcome_detail={"change_analysis_id": model.id, "risk_level": model.risk_level},
            )
        finally:
            db.close()

    @staticmethod
    def _report_result(report_id: str) -> WorkHandlerResult:
        from app.models.report import ReportModel

        db = SessionLocal()
        try:
            report = db.query(ReportModel).filter(ReportModel.id == report_id).first()
            if report is None or report.status != "READY":
                raise DomainWorkFailed(
                    FailureCode.INTERNAL_INVARIANT_VIOLATION,
                    "Report rendering did not complete successfully.",
                    retryable=bool(report and report.retryable),
                )
            return WorkHandlerResult(
                outcome=DomainOutcome.COMPLETE,
                coverage_summary={
                    "schema_version": "1.0",
                    "outcome": DomainOutcome.COMPLETE.value,
                    "units": [{"component": "report_render", "state": "SUCCESSFULLY_ANALYZED"}],
                    "explanation": "The immutable report document was rendered and digest-verified.",
                },
                coverage_artifact_id=report.coverage_artifact_id,
                output_artifact_id=(
                    report.artifact_lineage.get("pdf_artifact_id")
                    if isinstance(report.artifact_lineage, dict)
                    else None
                ),
                outcome_detail={
                    "report_id": report.id,
                    "pdf_digest": report.pdf_digest,
                    "page_count": report.page_count,
                },
            )
        finally:
            db.close()

    @classmethod
    def reconcile_orphaned_domain_work(cls) -> int:
        """Backfill canonical work items for pre-migration unfinished resources."""
        db = SessionLocal()
        created = 0
        try:
            inspector = inspect(db.get_bind())
            if not inspector.has_table("execution_work_items"):
                return 0
            service = WorkSubmissionService()
            settings = get_settings()

            from app.models.scan import ScanModel

            scans = db.query(ScanModel).filter(ScanModel.status.in_(["PENDING", "RUNNING"])).all()
            for scan in scans:
                if not scan.owner_user_id or cls._has_work(db, WorkKind.SCAN, scan.id):
                    continue
                service.submit(
                    db,
                    tenant_id=scan.owner_user_id,
                    actor_id=scan.owner_user_id,
                    request_id=f"startup-recovery:{scan.id}",
                    work_kind=WorkKind.SCAN,
                    resource_type="SCAN",
                    resource_id=scan.id,
                    request_payload={
                        "repository_url": scan.repository_url,
                        "branch": scan.branch,
                        "recovered": True,
                    },
                    idempotency_key=f"scan:{scan.id}",
                    resource_profile=ResourceProfile.SMALL_REPO_SCAN,
                    budget=RequestBudget(
                        max_wall_clock_seconds=settings.MAX_SCAN_DURATION_SECONDS,
                        max_analyzer_seconds=settings.MAX_SCAN_DURATION_SECONDS,
                        max_ai_calls=12,
                        max_input_tokens=500_000,
                        max_output_tokens=100_000,
                        max_escalation_tier=2,
                        max_retrieval_context_tokens=250_000,
                    ),
                    allow_when_paused=True,
                )
                created += 1

            from app.models.change_analysis import ChangeAnalysisModel

            changes = db.query(ChangeAnalysisModel).filter(
                ChangeAnalysisModel.status.notin_(["COMPLETED", "FAILED"])
            ).all()
            for model in changes:
                if not model.owner_user_id or cls._has_work(db, WorkKind.CHANGE_ANALYSIS, model.id):
                    continue
                service.submit(
                    db,
                    tenant_id=model.owner_user_id,
                    actor_id=model.owner_user_id,
                    request_id=f"startup-recovery:{model.id}",
                    work_kind=WorkKind.CHANGE_ANALYSIS,
                    resource_type="CHANGE_ANALYSIS",
                    resource_id=model.id,
                    request_payload={
                        "repository_url": model.repository_url,
                        "base_commit_sha": model.base_commit_sha,
                        "head_commit_sha": model.head_commit_sha,
                        "recovered": True,
                    },
                    idempotency_key=f"change-analysis:{model.id}",
                    resource_profile=ResourceProfile.CHANGE_ANALYSIS,
                    budget=RequestBudget(max_wall_clock_seconds=settings.MAX_SCAN_DURATION_SECONDS),
                    allow_when_paused=True,
                )
                created += 1

            from app.models.report import ReportModel

            reports = db.query(ReportModel).filter(
                ReportModel.status.in_(["REQUESTED", "ASSEMBLING", "RENDERING"])
            ).all()
            for report in reports:
                if cls._has_work(db, WorkKind.REPORT_GENERATION, report.id):
                    continue
                # Legacy report leases are no longer authoritative.
                report.status = "REQUESTED"
                report.lease_owner = None
                report.lease_expires_at = None
                service.submit(
                    db,
                    tenant_id=report.owner_user_id,
                    actor_id=report.owner_user_id,
                    request_id=f"startup-recovery:{report.id}",
                    work_kind=WorkKind.REPORT_GENERATION,
                    resource_type="REPORT",
                    resource_id=report.id,
                    request_payload={"report_id": report.id, "input_digest": report.input_digest},
                    idempotency_key=f"report:{report.input_digest}",
                    resource_profile=ResourceProfile.REPORT_RENDER,
                    budget=RequestBudget(
                        max_wall_clock_seconds=settings.REPORT_LEASE_SECONDS,
                        max_report_bytes=settings.REPORT_MAX_PDF_BYTES,
                        max_report_pages=settings.REPORT_MAX_PDF_PAGES,
                    ),
                    max_attempts=settings.REPORT_MAX_ATTEMPTS,
                    allow_when_paused=True,
                )
                created += 1
            db.commit()
            return created
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _has_work(db, kind: WorkKind, resource_id: str) -> bool:
        return db.query(WorkItemModel.id).filter(
            WorkItemModel.work_kind == kind.value,
            WorkItemModel.resource_id == resource_id,
        ).first() is not None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


__all__ = ["DomainWorkFailed", "DurableWorkDispatcher", "WorkHandlerResult"]
