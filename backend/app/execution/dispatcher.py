"""Single database-authoritative dispatcher for all long-running RepoLens work."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import os
import socket
import time
from typing import Any
from uuid import uuid4

from sqlalchemy import inspect

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.execution.application import WorkSubmissionService
from app.execution.engine import DurableExecutionEngine
from app.execution.errors import LeaseLost
from app.execution.types import (
    ClaimedWork,
    DomainOutcome,
    FailureCode,
    RequestBudget,
    ResourceProfile,
    WorkKind,
)
from app.governance.events import AuditLedger, DomainOutbox
from app.governance.taxonomy import AnalysisCoverage, CoverageState, CoverageUnit
from app.governance.telemetry import TelemetryRecorder
from app.models.execution import WorkItemModel


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkHandlerResult:
    outcome: DomainOutcome
    coverage_summary: dict[str, Any]
    coverage_artifact_id: str | None = None
    output_artifact_id: str | None = None
    outcome_detail: dict[str, Any] = field(default_factory=dict)


class DomainWorkFailed(RuntimeError):
    def __init__(self, code: FailureCode, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message
        self.retryable = retryable


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
                await asyncio.to_thread(cls._acknowledge_cancel, claim)
                return
            if control.budget_stopped or control.lease_lost:
                return
            await asyncio.to_thread(cls._complete_transition, claim, result)
        except asyncio.CancelledError:
            if control.cancel_requested:
                await asyncio.to_thread(cls._mark_domain_cancelled, claim)
                await asyncio.to_thread(cls._acknowledge_cancel, claim)
                return
            if control.budget_stopped or control.lease_lost:
                return
            # Shutdown deliberately leaves the SQL lease active. A later worker
            # recovers it after expiry instead of claiming false completion.
            raise
        except DomainWorkFailed as exc:
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
    def _acknowledge_cancel(cls, claim: ClaimedWork) -> None:
        db = SessionLocal()
        try:
            engine = cls._engine(db)
            engine.acknowledge_cancel(claim.work_item_id, claim.lease_token)
            DomainOutbox.append(
                db,
                tenant_id=claim.tenant_id,
                aggregate_type="WORK_ITEM",
                aggregate_id=claim.work_item_id,
                event_type="WORK_ITEM_CANCELLED",
                deduplication_key=f"work:{claim.work_item_id}:cancelled",
                payload={"attempt_number": claim.attempt_number},
            )
            AuditLedger.append(
                db,
                tenant_id=claim.tenant_id,
                event_type="JOB_CANCELLED",
                resource_type="WORK_ITEM",
                resource_id=claim.work_item_id,
                payload={"attempt_number": claim.attempt_number},
            )
            db.commit()
        except LeaseLost:
            db.rollback()
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

        raise DomainWorkFailed(
            FailureCode.INTERNAL_INVARIANT_VIOLATION,
            f"No durable handler is registered for {claim.work_kind.value}.",
            retryable=False,
        )

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
