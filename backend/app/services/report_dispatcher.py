"""Bounded dispatcher and lease-expiry recovery for durable report resources."""

import asyncio
from datetime import datetime, timezone
import logging
import socket
from typing import Dict, List, Optional
from uuid import uuid4

from sqlalchemy import inspect, or_

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.report import ReportModel
from app.reporting.schemas import ReportStatus
from app.services.report_generation import ReportGenerationService


logger = logging.getLogger(__name__)
_active_tasks: Dict[str, asyncio.Task] = {}


class ReportDispatcher:
    _semaphore: Optional[asyncio.Semaphore] = None
    _recovery_task: Optional[asyncio.Task] = None
    _worker_prefix = f"{socket.gethostname()}:{uuid4()}"

    @classmethod
    def _limit(cls) -> asyncio.Semaphore:
        if cls._semaphore is None:
            cls._semaphore = asyncio.Semaphore(get_settings().REPORT_MAX_CONCURRENT_JOBS)
        return cls._semaphore

    @classmethod
    def is_active(cls, report_id: str) -> bool:
        task = _active_tasks.get(report_id)
        return bool(task and not task.done())

    @classmethod
    def dispatch_report(cls, report_id: str) -> asyncio.Task:
        if cls.is_active(report_id):
            return _active_tasks[report_id]

        async def runner() -> None:
            async with cls._limit():
                worker_id = f"{cls._worker_prefix}:{uuid4()}"
                await asyncio.to_thread(ReportGenerationService.execute_report, report_id, worker_id)

        task = asyncio.create_task(runner())
        _active_tasks[report_id] = task
        task.add_done_callback(lambda _: _active_tasks.pop(report_id, None))
        return task

    @classmethod
    def recoverable_report_ids(cls, limit: int = 100) -> List[str]:
        now = datetime.now(timezone.utc)
        settings = get_settings()
        db = SessionLocal()
        try:
            if not inspect(db.get_bind()).has_table("reports"):
                return []
            active_statuses = [
                ReportStatus.REQUESTED.value,
                ReportStatus.ASSEMBLING.value,
                ReportStatus.RENDERING.value,
            ]
            available_lease = or_(ReportModel.lease_owner.is_(None), ReportModel.lease_expires_at < now)
            db.query(ReportModel).filter(
                ReportModel.status.in_(active_statuses),
                available_lease,
                ReportModel.attempt_count >= settings.REPORT_MAX_ATTEMPTS,
            ).update(
                {
                    ReportModel.status: ReportStatus.FAILED.value,
                    ReportModel.retryable: False,
                    ReportModel.failure_code: "REPORT_ATTEMPTS_EXHAUSTED",
                    ReportModel.failure_message: "Report generation exhausted its bounded attempt budget.",
                    ReportModel.lease_owner: None,
                    ReportModel.lease_expires_at: None,
                    ReportModel.updated_at: now,
                },
                synchronize_session=False,
            )
            db.commit()
            return [
                row[0]
                for row in (
                    db.query(ReportModel.id)
                    .filter(
                        ReportModel.status.in_(active_statuses),
                        ReportModel.retryable.is_(True),
                        ReportModel.attempt_count < settings.REPORT_MAX_ATTEMPTS,
                        available_lease,
                    )
                    .order_by(ReportModel.requested_at.asc())
                    .limit(limit)
                    .all()
                )
            ]
        finally:
            db.close()

    @classmethod
    def start_recovery_loop(cls) -> None:
        if cls._recovery_task and not cls._recovery_task.done():
            return

        async def recover() -> None:
            interval = get_settings().REPORT_RECOVERY_INTERVAL_SECONDS
            while True:
                try:
                    for report_id in await asyncio.to_thread(cls.recoverable_report_ids):
                        cls.dispatch_report(report_id)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Report recovery sweep failed.")
                await asyncio.sleep(interval)

        cls._recovery_task = asyncio.create_task(recover())

    @classmethod
    def cancel_all(cls) -> None:
        if cls._recovery_task and not cls._recovery_task.done():
            cls._recovery_task.cancel()
        cls._recovery_task = None
        for task in list(_active_tasks.values()):
            if not task.done():
                task.cancel()
        _active_tasks.clear()
        cls._semaphore = None
