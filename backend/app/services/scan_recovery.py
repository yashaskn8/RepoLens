"""Durable scan dispatcher and startup recovery service.

Provides a canonical in-process task registry to prevent duplicate scan executions,
safely track active background scans, and recover/resume PENDING and RUNNING scans
upon application startup without requiring external queue infrastructure.

Note: This in-memory active task registry maintains execution state within a single
FastAPI/Uvicorn process. It guards against duplicate in-process dispatch and coordinates
process-level scan lifecycles. It is not a distributed multi-node queue.
"""

import asyncio
import logging
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.scan import ScanModel
from app.schemas.enums import ScanStatus

logger = logging.getLogger(__name__)

# Canonical in-process task registry: scan_id -> asyncio.Task
_active_scan_tasks: Dict[str, asyncio.Task] = {}


class ScanDispatcher:
    """Canonical in-process scan dispatcher and execution manager."""

    @classmethod
    def is_scan_active(cls, scan_id: str) -> bool:
        """Check whether a background execution task is currently active for the given scan_id."""
        task = _active_scan_tasks.get(str(scan_id))
        if task is None:
            return False
        return not task.done()

    @classmethod
    def cleanup_completed_task(cls, scan_id: str) -> None:
        """Remove finished or cancelled task from the active registry."""
        _active_scan_tasks.pop(str(scan_id), None)

    @classmethod
    def dispatch_scan(
        cls,
        scan_id: str,
        repo_url: str,
        branch: Optional[str] = None,
        checkpoint_db_path: Optional[str] = None,
    ) -> asyncio.Task:
        """Safely dispatch background scan execution through the canonical task registry.

        Guarantees:
        - Prevents duplicate concurrent execution of the same scan_id within the process.
        - Automatically unregisters task upon completion or failure.
        - Wraps execution within MAX_SCAN_DURATION_SECONDS global timeout boundary.
        """
        sid = str(scan_id)
        if cls.is_scan_active(sid):
            logger.warning(f"Scan '{sid}' is already actively executing in this process. Skipping duplicate dispatch.")
            return _active_scan_tasks[sid]

        # Import here to prevent circular imports with scans router
        from app.api.routes.scans import execute_background_scan

        async def _bounded_scan_runner() -> None:
            settings = get_settings()
            max_duration = getattr(settings, "MAX_SCAN_DURATION_SECONDS", 300)
            try:
                await asyncio.wait_for(
                    execute_background_scan(
                        scan_id=sid,
                        repo_url=repo_url,
                        branch=branch,
                        checkpoint_db_path=checkpoint_db_path,
                    ),
                    timeout=float(max_duration),
                )
            except asyncio.TimeoutError:
                logger.error(
                    f"Scan '{sid}' exceeded maximum global execution duration of {max_duration}s. Terminating scan."
                )
                from app.core.database import SessionLocal
                from datetime import datetime, timezone
                db = SessionLocal()
                try:
                    scan = db.query(ScanModel).filter(ScanModel.id == sid).first()
                    if scan and scan.status in (ScanStatus.PENDING.value, ScanStatus.RUNNING.value):
                        scan.status = ScanStatus.FAILED.value
                        scan.completed_at = datetime.now(timezone.utc)
                        meta = scan.model_metadata or {}
                        meta["error"] = f"Scan exceeded maximum duration of {max_duration} seconds (timeout)."
                        scan.model_metadata = meta
                        db.commit()
                except Exception as exc:
                    logger.error(f"Failed to record timeout error for scan {sid}: {str(exc)}")
                finally:
                    db.close()
            except Exception as exc:
                logger.error(f"Unhandled error in scan task wrapper for '{sid}': {str(exc)}", exc_info=True)

        task = asyncio.create_task(_bounded_scan_runner())
        if task is not None:
            _active_scan_tasks[sid] = task

            def _on_done(t: asyncio.Task) -> None:
                cls.cleanup_completed_task(sid)

            try:
                task.add_done_callback(_on_done)
            except Exception:
                pass
        return task

    @classmethod
    def cancel_all_active_scans(cls) -> None:
        """Gracefully cancel all running task wrappers during application shutdown."""
        for sid, task in list(_active_scan_tasks.items()):
            if task is not None:
                try:
                    if not task.done():
                        logger.info(f"Cancelling in-flight task wrapper for scan '{sid}' during shutdown.")
                        task.cancel()
                except Exception:
                    pass
            cls.cleanup_completed_task(sid)


class ScanRecoveryService:
    """Service to discover and resume uncompleted database scans on application startup."""

    @classmethod
    def recover_unfinished_scans(
        cls,
        db: Session,
        checkpoint_db_path: Optional[str] = None,
    ) -> List[str]:
        """Discover database scans with status PENDING or RUNNING and resume execution once.

        Recovery rules:
        - PENDING without commit SHA -> dispatches initial clone and analysis.
        - RUNNING / PENDING with commit SHA -> rehydrates exact snapshot and resumes checkpoint.
        - COMPLETED -> never rerun.
        - FAILED -> not automatically retried.

        Returns list of recovered scan IDs.
        """
        unfinished_scans = (
            db.query(ScanModel)
            .filter(ScanModel.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value]))
            .order_by(ScanModel.created_at.asc())
            .all()
        )

        recovered_ids: List[str] = []
        for scan in unfinished_scans:
            sid = str(scan.id)
            if ScanDispatcher.is_scan_active(sid):
                continue

            meta = scan.model_metadata if isinstance(scan.model_metadata, dict) else {}
            req_branch = getattr(scan, "requested_branch", None) or meta.get("requested_branch") or scan.branch
            logger.info(
                f"Discovered unfinished scan '{sid}' (status={scan.status}, commit={scan.commit_hash}). Dispatching recovery..."
            )
            ScanDispatcher.dispatch_scan(
                scan_id=sid,
                repo_url=scan.repository_url,
                branch=req_branch,
                checkpoint_db_path=checkpoint_db_path,
            )
            recovered_ids.append(sid)

        return recovered_ids
