"""Periodic retention, tombstone, and physical deletion reconciliation runtime."""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import inspect

from app.artifacts.lifecycle import ArtifactDeletionReconciler, ArtifactLifecycleService
from app.artifacts.registry import ArtifactRegistry
from app.artifacts.service import get_artifact_store
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.governance.events import AuditLedger, DomainOutbox
from app.governance.telemetry import TelemetryRecorder


logger = logging.getLogger(__name__)


class ArtifactLifecycleRuntime:
    _task: asyncio.Task | None = None

    @classmethod
    def sweep_once(cls) -> dict[str, int]:
        settings = get_settings()
        db = SessionLocal()
        try:
            if not inspect(db.get_bind()).has_table("artifact_tombstones"):
                return {"requested": 0, "deleted": 0, "blocked": 0, "retryable": 0, "permanent": 0}
            store = get_artifact_store(settings)
            registry = ArtifactRegistry(db, store=store)
            lifecycle = ArtifactLifecycleService(registry)
            candidates = lifecycle.garbage_collection_candidates(limit=settings.ARTIFACT_GC_BATCH_SIZE)
            requested = 0
            for artifact in candidates:
                result = lifecycle.request_deletion(
                    tenant_id=artifact.tenant_id,
                    artifact_id=artifact.artifact_id,
                    reason_code="RETENTION_EXPIRED",
                    requested_by="artifact-lifecycle",
                    request_id=f"retention:{artifact.artifact_id}",
                )
                if result.status in {"REQUESTED", "REUSED"}:
                    requested += 1
                    DomainOutbox.append(
                        db,
                        tenant_id=artifact.tenant_id,
                        aggregate_type="ARTIFACT",
                        aggregate_id=artifact.artifact_id,
                        event_type="ARTIFACT_DELETION_REQUESTED",
                        deduplication_key=f"artifact:{artifact.artifact_id}:retention-delete",
                        payload={"reason_code": "RETENTION_EXPIRED"},
                    )
                    AuditLedger.append(
                        db,
                        tenant_id=artifact.tenant_id,
                        event_type="ARTIFACT_DELETION_REQUESTED",
                        resource_type="ARTIFACT",
                        resource_id=artifact.artifact_id,
                        artifact_digest=artifact.content_digest,
                        payload={"reason_code": "RETENTION_EXPIRED"},
                    )
            summary = ArtifactDeletionReconciler(registry, store).reconcile(
                limit=settings.ARTIFACT_GC_BATCH_SIZE
            )
            TelemetryRecorder.record(
                db,
                metric_name="artifact.deletion_reconciliation",
                value=float(summary.examined),
                unit="count",
                dimensions={
                    "deleted": summary.deleted,
                    "blocked": summary.blocked,
                    "retryable": summary.retryable_failures,
                    "permanent": summary.permanent_failures,
                },
            )
            db.commit()
            return {
                "requested": requested,
                "deleted": summary.deleted,
                "blocked": summary.blocked,
                "retryable": summary.retryable_failures,
                "permanent": summary.permanent_failures,
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @classmethod
    def start(cls) -> None:
        if cls._task is not None and not cls._task.done():
            return

        async def loop() -> None:
            interval = get_settings().ARTIFACT_RECONCILIATION_INTERVAL_SECONDS
            while True:
                try:
                    await asyncio.to_thread(cls.sweep_once)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Artifact lifecycle reconciliation failed.")
                await asyncio.sleep(max(5, interval))

        cls._task = asyncio.create_task(loop(), name="artifact-lifecycle-reconciler")

    @classmethod
    async def stop(cls) -> None:
        task = cls._task
        cls._task = None
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


__all__ = ["ArtifactLifecycleRuntime"]
