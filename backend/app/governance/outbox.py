"""Lease-backed relational outbox relay with at-least-once delivery semantics."""

import asyncio
import inspect
import logging
import socket
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.governance.events import DomainOutbox


logger = logging.getLogger(__name__)
OutboxHandler = Callable[[dict[str, Any]], Any]


class RelationalOutboxRelay:
    _handlers: dict[str, list[OutboxHandler]] = {}
    _task: asyncio.Task | None = None
    _worker_id = f"{socket.gethostname()}:{uuid4()}"

    @classmethod
    def register(cls, event_type: str, handler: OutboxHandler) -> None:
        cls._handlers.setdefault(event_type, []).append(handler)

    @classmethod
    def _claim(cls, limit: int = 100) -> list[dict[str, Any]]:
        db = SessionLocal()
        try:
            rows = DomainOutbox.claim(db, worker_id=cls._worker_id, limit=limit)
            claimed = [{
                "id": row.id,
                "tenant_id": row.tenant_id,
                "aggregate_type": row.aggregate_type,
                "aggregate_id": row.aggregate_id,
                "event_type": row.event_type,
                "payload": row.payload or {},
                "payload_digest": row.payload_digest,
            } for row in rows]
            db.commit()
            return claimed
        finally:
            db.close()

    @classmethod
    def _finish(cls, event_id: str, *, failure_code: str | None = None) -> None:
        db = SessionLocal()
        try:
            if failure_code:
                DomainOutbox.mark_failed(
                    db,
                    event_id,
                    cls._worker_id,
                    failure_code=failure_code,
                    max_attempts=get_settings().MAX_OUTBOX_ATTEMPTS,
                )
            else:
                DomainOutbox.mark_published(db, event_id, cls._worker_id)
            db.commit()
        finally:
            db.close()

    @classmethod
    async def relay_once(cls, limit: int = 100) -> int:
        events = await asyncio.to_thread(cls._claim, limit)
        for event in events:
            try:
                handlers = cls._handlers.get(event["event_type"], [])
                for handler in handlers:
                    result = handler(event)
                    if inspect.isawaitable(result):
                        await result
                logger.info(
                    "domain_event_published",
                    extra={
                        "event_id": event["id"],
                        "event_type": event["event_type"],
                        "aggregate_type": event["aggregate_type"],
                    },
                )
                await asyncio.to_thread(cls._finish, event["id"])
            except Exception:
                logger.exception("Outbox event %s delivery failed.", event["id"])
                await asyncio.to_thread(cls._finish, event["id"], failure_code="OUTBOX_HANDLER_FAILED")
        return len(events)

    @classmethod
    def start(cls) -> None:
        if cls._task and not cls._task.done():
            return

        async def loop() -> None:
            while True:
                try:
                    delivered = await cls.relay_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Relational outbox sweep failed.")
                    delivered = 0
                await asyncio.sleep(1 if delivered else 5)

        cls._task = asyncio.create_task(loop())

    @classmethod
    def stop(cls) -> None:
        if cls._task and not cls._task.done():
            cls._task.cancel()
        cls._task = None
