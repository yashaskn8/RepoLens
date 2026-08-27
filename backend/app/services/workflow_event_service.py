"""Canonical WorkflowEventService for emitting and querying durable workflow events."""

import logging
from typing import Any, Callable, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.models.workflow_event import WorkflowEventModel
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.security.redaction import redact_secrets, sanitize_metadata

logger = logging.getLogger(__name__)

# Preserve alias for backward compatibility with tests
_sanitize_metadata = sanitize_metadata


def _build_event_model(event: WorkflowEventCreate) -> WorkflowEventModel:
    """Build a WorkflowEventModel from a WorkflowEventCreate schema with sanitized metadata and redacted message."""
    clean_meta = sanitize_metadata(event.metadata_payload)
    clean_msg = redact_secrets(event.message) if event.message else ""
    if len(clean_msg) > 2048:
        clean_msg = clean_msg[:2048] + "... [truncated]"

    delivery_id = str(event.delivery_id) if event.delivery_id else None
    if not delivery_id and event.metadata_payload and "delivery_id" in event.metadata_payload:
        delivery_id = str(event.metadata_payload["delivery_id"])

    change_analysis_id = str(event.change_analysis_id) if event.change_analysis_id else None
    if not change_analysis_id and event.metadata_payload and "change_analysis_id" in event.metadata_payload:
        change_analysis_id = str(event.metadata_payload["change_analysis_id"])

    return WorkflowEventModel(
        event_type=event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
        scan_id=str(event.scan_id) if event.scan_id else None,
        change_analysis_id=change_analysis_id,
        finding_id=str(event.finding_id) if event.finding_id else None,
        patch_id=str(event.patch_id) if event.patch_id else None,
        delivery_id=delivery_id,
        thread_id=event.thread_id,
        commit_sha=event.commit_sha,
        stage=event.stage,
        tool_name=event.tool_name,
        provider=event.provider,
        model_name=event.model_name,
        message=clean_msg,
        metadata_payload=clean_meta,
    )


class WorkflowEventService:
    """Canonical service for creating, emitting, and querying durable workflow events.

    Provides two explicit emission modes:

    1. emit_critical(db, event) — adds the event to the CALLER's session so that it
       is committed or rolled back atomically with the primary domain state transition.
       Errors propagate to ensure human-audit events (HUMAN_APPROVED, HUMAN_REJECTED,
       HUMAN_REVISION_REQUESTED, PATCH_APPROVED, PATCH_REJECTED) never silently drop.

    2. emit_operational(event, session_factory) — uses an INDEPENDENT short-lived session
       to persist the event. Failures are caught and logged so that valid domain work
       (scan execution, tool outcomes) is never turned into failure by telemetry problems.
       For SQLite, operational events that reference scan rows should be emitted AFTER
       the primary state commit so the FK target exists.

    The legacy emit(db, event, critical) method is preserved for backward compatibility
    but now correctly routes critical=True to the caller session and critical=False to
    an independent session when a session_factory is available.
    """

    @staticmethod
    def emit_critical(
        db: Session,
        event: WorkflowEventCreate,
    ) -> WorkflowEventModel:
        """Emit an audit-critical event atomically within the caller's session.

        Errors propagate so the enclosing transaction rolls back if the audit event
        cannot be persisted — ensuring no silent audit gaps for human approvals/rejections.
        """
        model = _build_event_model(event)
        db.add(model)
        return model

    @staticmethod
    def emit_operational(
        event: WorkflowEventCreate,
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> Optional[WorkflowEventModel]:
        """Emit an operational telemetry event using an independent short-lived session.

        Failures are caught and logged — they never propagate to the caller's domain
        transaction. Returns None on failure.

        If session_factory is None, falls back to the global SessionLocal.
        """
        if session_factory is None:
            from app.core.database import SessionLocal
            session_factory = SessionLocal

        op_session: Optional[Session] = None
        try:
            model = _build_event_model(event)
            op_session = session_factory()
            op_session.add(model)
            op_session.commit()
            op_session.refresh(model)
            op_session.expunge(model)
            return model
        except Exception as exc:
            logger.warning(f"Operational event emission failed for {event.event_type}: {exc}")
            if op_session is not None:
                try:
                    op_session.rollback()
                except Exception:
                    pass
            return None
        finally:
            if op_session is not None:
                try:
                    op_session.close()
                except Exception:
                    pass

    @staticmethod
    def emit(
        db: Optional[Session],
        event: WorkflowEventCreate,
        critical: bool = False,
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> Optional[WorkflowEventModel]:
        """Canonical event emission interface.

        If critical is True:
            Delegates to emit_critical (attaches to caller's session so audit events
            commit or rollback atomically with domain state transitions; errors propagate).

        If critical is False:
            Delegates to emit_operational (independent short-lived transaction).
            If session_factory is supplied, it is used.
            If session_factory is None and db is supplied, derives an independent session_factory
            from the active engine/bind of that session.
            If neither is available, falls back to global SessionLocal.
            NO non-critical event ever attaches to the caller's transaction.
        """
        if critical:
            if db is None:
                raise ValueError("A database session is required for critical audit event emission.")
            return WorkflowEventService.emit_critical(db, event)

        if session_factory is None and db is not None:
            bind = None
            if hasattr(db, "get_bind"):
                try:
                    bind = db.get_bind()
                except Exception:
                    bind = None
            if bind is None:
                bind = getattr(db, "bind", None)

            if bind is not None:
                session_factory = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=bind)

        return WorkflowEventService.emit_operational(event, session_factory=session_factory)

    @staticmethod
    def list_for_scan(
        db: Session,
        scan_id: str,
        limit: int = 100,
    ) -> List[WorkflowEventModel]:
        """Query workflow events for a given scan ordered by monotonically increasing event ID."""
        return (
            db.query(WorkflowEventModel)
            .filter(WorkflowEventModel.scan_id == str(scan_id))
            .order_by(WorkflowEventModel.id.asc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def list_after_id(
        db: Session,
        scan_id: str,
        after_id: int,
        limit: int = 100,
    ) -> List[WorkflowEventModel]:
        """Query workflow events for a given scan strictly after a given event ID for SSE replay."""
        return (
            db.query(WorkflowEventModel)
            .filter(
                WorkflowEventModel.scan_id == str(scan_id),
                WorkflowEventModel.id > after_id,
            )
            .order_by(WorkflowEventModel.id.asc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def list_for_patch(
        db: Session,
        patch_id: str,
        limit: int = 100,
    ) -> List[WorkflowEventModel]:
        """Query workflow events for a specific patch proposal."""
        return (
            db.query(WorkflowEventModel)
            .filter(WorkflowEventModel.patch_id == str(patch_id))
            .order_by(WorkflowEventModel.id.asc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def list_for_delivery(
        db: Session,
        delivery_id: str,
        limit: int = 100,
    ) -> List[WorkflowEventModel]:
        """Query workflow events for a specific delivery execution."""
        return (
            db.query(WorkflowEventModel)
            .filter(WorkflowEventModel.delivery_id == str(delivery_id))
            .order_by(WorkflowEventModel.id.asc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def list_for_change_analysis(
        db: Session,
        change_analysis_id: str,
        limit: int = 100,
    ) -> List[WorkflowEventModel]:
        """Query workflow events for a specific change intelligence analysis."""
        return (
            db.query(WorkflowEventModel)
            .filter(WorkflowEventModel.change_analysis_id == str(change_analysis_id))
            .order_by(WorkflowEventModel.id.asc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def list_after_id_for_change_analysis(
        db: Session,
        change_analysis_id: str,
        after_id: int,
        limit: int = 100,
    ) -> List[WorkflowEventModel]:
        """Query workflow events for a given change analysis strictly after a given event ID for SSE replay."""
        return (
            db.query(WorkflowEventModel)
            .filter(
                WorkflowEventModel.change_analysis_id == str(change_analysis_id),
                WorkflowEventModel.id > after_id,
            )
            .order_by(WorkflowEventModel.id.asc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def list_events(
        db: Session,
        scan_id: str,
        limit: int = 100,
    ) -> List[WorkflowEventModel]:
        """Alias for list_for_scan."""
        return WorkflowEventService.list_for_scan(db=db, scan_id=scan_id, limit=limit)


