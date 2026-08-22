"""Canonical WorkflowEventService for emitting and querying durable workflow events."""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.workflow_event import WorkflowEventModel
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType

logger = logging.getLogger(__name__)

# Keys that should never be persisted in event metadata
_SENSITIVE_KEY_SUBSTRINGS = ("key", "token", "secret", "auth", "password", "credential", "prompt")


def _sanitize_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Sanitize metadata dictionary to ensure no sensitive credentials or raw prompts are leaked."""
    if not metadata or not isinstance(metadata, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for k, v in metadata.items():
        k_lower = str(k).lower()
        if any(substr in k_lower for substr in _SENSITIVE_KEY_SUBSTRINGS):
            continue
        # Truncate overly long string values
        if isinstance(v, str) and len(v) > 2048:
            sanitized[k] = v[:2048] + "... [truncated]"
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_metadata(v)
        else:
            sanitized[k] = v
    return sanitized


class WorkflowEventService:
    """Canonical service for creating, emitting, and querying durable workflow events."""

    @staticmethod
    def emit(
        db: Session,
        event: WorkflowEventCreate,
        critical: bool = False,
    ) -> Optional[WorkflowEventModel]:
        """Emit and persist a workflow event into the database.

        If critical is True, errors will propagate to ensure atomicity with critical state changes.
        If critical is False (operational telemetry), failures are caught and logged so scans continue.
        """
        try:
            clean_meta = _sanitize_metadata(event.metadata_payload)
            model = WorkflowEventModel(
                event_type=event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
                scan_id=str(event.scan_id),
                finding_id=str(event.finding_id) if event.finding_id else None,
                patch_id=str(event.patch_id) if event.patch_id else None,
                thread_id=event.thread_id,
                commit_sha=event.commit_sha,
                stage=event.stage,
                tool_name=event.tool_name,
                provider=event.provider,
                model_name=event.model_name,
                message=event.message,
                metadata_payload=clean_meta,
            )
            db.add(model)
            return model
        except Exception as exc:
            logger.warning(f"Failed to emit workflow event {event.event_type}: {str(exc)}")
            if critical:
                raise
            return None

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
    def list_events(
        db: Session,
        scan_id: str,
        limit: int = 100,
    ) -> List[WorkflowEventModel]:
        """Alias for list_for_scan."""
        return WorkflowEventService.list_for_scan(db=db, scan_id=scan_id, limit=limit)
