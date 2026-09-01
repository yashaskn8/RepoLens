"""Transactional domain outbox and tamper-evident audit authorities."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.platform import AuditChainHeadModel, AuditEventModel, OutboxEventModel
from app.security.redaction import sanitize_metadata


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


class DomainOutbox:
    @staticmethod
    def append(
        db: Session,
        *,
        tenant_id: str,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        deduplication_key: str,
        payload: dict[str, Any] | None = None,
    ) -> OutboxEventModel:
        safe_payload = sanitize_metadata(payload or {})
        existing = db.query(OutboxEventModel).filter(
            OutboxEventModel.tenant_id == tenant_id,
            OutboxEventModel.deduplication_key == deduplication_key,
        ).first()
        if existing is not None:
            return existing
        model = OutboxEventModel(
            tenant_id=tenant_id,
            aggregate_type=aggregate_type[:64],
            aggregate_id=aggregate_id[:128],
            event_type=event_type[:128],
            deduplication_key=deduplication_key[:128],
            payload=safe_payload,
            payload_digest=_digest(safe_payload),
        )
        db.add(model)
        db.flush()
        return model

    @staticmethod
    def claim(db: Session, *, worker_id: str, limit: int = 100, lease_seconds: int = 60) -> list[OutboxEventModel]:
        now = datetime.now(timezone.utc)
        rows = (
            db.query(OutboxEventModel)
            .filter(
                OutboxEventModel.status.in_(["PENDING", "PROCESSING"]),
                OutboxEventModel.available_at <= now,
                or_(OutboxEventModel.lease_owner.is_(None), OutboxEventModel.lease_expires_at < now),
            )
            .order_by(OutboxEventModel.created_at.asc(), OutboxEventModel.id.asc())
            .with_for_update(skip_locked=True)
            .limit(max(1, min(limit, 1000)))
            .all()
        )
        for row in rows:
            row.status = "PROCESSING"
            row.lease_owner = worker_id[:128]
            row.lease_expires_at = now + timedelta(seconds=lease_seconds)
            row.attempt_count += 1
        db.flush()
        return rows

    @staticmethod
    def mark_published(db: Session, event_id: str, worker_id: str) -> bool:
        now = datetime.now(timezone.utc)
        updated = db.query(OutboxEventModel).filter(
            OutboxEventModel.id == event_id,
            OutboxEventModel.status == "PROCESSING",
            OutboxEventModel.lease_owner == worker_id,
        ).update({
            OutboxEventModel.status: "PUBLISHED",
            OutboxEventModel.published_at: now,
            OutboxEventModel.lease_owner: None,
            OutboxEventModel.lease_expires_at: None,
            OutboxEventModel.failure_code: None,
        }, synchronize_session=False)
        db.flush()
        return updated == 1

    @staticmethod
    def mark_failed(
        db: Session,
        event_id: str,
        worker_id: str,
        *,
        failure_code: str,
        retry_after_seconds: int = 30,
        max_attempts: int = 10,
    ) -> bool:
        event = db.query(OutboxEventModel).filter(
            OutboxEventModel.id == event_id,
            OutboxEventModel.status == "PROCESSING",
            OutboxEventModel.lease_owner == worker_id,
        ).first()
        if event is None:
            return False
        exhausted = event.attempt_count >= max_attempts
        event.status = "FAILED" if exhausted else "PENDING"
        event.available_at = datetime.now(timezone.utc) + timedelta(seconds=max(1, retry_after_seconds))
        event.lease_owner = None
        event.lease_expires_at = None
        event.failure_code = failure_code[:64]
        db.flush()
        return True


class AuditLedger:
    @staticmethod
    def append(
        db: Session,
        *,
        tenant_id: str,
        event_type: str,
        resource_type: str,
        resource_id: str,
        actor_id: str | None = None,
        request_id: str | None = None,
        artifact_digest: str | None = None,
        state_digest: str | None = None,
        payload: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEventModel:
        safe_payload = sanitize_metadata(payload or {})
        payload_digest = _digest(safe_payload)
        timestamp = occurred_at or datetime.now(timezone.utc)
        head = db.query(AuditChainHeadModel).filter(
            AuditChainHeadModel.tenant_id == tenant_id,
        ).with_for_update().first()
        if head is None:
            try:
                with db.begin_nested():
                    head = AuditChainHeadModel(tenant_id=tenant_id, sequence=0, head_hash="0" * 64)
                    db.add(head)
                    db.flush()
            except IntegrityError:
                head = db.query(AuditChainHeadModel).filter(
                    AuditChainHeadModel.tenant_id == tenant_id,
                ).with_for_update().one()
        sequence = int(head.sequence) + 1
        material = {
            "tenant_id": tenant_id,
            "sequence": sequence,
            "previous_hash": head.head_hash,
            "event_type": event_type,
            "actor_id": actor_id,
            "request_id": request_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "artifact_digest": artifact_digest,
            "state_digest": state_digest,
            "payload_digest": payload_digest,
            "created_at": _timestamp(timestamp),
        }
        event_hash = _digest(material)
        event = AuditEventModel(
            id=str(uuid4()),
            tenant_id=tenant_id,
            sequence=sequence,
            previous_hash=head.head_hash,
            event_hash=event_hash,
            event_type=event_type[:128],
            actor_id=actor_id,
            request_id=request_id[:128] if request_id else None,
            resource_type=resource_type[:64],
            resource_id=resource_id[:128],
            artifact_digest=artifact_digest,
            state_digest=state_digest,
            payload_digest=payload_digest,
            safe_payload=safe_payload,
            created_at=timestamp,
        )
        db.add(event)
        head.sequence = sequence
        head.head_hash = event_hash
        head.updated_at = timestamp
        db.flush()
        return event

    @staticmethod
    def verify(db: Session, tenant_id: str) -> bool:
        events = db.query(AuditEventModel).filter(
            AuditEventModel.tenant_id == tenant_id,
        ).order_by(AuditEventModel.sequence.asc()).all()
        previous_hash = "0" * 64
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence or event.previous_hash != previous_hash:
                return False
            if _digest(event.safe_payload or {}) != event.payload_digest:
                return False
            material = {
                "tenant_id": event.tenant_id,
                "sequence": event.sequence,
                "previous_hash": event.previous_hash,
                "event_type": event.event_type,
                "actor_id": event.actor_id,
                "request_id": event.request_id,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "artifact_digest": event.artifact_digest,
                "state_digest": event.state_digest,
                "payload_digest": event.payload_digest,
                "created_at": _timestamp(event.created_at),
            }
            if _digest(material) != event.event_hash:
                return False
            previous_hash = event.event_hash
        head = db.query(AuditChainHeadModel).filter(AuditChainHeadModel.tenant_id == tenant_id).first()
        return head is None if not events else bool(head and head.sequence == len(events) and head.head_hash == previous_hash)
