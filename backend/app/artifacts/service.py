"""Application service that atomically publishes payloads and registers provenance."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.artifacts.registry import ArtifactRegistration, ArtifactRegistry
from app.artifacts.schemas import (
    ARTIFACT_CLASS_BY_TYPE,
    ArtifactCoverage,
    ArtifactLineageEdge,
    ArtifactSensitivity,
    ArtifactType,
    CoverageStatus,
    LineageRelation,
    RetentionClass,
)
from app.artifacts.store import ArtifactPutRequest, ArtifactStore, LocalArtifactStore, artifact_locator
from app.core.config import Settings, get_settings
from app.governance.events import AuditLedger, DomainOutbox
from app.governance.telemetry import TelemetryRecorder
from app.models.artifact import ArtifactPublicationIntentModel


_configured_store: ArtifactStore | None = None
_EMPTY_CONFIG_DIGEST = hashlib.sha256(b"{}").hexdigest()


def configure_artifact_store(store: ArtifactStore) -> None:
    """Inject a production conditional-blob adapter without hard-coding a vendor."""
    global _configured_store
    _configured_store = store


def get_artifact_store(settings: Settings | None = None) -> ArtifactStore:
    configured = settings or get_settings()
    if _configured_store is not None:
        return _configured_store
    if configured.ARTIFACT_STORAGE_BACKEND == "local":
        return LocalArtifactStore(Path(configured.ARTIFACT_ROOT_DIR))
    raise RuntimeError(
        "ARTIFACT_STORAGE_BACKEND=blob requires a configured ConditionalBlobClient adapter."
    )


class CanonicalArtifactService:
    def __init__(
        self,
        db: Session,
        *,
        store: ArtifactStore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.store = store or get_artifact_store(self.settings)
        self.registry = ArtifactRegistry(db, store=self.store)

    def publish_json(
        self,
        *,
        tenant_id: str,
        repository_id: str | None,
        revision_id: str | None,
        artifact_type: ArtifactType,
        payload: Mapping[str, Any] | list[Any],
        producer: str,
        producer_version: str,
        policy_snapshot_id: str,
        lineage: Iterable[tuple[LineageRelation, str]] = (),
        coverage: ArtifactCoverage | None = None,
        sensitivity: ArtifactSensitivity = ArtifactSensitivity.SOURCE_DERIVED,
        retention_class: RetentionClass = RetentionClass.ANALYSIS_ARTIFACT,
        producer_config_digest: str = _EMPTY_CONFIG_DIGEST,
        referrer: tuple[str, str] | None = None,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> ArtifactRegistration:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        return self.publish_bytes(
            tenant_id=tenant_id,
            repository_id=repository_id,
            revision_id=revision_id,
            artifact_type=artifact_type,
            payload=encoded,
            media_type="application/json",
            producer=producer,
            producer_version=producer_version,
            policy_snapshot_id=policy_snapshot_id,
            lineage=lineage,
            coverage=coverage,
            sensitivity=sensitivity,
            retention_class=retention_class,
            producer_config_digest=producer_config_digest,
            referrer=referrer,
            actor_id=actor_id,
            request_id=request_id,
        )

    def publish_file(
        self,
        *,
        path: Path,
        media_type: str,
        tenant_id: str,
        repository_id: str | None,
        revision_id: str | None,
        artifact_type: ArtifactType,
        producer: str,
        producer_version: str,
        policy_snapshot_id: str,
        lineage: Iterable[tuple[LineageRelation, str]] = (),
        coverage: ArtifactCoverage | None = None,
        sensitivity: ArtifactSensitivity = ArtifactSensitivity.SOURCE_DERIVED,
        retention_class: RetentionClass = RetentionClass.ANALYSIS_ARTIFACT,
        producer_config_digest: str = _EMPTY_CONFIG_DIGEST,
        referrer: tuple[str, str] | None = None,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> ArtifactRegistration:
        with path.open("rb") as stream:
            payload = stream.read()
        return self.publish_bytes(
            tenant_id=tenant_id,
            repository_id=repository_id,
            revision_id=revision_id,
            artifact_type=artifact_type,
            payload=payload,
            media_type=media_type,
            producer=producer,
            producer_version=producer_version,
            policy_snapshot_id=policy_snapshot_id,
            lineage=lineage,
            coverage=coverage,
            sensitivity=sensitivity,
            retention_class=retention_class,
            producer_config_digest=producer_config_digest,
            referrer=referrer,
            actor_id=actor_id,
            request_id=request_id,
        )

    def publish_bytes(
        self,
        *,
        tenant_id: str,
        repository_id: str | None,
        revision_id: str | None,
        artifact_type: ArtifactType,
        payload: bytes,
        media_type: str,
        producer: str,
        producer_version: str,
        policy_snapshot_id: str,
        lineage: Iterable[tuple[LineageRelation, str]] = (),
        coverage: ArtifactCoverage | None = None,
        sensitivity: ArtifactSensitivity = ArtifactSensitivity.SOURCE_DERIVED,
        retention_class: RetentionClass = RetentionClass.ANALYSIS_ARTIFACT,
        producer_config_digest: str = _EMPTY_CONFIG_DIGEST,
        referrer: tuple[str, str] | None = None,
        actor_id: str | None = None,
        request_id: str | None = None,
    ) -> ArtifactRegistration:
        content_digest = hashlib.sha256(payload).hexdigest()
        lineage_edges = tuple(lineage)
        edge_inputs = tuple(sorted((relation.value, target) for relation, target in lineage_edges))
        identity = json.dumps(
            {
                "tenant_id": tenant_id,
                "repository_id": repository_id,
                "revision_id": revision_id,
                "artifact_type": artifact_type.value,
                "content_digest": content_digest,
                "producer": producer,
                "producer_version": producer_version,
                "producer_config_digest": producer_config_digest,
                "policy_snapshot_id": policy_snapshot_id,
                "lineage": edge_inputs,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        artifact_id = str(uuid5(NAMESPACE_URL, f"repolens-artifact:{identity}"))
        put_request = ArtifactPutRequest(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            expected_digest=content_digest,
            expected_size_bytes=len(payload),
            content_type=media_type,
            sensitivity=sensitivity,
            retention_class=retention_class,
        )
        intent = self._lock_publication_intent(
            request=put_request,
            artifact_type=artifact_type,
        )
        metadata = self.store.publish_atomic(
            put_request,
            io.BytesIO(payload),
        )
        now = datetime.now(timezone.utc)
        edges = tuple(
            ArtifactLineageEdge(
                tenant_id=tenant_id,
                artifact_id=artifact_id,
                relation=relation,
                related_artifact_id=target,
                created_at=now,
            )
            for relation, target in lineage_edges
        )
        artifact_class = ARTIFACT_CLASS_BY_TYPE[artifact_type]
        artifact = artifact_class(
            artifact_id=artifact_id,
            tenant_id=tenant_id,
            repository_id=repository_id,
            revision_id=revision_id,
            schema_version="1.0",
            content_digest=metadata.content_digest,
            payload_locator=metadata.locator,
            payload_size_bytes=metadata.size_bytes,
            media_type=metadata.content_type,
            producer=producer,
            producer_version=producer_version,
            producer_config_digest=producer_config_digest,
            policy_snapshot_id=policy_snapshot_id,
            created_at=now,
            lineage=edges,
            coverage=coverage or ArtifactCoverage(
                status=CoverageStatus.SUCCESSFULLY_ANALYZED,
                discovered_count=1,
                analyzed_count=1,
            ),
            sensitivity=sensitivity,
            retention_class=retention_class,
        )
        registration = self.registry.register(artifact)
        if referrer is not None:
            self.registry.acquire_reference(
                tenant_id=tenant_id,
                artifact_id=registration.artifact.artifact_id,
                referrer_kind=referrer[0],
                referrer_id=referrer[1],
            )
        DomainOutbox.append(
            self.db,
            tenant_id=tenant_id,
            aggregate_type="ARTIFACT",
            aggregate_id=registration.artifact.artifact_id,
            event_type="ARTIFACT_PUBLISHED",
            deduplication_key=f"artifact:{registration.artifact.artifact_id}:published",
            payload={
                "artifact_type": artifact_type.value,
                "content_digest": registration.artifact.content_digest,
                "reused": registration.reused,
            },
        )
        AuditLedger.append(
            self.db,
            tenant_id=tenant_id,
            actor_id=actor_id,
            request_id=request_id,
            event_type="ARTIFACT_PUBLISHED",
            resource_type="ARTIFACT",
            resource_id=registration.artifact.artifact_id,
            artifact_digest=registration.artifact.content_digest,
            payload={"artifact_type": artifact_type.value, "reused": registration.reused},
        )
        TelemetryRecorder.record(
            self.db,
            tenant_id=tenant_id,
            request_id=request_id,
            metric_name="artifact.reuse",
            value=1 if registration.reused else 0,
            unit="boolean",
            dimensions={"artifact_type": artifact_type.value},
        )
        intent.status = "REGISTERED"
        intent.failure_code = None
        intent.resolved_at = now
        self.db.flush()
        return registration

    def _lock_publication_intent(
        self,
        *,
        request: ArtifactPutRequest,
        artifact_type: ArtifactType,
    ) -> ArtifactPublicationIntentModel:
        """Commit the recovery marker before storage, then lock through caller commit.

        Production sessions are engine-bound, so the intent is written in a
        separate durable transaction before object publication. Connection-bound
        test/outer transactions keep the marker in their own transaction; durable
        orphan recovery is separately exercised with engine-bound sessions.
        """
        bind = self.db.get_bind()
        locator = artifact_locator(request)
        # PostgreSQL is the production transactional authority. SQLite uses the
        # caller transaction to avoid competing writers in local/dev databases.
        durable_elsewhere = isinstance(bind, Engine) and bind.dialect.name == "postgresql"
        intent_session = sessionmaker(bind=bind, expire_on_commit=False)() if durable_elsewhere else None
        try:
            intent_db = intent_session or self.db
            existing = intent_db.get(ArtifactPublicationIntentModel, request.artifact_id)
            if existing is None:
                intent_db.add(
                    ArtifactPublicationIntentModel(
                        artifact_id=request.artifact_id,
                        tenant_id=request.tenant_id,
                        payload_locator=locator,
                        content_digest=request.expected_digest,
                        payload_size_bytes=request.expected_size_bytes or 0,
                        media_type=request.content_type,
                        artifact_type=artifact_type.value,
                        status="PENDING",
                    )
                )
                try:
                    if durable_elsewhere:
                        intent_db.commit()
                    else:
                        intent_db.flush()
                except IntegrityError:
                    intent_db.rollback()
                    if intent_db.get(ArtifactPublicationIntentModel, request.artifact_id) is None:
                        raise
            intent = (
                self.db.query(ArtifactPublicationIntentModel)
                .filter(ArtifactPublicationIntentModel.artifact_id == request.artifact_id)
                .with_for_update()
                .one()
            )
            if (
                intent.tenant_id != request.tenant_id
                or intent.payload_locator != locator
                or intent.content_digest != request.expected_digest
                or intent.payload_size_bytes != (request.expected_size_bytes or 0)
                or intent.media_type != request.content_type
                or intent.artifact_type != artifact_type.value
            ):
                raise RuntimeError("ARTIFACT_PUBLICATION_INTENT_MISMATCH")
            if intent.status in {"CLEANED", "RETRYABLE_FAILURE"}:
                intent.status = "PENDING"
                intent.failure_code = None
                intent.created_at = datetime.now(timezone.utc)
                intent.resolved_at = None
                self.db.flush()
            return intent
        finally:
            if intent_session is not None:
                intent_session.close()


__all__ = [
    "CanonicalArtifactService",
    "configure_artifact_store",
    "get_artifact_store",
]
