"""Database-backed registry for immutable artifacts and provenance edges."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Iterable, Mapping, Sequence

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased

from app.artifacts.schemas import (
    ARTIFACT_CLASS_BY_TYPE,
    ArtifactCoverage,
    ArtifactLineageEdge,
    ArtifactType,
    CanonicalArtifact,
    LineageRelation,
)
from app.artifacts.store import ArtifactIntegrityError, ArtifactStore
from app.models.artifact import (
    ArtifactDeletionAttemptModel,
    ArtifactLineageModel,
    ArtifactModel,
    ArtifactReferenceModel,
    ArtifactReferenceReleaseModel,
    ArtifactTombstoneModel,
)


class ArtifactRegistryError(RuntimeError):
    pass


class ArtifactNotRegisteredError(ArtifactRegistryError):
    pass


class ArtifactTenantBoundaryError(ArtifactRegistryError):
    pass


class ArtifactProvenanceError(ArtifactRegistryError):
    pass


class ArtifactLifecycleConflict(ArtifactRegistryError):
    pass


@dataclass(frozen=True)
class ArtifactRegistration:
    artifact: CanonicalArtifact
    reused: bool


@dataclass(frozen=True)
class ArtifactReferenceHandle:
    reference_id: str
    artifact_id: str
    tenant_id: str
    reused: bool


@dataclass(frozen=True)
class TombstoneRequest:
    tombstone_id: str
    artifact_id: str
    tenant_id: str
    requested_at: datetime
    eligible_at: datetime
    reused: bool


@dataclass(frozen=True)
class PendingDeletion:
    tombstone_id: str
    artifact_id: str
    tenant_id: str
    locator: str
    content_digest: str
    reason_code: str


@dataclass(frozen=True)
class DeletionAttempt:
    attempt_id: str
    tombstone_id: str
    outcome: str
    attempted_at: datetime


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class ArtifactRegistry:
    """Create-only artifact authority; transaction ownership stays with callers."""

    def __init__(self, session: Session, *, store: ArtifactStore | None = None) -> None:
        self.session = session
        self.store = store

    def get(self, *, tenant_id: str, artifact_id: str, include_tombstoned: bool = True) -> CanonicalArtifact:
        model = self.session.execute(
            select(ArtifactModel).where(
                ArtifactModel.id == artifact_id,
                ArtifactModel.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if model is None:
            raise ArtifactNotRegisteredError("artifact was not found in this tenant")
        if not include_tombstoned and self.has_tombstone(tenant_id=tenant_id, artifact_id=artifact_id):
            raise ArtifactLifecycleConflict("artifact is tombstoned")
        return self._to_record(model)

    def register(self, artifact: CanonicalArtifact) -> ArtifactRegistration:
        identity_digest = artifact.identity_digest()
        existing = self.session.execute(
            select(ArtifactModel).where(
                ArtifactModel.tenant_id == artifact.tenant_id,
                ArtifactModel.identity_digest == identity_digest,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return ArtifactRegistration(artifact=self._to_record(existing), reused=True)

        conflicting_id = self.session.get(ArtifactModel, artifact.artifact_id)
        if conflicting_id is not None:
            raise ArtifactRegistryError("artifact_id already identifies different immutable content")

        related = self._load_and_validate_targets(artifact)
        self._validate_direct_invariants(artifact, related)
        if artifact.artifact_type == ArtifactType.FINDING:
            self._validate_finding_traceability(artifact)
        self._validate_store_object(artifact)

        model = ArtifactModel(
            id=artifact.artifact_id,
            tenant_id=artifact.tenant_id,
            repository_id=artifact.repository_id,
            revision_id=artifact.revision_id,
            artifact_type=artifact.artifact_type.value,
            schema_version=artifact.schema_version,
            identity_digest=identity_digest,
            content_digest=artifact.content_digest,
            payload_locator=artifact.payload_locator,
            payload_size_bytes=artifact.payload_size_bytes,
            media_type=artifact.media_type,
            producer=artifact.producer,
            producer_version=artifact.producer_version,
            producer_config_digest=artifact.producer_config_digest,
            policy_snapshot_id=artifact.policy_snapshot_id,
            coverage_status=artifact.coverage.status.value,
            coverage_payload=artifact.coverage.model_dump(mode="json"),
            sensitivity=artifact.sensitivity.value,
            retention_class=artifact.retention_class.value,
            created_at=artifact.created_at,
        )
        try:
            with self.session.begin_nested():
                self.session.add(model)
                self.session.add_all(
                    ArtifactLineageModel(
                        tenant_id=edge.tenant_id,
                        artifact_id=edge.artifact_id,
                        relation=edge.relation.value,
                        related_artifact_id=edge.related_artifact_id,
                        created_at=edge.created_at,
                    )
                    for edge in artifact.lineage
                )
                self.session.flush()
        except IntegrityError:
            winner = self.session.execute(
                select(ArtifactModel).where(
                    ArtifactModel.tenant_id == artifact.tenant_id,
                    ArtifactModel.identity_digest == identity_digest,
                )
            ).scalar_one_or_none()
            if winner is None:
                raise ArtifactRegistryError("artifact registration violated an immutable constraint")
            return ArtifactRegistration(artifact=self._to_record(winner), reused=True)
        return ArtifactRegistration(artifact=artifact, reused=False)

    def _validate_store_object(self, artifact: CanonicalArtifact) -> None:
        if self.store is None:
            return
        metadata = self.store.metadata(artifact.payload_locator)
        if (
            metadata.content_digest != artifact.content_digest
            or metadata.size_bytes != artifact.payload_size_bytes
            or metadata.content_type != artifact.media_type
            or metadata.sensitivity != artifact.sensitivity
            or metadata.retention_class != artifact.retention_class
        ):
            raise ArtifactIntegrityError("artifact record does not match published object metadata")
        if not self.store.verify_digest(artifact.payload_locator, artifact.content_digest):
            raise ArtifactIntegrityError("artifact object failed content digest verification")

    def _load_and_validate_targets(self, artifact: CanonicalArtifact) -> dict[str, ArtifactModel]:
        target_ids = {edge.related_artifact_id for edge in artifact.lineage}
        if not target_ids:
            return {}
        models = self.session.execute(
            select(ArtifactModel).where(ArtifactModel.id.in_(target_ids))
        ).scalars().all()
        related = {model.id: model for model in models}
        missing = sorted(target_ids - related.keys())
        if missing:
            raise ArtifactProvenanceError("lineage references unregistered artifact IDs")
        for model in models:
            if model.tenant_id != artifact.tenant_id:
                raise ArtifactTenantBoundaryError("cross-tenant artifact lineage is forbidden")
            if self.has_tombstone(tenant_id=artifact.tenant_id, artifact_id=model.id):
                raise ArtifactLifecycleConflict("new lineage cannot target a tombstoned artifact")
        for edge in artifact.lineage:
            target = related[edge.related_artifact_id]
            if edge.relation == LineageRelation.SUPERSEDES and target.artifact_type != artifact.artifact_type.value:
                raise ArtifactProvenanceError("SUPERSEDES must target the same artifact type")
        return related

    def _validate_direct_invariants(
        self, artifact: CanonicalArtifact, related: dict[str, ArtifactModel]
    ) -> None:
        related_types = {
            (edge.relation, ArtifactType(related[edge.related_artifact_id].artifact_type))
            for edge in artifact.lineage
        }
        if artifact.artifact_type == ArtifactType.ANALYZER_RUN and (
            LineageRelation.DERIVED_FROM,
            ArtifactType.REPOSITORY_REVISION,
        ) not in related_types:
            raise ArtifactProvenanceError("an analyzer run must derive from a repository revision")
        if (
            artifact.artifact_type == ArtifactType.AI_EXECUTION
            and artifact.revision_id is not None
            and (LineageRelation.DERIVED_FROM, ArtifactType.REPOSITORY_REVISION) not in related_types
        ):
            raise ArtifactProvenanceError("a revision-bound AI execution must derive from that revision")
        if artifact.artifact_type == ArtifactType.EVIDENCE and not any(
            relation == LineageRelation.PRODUCED_BY
            and target_type in {ArtifactType.ANALYZER_RUN, ArtifactType.AI_EXECUTION}
            for relation, target_type in related_types
        ):
            raise ArtifactProvenanceError("evidence must identify its analyzer or AI execution producer")
        if artifact.artifact_type == ArtifactType.CLAIM and (
            LineageRelation.DERIVED_FROM,
            ArtifactType.EVIDENCE,
        ) not in related_types:
            raise ArtifactProvenanceError("a claim must derive from evidence")
        if artifact.artifact_type == ArtifactType.FINDING and (
            LineageRelation.DERIVED_FROM,
            ArtifactType.CLAIM,
        ) not in related_types:
            raise ArtifactProvenanceError("a finding must derive from a claim")

    def _edges_for(self, artifact_id: str) -> list[ArtifactLineageModel]:
        return list(
            self.session.execute(
                select(ArtifactLineageModel).where(ArtifactLineageModel.artifact_id == artifact_id)
            ).scalars()
        )

    def _artifact_type(self, artifact_id: str) -> ArtifactType | None:
        value = self.session.execute(
            select(ArtifactModel.artifact_type).where(ArtifactModel.id == artifact_id)
        ).scalar_one_or_none()
        return ArtifactType(value) if value else None

    def _validate_finding_traceability(self, finding: CanonicalArtifact) -> None:
        proposed_edges = list(finding.lineage)
        claim_ids = [
            edge.related_artifact_id
            for edge in proposed_edges
            if edge.relation == LineageRelation.DERIVED_FROM
            and self._artifact_type(edge.related_artifact_id) == ArtifactType.CLAIM
        ]
        for claim_id in claim_ids:
            evidence_ids = [
                edge.related_artifact_id
                for edge in self._edges_for(claim_id)
                if edge.relation == LineageRelation.DERIVED_FROM.value
                and self._artifact_type(edge.related_artifact_id) == ArtifactType.EVIDENCE
            ]
            for evidence_id in evidence_ids:
                producer_ids = [
                    edge.related_artifact_id
                    for edge in self._edges_for(evidence_id)
                    if edge.relation == LineageRelation.PRODUCED_BY.value
                    and self._artifact_type(edge.related_artifact_id)
                    in {ArtifactType.ANALYZER_RUN, ArtifactType.AI_EXECUTION}
                ]
                for producer_id in producer_ids:
                    if any(
                        edge.relation == LineageRelation.DERIVED_FROM.value
                        and self._artifact_type(edge.related_artifact_id)
                        == ArtifactType.REPOSITORY_REVISION
                        for edge in self._edges_for(producer_id)
                    ):
                        return
        raise ArtifactProvenanceError(
            "finding provenance must resolve through claim, evidence, execution, and revision"
        )

    def assert_finding_traceable(self, *, tenant_id: str, artifact_id: str) -> None:
        finding = self.get(tenant_id=tenant_id, artifact_id=artifact_id, include_tombstoned=False)
        if finding.artifact_type != ArtifactType.FINDING:
            raise ArtifactProvenanceError("artifact is not a finding")
        self._validate_finding_traceability(finding)

    def _to_record(self, model: ArtifactModel) -> CanonicalArtifact:
        edges = tuple(
            ArtifactLineageEdge(
                tenant_id=edge.tenant_id,
                artifact_id=edge.artifact_id,
                relation=LineageRelation(edge.relation),
                related_artifact_id=edge.related_artifact_id,
                created_at=_as_utc(edge.created_at),
            )
            for edge in self.session.execute(
                select(ArtifactLineageModel)
                .where(ArtifactLineageModel.artifact_id == model.id)
                .order_by(
                    ArtifactLineageModel.relation.asc(),
                    ArtifactLineageModel.related_artifact_id.asc(),
                )
            ).scalars()
        )
        artifact_class = ARTIFACT_CLASS_BY_TYPE[ArtifactType(model.artifact_type)]
        return artifact_class(
            artifact_id=model.id,
            tenant_id=model.tenant_id,
            repository_id=model.repository_id,
            revision_id=model.revision_id,
            schema_version=model.schema_version,
            content_digest=model.content_digest,
            payload_locator=model.payload_locator,
            payload_size_bytes=model.payload_size_bytes,
            media_type=model.media_type,
            producer=model.producer,
            producer_version=model.producer_version,
            producer_config_digest=model.producer_config_digest,
            policy_snapshot_id=model.policy_snapshot_id,
            created_at=_as_utc(model.created_at),
            lineage=edges,
            coverage=ArtifactCoverage.model_validate(model.coverage_payload),
            sensitivity=model.sensitivity,
            retention_class=model.retention_class,
        )

    def has_tombstone(self, *, tenant_id: str, artifact_id: str) -> bool:
        return self.session.execute(
            select(ArtifactTombstoneModel.id).where(
                ArtifactTombstoneModel.tenant_id == tenant_id,
                ArtifactTombstoneModel.artifact_id == artifact_id,
            )
        ).first() is not None

    def acquire_reference(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        referrer_kind: str,
        referrer_id: str,
    ) -> ArtifactReferenceHandle:
        artifact = self.session.execute(
            select(ArtifactModel)
            .where(ArtifactModel.id == artifact_id, ArtifactModel.tenant_id == tenant_id)
            .with_for_update()
        ).scalar_one_or_none()
        if artifact is None:
            raise ArtifactNotRegisteredError("artifact was not found in this tenant")
        if self.has_tombstone(tenant_id=tenant_id, artifact_id=artifact_id):
            raise ArtifactLifecycleConflict("cannot reference a tombstoned artifact")
        existing = self.session.execute(
            select(ArtifactReferenceModel).where(
                ArtifactReferenceModel.tenant_id == tenant_id,
                ArtifactReferenceModel.artifact_id == artifact_id,
                ArtifactReferenceModel.referrer_kind == referrer_kind,
                ArtifactReferenceModel.referrer_id == referrer_id,
            )
        ).scalar_one_or_none()
        if existing is not None:
            released = self.session.execute(
                select(ArtifactReferenceReleaseModel.id).where(
                    ArtifactReferenceReleaseModel.reference_id == existing.id
                )
            ).first()
            if released is not None:
                raise ArtifactLifecycleConflict("an immutable released reference cannot be reacquired")
            return ArtifactReferenceHandle(existing.id, artifact_id, tenant_id, True)
        reference = ArtifactReferenceModel(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            referrer_kind=referrer_kind[:64],
            referrer_id=referrer_id[:128],
        )
        self.session.add(reference)
        self.session.flush()
        return ArtifactReferenceHandle(reference.id, artifact_id, tenant_id, False)

    def release_reference(self, *, reference_id: str, reason_code: str) -> bool:
        reference = self.session.get(ArtifactReferenceModel, reference_id)
        if reference is None:
            raise ArtifactNotRegisteredError("artifact reference was not found")
        existing = self.session.execute(
            select(ArtifactReferenceReleaseModel.id).where(
                ArtifactReferenceReleaseModel.reference_id == reference_id
            )
        ).first()
        if existing is not None:
            return False
        self.session.add(
            ArtifactReferenceReleaseModel(
                reference_id=reference_id,
                reason_code=reason_code[:64],
            )
        )
        self.session.flush()
        return True

    def active_reference_ids(self, *, tenant_id: str, artifact_id: str) -> list[str]:
        released = aliased(ArtifactReferenceReleaseModel)
        return list(
            self.session.execute(
                select(ArtifactReferenceModel.id)
                .outerjoin(released, released.reference_id == ArtifactReferenceModel.id)
                .where(
                    ArtifactReferenceModel.artifact_id == artifact_id,
                    released.id.is_(None),
                )
                .order_by(ArtifactReferenceModel.id.asc())
            ).scalars()
        )

    def active_dependent_ids(self, *, tenant_id: str, artifact_id: str) -> list[str]:
        tombstone = aliased(ArtifactTombstoneModel)
        return list(
            self.session.execute(
                select(ArtifactLineageModel.artifact_id)
                .join(ArtifactModel, ArtifactModel.id == ArtifactLineageModel.artifact_id)
                .outerjoin(tombstone, tombstone.artifact_id == ArtifactLineageModel.artifact_id)
                .where(
                    ArtifactLineageModel.related_artifact_id == artifact_id,
                    tombstone.id.is_(None),
                )
                .distinct()
                .order_by(ArtifactLineageModel.artifact_id.asc())
            ).scalars()
        )

    def list_active_artifact_ids(self, *, tenant_id: str, lock: bool = False) -> list[str]:
        statement = (
            select(ArtifactModel.id)
            .outerjoin(ArtifactTombstoneModel, ArtifactTombstoneModel.artifact_id == ArtifactModel.id)
            .where(ArtifactModel.tenant_id == tenant_id, ArtifactTombstoneModel.id.is_(None))
            .order_by(ArtifactModel.created_at.desc(), ArtifactModel.id.asc())
        )
        if lock:
            statement = statement.with_for_update()
        return list(self.session.execute(statement).scalars())

    def list_expired_candidates(
        self,
        *,
        cutoffs: Mapping[str, datetime],
        limit: int,
        tenant_id: str | None = None,
    ) -> list[CanonicalArtifact]:
        """Return a bounded oldest-first set for retention garbage collection."""

        if limit <= 0 or not cutoffs:
            return []
        expiry_conditions = [
            and_(
                ArtifactModel.retention_class == retention_class,
                ArtifactModel.created_at <= _as_utc(cutoff),
            )
            for retention_class, cutoff in cutoffs.items()
        ]
        statement = (
            select(ArtifactModel)
            .outerjoin(ArtifactTombstoneModel, ArtifactTombstoneModel.artifact_id == ArtifactModel.id)
            .where(ArtifactTombstoneModel.id.is_(None), or_(*expiry_conditions))
            .order_by(ArtifactModel.created_at.asc(), ArtifactModel.id.asc())
            .limit(limit)
        )
        if tenant_id is not None:
            statement = statement.where(ArtifactModel.tenant_id == tenant_id)
        return [self._to_record(model) for model in self.session.execute(statement).scalars()]

    def release_tenant_references(self, *, tenant_id: str, reason_code: str) -> int:
        released = aliased(ArtifactReferenceReleaseModel)
        references = self.session.execute(
            select(ArtifactReferenceModel)
            .outerjoin(released, released.reference_id == ArtifactReferenceModel.id)
            .where(ArtifactReferenceModel.tenant_id == tenant_id, released.id.is_(None))
            .with_for_update()
        ).scalars().all()
        self.session.add_all(
            ArtifactReferenceReleaseModel(reference_id=reference.id, reason_code=reason_code[:64])
            for reference in references
        )
        self.session.flush()
        return len(references)

    def create_tombstone(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        reason_code: str,
        requested_by: str,
        request_id: str,
        requested_at: datetime,
        eligible_at: datetime,
        deletion_scope: Iterable[str] = (),
    ) -> TombstoneRequest:
        artifact = self.session.execute(
            select(ArtifactModel)
            .where(ArtifactModel.id == artifact_id, ArtifactModel.tenant_id == tenant_id)
            .with_for_update()
        ).scalar_one_or_none()
        if artifact is None:
            raise ArtifactNotRegisteredError("artifact was not found in this tenant")
        existing = self.session.execute(
            select(ArtifactTombstoneModel).where(
                ArtifactTombstoneModel.tenant_id == tenant_id,
                ArtifactTombstoneModel.artifact_id == artifact_id,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return TombstoneRequest(
                existing.id,
                existing.artifact_id,
                existing.tenant_id,
                _as_utc(existing.requested_at),
                _as_utc(existing.eligible_at),
                True,
            )
        scope = set(deletion_scope)
        references = self.active_reference_ids(tenant_id=tenant_id, artifact_id=artifact_id)
        dependents = set(self.active_dependent_ids(tenant_id=tenant_id, artifact_id=artifact_id)) - scope
        if references or dependents:
            raise ArtifactLifecycleConflict("artifact still has active references or lineage dependents")
        requested_at = _as_utc(requested_at)
        eligible_at = _as_utc(eligible_at)
        request_payload = {
            "tenant_id": tenant_id,
            "artifact_id": artifact_id,
            "reason_code": reason_code,
            "requested_by": requested_by,
            "request_id": request_id,
            "requested_at": requested_at.isoformat(),
            "eligible_at": eligible_at.isoformat(),
        }
        request_digest = hashlib.sha256(
            json.dumps(request_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        tombstone = ArtifactTombstoneModel(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            reason_code=reason_code[:64],
            requested_by=requested_by[:128],
            request_id=request_id[:128],
            request_digest=request_digest,
            requested_at=requested_at,
            eligible_at=eligible_at,
        )
        self.session.add(tombstone)
        self.session.flush()
        return TombstoneRequest(
            tombstone.id,
            artifact_id,
            tenant_id,
            requested_at,
            eligible_at,
            False,
        )

    def pending_deletions(
        self,
        *,
        now: datetime,
        limit: int,
        retry_before: datetime | None = None,
    ) -> list[PendingDeletion]:
        if limit <= 0:
            return []
        terminal_attempt = exists().where(
            ArtifactDeletionAttemptModel.tombstone_id == ArtifactTombstoneModel.id,
            ArtifactDeletionAttemptModel.outcome.in_(("DELETED", "PERMANENT_FAILURE")),
        )
        conditions = [
            ArtifactTombstoneModel.eligible_at <= _as_utc(now),
            ~terminal_attempt,
        ]
        if retry_before is not None:
            recent_attempt = exists().where(
                ArtifactDeletionAttemptModel.tombstone_id == ArtifactTombstoneModel.id,
                ArtifactDeletionAttemptModel.attempted_at > _as_utc(retry_before),
            )
            conditions.append(~recent_attempt)
        rows = self.session.execute(
            select(ArtifactTombstoneModel, ArtifactModel)
            .join(ArtifactModel, ArtifactModel.id == ArtifactTombstoneModel.artifact_id)
            .where(*conditions)
            .order_by(ArtifactTombstoneModel.requested_at.asc(), ArtifactTombstoneModel.id.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).all()
        return [
            PendingDeletion(
                tombstone_id=tombstone.id,
                artifact_id=artifact.id,
                tenant_id=artifact.tenant_id,
                locator=artifact.payload_locator,
                content_digest=artifact.content_digest,
                reason_code=tombstone.reason_code,
            )
            for tombstone, artifact in rows
        ]

    def record_deletion_attempt(
        self,
        *,
        tombstone_id: str,
        outcome: str,
        observed_digest: str | None = None,
        blocker_codes: Sequence[str] = (),
        failure_code: str | None = None,
        attempted_at: datetime | None = None,
    ) -> DeletionAttempt:
        if outcome not in {"DELETED", "BLOCKED", "RETRYABLE_FAILURE", "PERMANENT_FAILURE"}:
            raise ValueError("unsupported deletion outcome")
        attempt = ArtifactDeletionAttemptModel(
            tombstone_id=tombstone_id,
            outcome=outcome,
            observed_digest=observed_digest,
            blocker_codes=[str(code)[:64] for code in blocker_codes[:50]],
            failure_code=failure_code[:64] if failure_code else None,
            attempted_at=_as_utc(attempted_at or datetime.now(timezone.utc)),
        )
        self.session.add(attempt)
        self.session.flush()
        return DeletionAttempt(attempt.id, tombstone_id, outcome, _as_utc(attempt.attempted_at))
