"""Retention, tombstoning, and deletion reconciliation for artifact payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Mapping

from app.artifacts.registry import (
    ArtifactLifecycleConflict,
    ArtifactRegistry,
    PendingDeletion,
    TombstoneRequest,
)
from app.artifacts.schemas import CanonicalArtifact, RetentionClass
from app.artifacts.store import (
    ArtifactConflictError,
    ArtifactIntegrityError,
    ArtifactStore,
    ArtifactStoreError,
)


@dataclass(frozen=True)
class RetentionPolicy:
    retention_class: RetentionClass
    minimum_age: timedelta | None

    def __post_init__(self) -> None:
        if self.minimum_age is not None and self.minimum_age.total_seconds() < 0:
            raise ValueError("minimum retention age cannot be negative")


def _default_policies() -> Mapping[RetentionClass, RetentionPolicy]:
    policies = {
        RetentionClass.EPHEMERAL_REPOSITORY_SNAPSHOT: RetentionPolicy(
            RetentionClass.EPHEMERAL_REPOSITORY_SNAPSHOT, timedelta(days=1)
        ),
        RetentionClass.SOURCE_BEARING_ARTIFACT: RetentionPolicy(
            RetentionClass.SOURCE_BEARING_ARTIFACT, timedelta(days=7)
        ),
        RetentionClass.EMBEDDING: RetentionPolicy(RetentionClass.EMBEDDING, timedelta(days=30)),
        RetentionClass.ANALYSIS_ARTIFACT: RetentionPolicy(
            RetentionClass.ANALYSIS_ARTIFACT, timedelta(days=180)
        ),
        RetentionClass.PDF_REPORT: RetentionPolicy(RetentionClass.PDF_REPORT, timedelta(days=365)),
        RetentionClass.WORKFLOW_EVENT: RetentionPolicy(
            RetentionClass.WORKFLOW_EVENT, timedelta(days=90)
        ),
        RetentionClass.AUDIT_RECORD: RetentionPolicy(RetentionClass.AUDIT_RECORD, None),
        RetentionClass.GITHUB_PUBLICATION_RECORD: RetentionPolicy(
            RetentionClass.GITHUB_PUBLICATION_RECORD, None
        ),
    }
    return MappingProxyType(policies)


@dataclass(frozen=True)
class RetentionPolicySet:
    policies: Mapping[RetentionClass, RetentionPolicy] = field(default_factory=_default_policies)

    def __post_init__(self) -> None:
        normalized = dict(self.policies)
        missing = set(RetentionClass) - normalized.keys()
        if missing:
            raise ValueError(f"retention policies are missing classes: {sorted(item.value for item in missing)}")
        for retention_class, policy in normalized.items():
            if retention_class != policy.retention_class:
                raise ValueError("retention policy key does not match its class")
        object.__setattr__(self, "policies", MappingProxyType(normalized))

    def policy_for(self, retention_class: RetentionClass) -> RetentionPolicy:
        return self.policies[retention_class]

    def eligible_at(self, artifact: CanonicalArtifact) -> datetime | None:
        minimum_age = self.policy_for(artifact.retention_class).minimum_age
        return artifact.created_at + minimum_age if minimum_age is not None else None


@dataclass(frozen=True)
class DeletionEvaluation:
    artifact_id: str
    eligible: bool
    eligible_at: datetime | None
    blocker_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeletionRequestResult:
    artifact_id: str
    status: str
    blocker_codes: tuple[str, ...] = ()
    tombstone: TombstoneRequest | None = None


@dataclass(frozen=True)
class ReconciliationSummary:
    examined: int
    deleted: int
    blocked: int
    retryable_failures: int
    permanent_failures: int


class ArtifactLifecycleService:
    """Policy gate for payload deletion; artifact metadata is never erased."""

    def __init__(
        self,
        registry: ArtifactRegistry,
        *,
        policies: RetentionPolicySet | None = None,
    ) -> None:
        self.registry = registry
        self.policies = policies or RetentionPolicySet()

    def evaluate(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        now: datetime | None = None,
        tenant_deletion: bool = False,
        deletion_scope: frozenset[str] = frozenset(),
    ) -> DeletionEvaluation:
        now = _as_utc(now or datetime.now(timezone.utc))
        artifact = self.registry.get(tenant_id=tenant_id, artifact_id=artifact_id)
        if self.registry.has_tombstone(tenant_id=tenant_id, artifact_id=artifact_id):
            return DeletionEvaluation(artifact_id, True, now)

        eligible_at = now if tenant_deletion else self.policies.eligible_at(artifact)
        blockers: list[str] = []
        if eligible_at is None:
            blockers.append("RETENTION_INDEFINITE")
        elif now < _as_utc(eligible_at):
            blockers.append("RETENTION_NOT_EXPIRED")
        active_references = self.registry.active_reference_ids(
            tenant_id=tenant_id, artifact_id=artifact_id
        )
        if active_references:
            blockers.append("ACTIVE_RESOURCE_REFERENCE")
        active_dependents = set(
            self.registry.active_dependent_ids(tenant_id=tenant_id, artifact_id=artifact_id)
        ) - set(deletion_scope)
        if active_dependents:
            blockers.append("ACTIVE_LINEAGE_DEPENDENT")
        return DeletionEvaluation(
            artifact_id=artifact_id,
            eligible=not blockers,
            eligible_at=eligible_at,
            blocker_codes=tuple(blockers),
        )

    def request_deletion(
        self,
        *,
        tenant_id: str,
        artifact_id: str,
        reason_code: str,
        requested_by: str,
        request_id: str,
        now: datetime | None = None,
    ) -> DeletionRequestResult:
        now = _as_utc(now or datetime.now(timezone.utc))
        evaluation = self.evaluate(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            now=now,
        )
        if not evaluation.eligible:
            return DeletionRequestResult(
                artifact_id=artifact_id,
                status="BLOCKED",
                blocker_codes=evaluation.blocker_codes,
            )
        tombstone = self.registry.create_tombstone(
            tenant_id=tenant_id,
            artifact_id=artifact_id,
            reason_code=reason_code,
            requested_by=requested_by,
            request_id=request_id,
            requested_at=now,
            eligible_at=evaluation.eligible_at or now,
        )
        return DeletionRequestResult(
            artifact_id=artifact_id,
            status="REUSED" if tombstone.reused else "REQUESTED",
            tombstone=tombstone,
        )

    def garbage_collection_candidates(
        self,
        *,
        now: datetime | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> tuple[CanonicalArtifact, ...]:
        """Discover expired, unreferenced payloads without mutating lifecycle state."""

        now = _as_utc(now or datetime.now(timezone.utc))
        cutoffs = {
            retention_class.value: now - policy.minimum_age
            for retention_class, policy in self.policies.policies.items()
            if policy.minimum_age is not None
        }
        candidates = self.registry.list_expired_candidates(
            cutoffs=cutoffs,
            limit=limit,
            tenant_id=tenant_id,
        )
        return tuple(
            artifact
            for artifact in candidates
            if self.evaluate(
                tenant_id=artifact.tenant_id,
                artifact_id=artifact.artifact_id,
                now=now,
            ).eligible
        )

    def request_tenant_deletion(
        self,
        *,
        tenant_id: str,
        requested_by: str,
        request_id: str,
        now: datetime | None = None,
    ) -> tuple[DeletionRequestResult, ...]:
        """Tombstone one tenant's artifact graph as one caller-owned transaction."""

        now = _as_utc(now or datetime.now(timezone.utc))
        artifact_ids = self.registry.list_active_artifact_ids(tenant_id=tenant_id, lock=True)
        deletion_scope = frozenset(artifact_ids)
        self.registry.release_tenant_references(
            tenant_id=tenant_id,
            reason_code="TENANT_DELETION",
        )
        results: list[DeletionRequestResult] = []
        for artifact_id in artifact_ids:
            evaluation = self.evaluate(
                tenant_id=tenant_id,
                artifact_id=artifact_id,
                now=now,
                tenant_deletion=True,
                deletion_scope=deletion_scope,
            )
            if not evaluation.eligible:
                results.append(
                    DeletionRequestResult(
                        artifact_id=artifact_id,
                        status="BLOCKED",
                        blocker_codes=evaluation.blocker_codes,
                    )
                )
                continue
            tombstone = self.registry.create_tombstone(
                tenant_id=tenant_id,
                artifact_id=artifact_id,
                reason_code="TENANT_DELETION",
                requested_by=requested_by,
                request_id=f"{request_id}:{artifact_id}",
                requested_at=now,
                eligible_at=now,
                deletion_scope=deletion_scope,
            )
            results.append(
                DeletionRequestResult(
                    artifact_id=artifact_id,
                    status="REUSED" if tombstone.reused else "REQUESTED",
                    tombstone=tombstone,
                )
            )
        return tuple(results)


class ArtifactDeletionReconciler:
    """Idempotently projects durable database tombstones into blob deletion."""

    def __init__(
        self,
        registry: ArtifactRegistry,
        store: ArtifactStore,
        *,
        retry_interval: timedelta = timedelta(minutes=1),
    ) -> None:
        if retry_interval.total_seconds() < 0:
            raise ValueError("retry_interval cannot be negative")
        self.registry = registry
        self.store = store
        self.retry_interval = retry_interval

    def reconcile(self, *, now: datetime | None = None, limit: int = 100) -> ReconciliationSummary:
        now = _as_utc(now or datetime.now(timezone.utc))
        pending = self.registry.pending_deletions(
            now=now,
            limit=limit,
            retry_before=now - self.retry_interval,
        )
        deleted = blocked = retryable = permanent = 0
        for deletion in pending:
            outcome = self._reconcile_one(deletion, now=now)
            if outcome == "DELETED":
                deleted += 1
            elif outcome == "BLOCKED":
                blocked += 1
            elif outcome == "RETRYABLE_FAILURE":
                retryable += 1
            else:
                permanent += 1
        return ReconciliationSummary(len(pending), deleted, blocked, retryable, permanent)

    def _reconcile_one(self, deletion: PendingDeletion, *, now: datetime) -> str:
        references = self.registry.active_reference_ids(
            tenant_id=deletion.tenant_id,
            artifact_id=deletion.artifact_id,
        )
        dependents = self.registry.active_dependent_ids(
            tenant_id=deletion.tenant_id,
            artifact_id=deletion.artifact_id,
        )
        if references or dependents:
            blockers = []
            if references:
                blockers.append("ACTIVE_RESOURCE_REFERENCE")
            if dependents:
                blockers.append("ACTIVE_LINEAGE_DEPENDENT")
            self.registry.record_deletion_attempt(
                tombstone_id=deletion.tombstone_id,
                outcome="BLOCKED",
                blocker_codes=blockers,
                attempted_at=now,
            )
            return "BLOCKED"

        try:
            self.store.tombstone(deletion.locator, reason_code=deletion.reason_code)
            if self.store.exists(deletion.locator, include_tombstoned=True):
                if not self.store.verify_digest(deletion.locator, deletion.content_digest):
                    raise ArtifactIntegrityError("artifact digest mismatch during deletion reconciliation")
                self.store.delete(deletion.locator, expected_digest=deletion.content_digest)
            self.registry.record_deletion_attempt(
                tombstone_id=deletion.tombstone_id,
                outcome="DELETED",
                observed_digest=deletion.content_digest,
                attempted_at=now,
            )
            return "DELETED"
        except ArtifactIntegrityError:
            self.registry.record_deletion_attempt(
                tombstone_id=deletion.tombstone_id,
                outcome="PERMANENT_FAILURE",
                failure_code="CONTENT_DIGEST_MISMATCH",
                attempted_at=now,
            )
            return "PERMANENT_FAILURE"
        except ArtifactConflictError:
            self.registry.record_deletion_attempt(
                tombstone_id=deletion.tombstone_id,
                outcome="RETRYABLE_FAILURE",
                failure_code="CONCURRENT_STORAGE_CHANGE",
                attempted_at=now,
            )
            return "RETRYABLE_FAILURE"
        except (ArtifactStoreError, OSError):
            self.registry.record_deletion_attempt(
                tombstone_id=deletion.tombstone_id,
                outcome="RETRYABLE_FAILURE",
                failure_code="STORAGE_UNAVAILABLE",
                attempted_at=now,
            )
            return "RETRYABLE_FAILURE"


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
