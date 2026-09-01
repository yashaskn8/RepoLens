"""Focused invariants for canonical artifacts, storage, and safe deletion."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.artifacts.lifecycle import ArtifactDeletionReconciler, ArtifactLifecycleService
from app.artifacts.registry import (
    ArtifactLifecycleConflict,
    ArtifactProvenanceError,
    ArtifactRegistry,
)
from app.artifacts.schemas import (
    AnalyzerRunArtifact,
    ArtifactCoverage,
    ArtifactLineageEdge,
    ArtifactSensitivity,
    ClaimArtifact,
    CoverageStatus,
    EvidenceArtifact,
    FindingArtifact,
    LineageRelation,
    RepositoryRevisionArtifact,
    RetentionClass,
)
from app.artifacts.store import (
    ArtifactIntegrityError,
    ArtifactPutRequest,
    ArtifactTombstonedError,
    BlobAlreadyExists,
    BlobObjectHead,
    LocalArtifactStore,
    ProductionBlobArtifactStore,
    ProductionBlobStoreConfig,
)


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
CONFIG_DIGEST = hashlib.sha256(b"{}").hexdigest()


def _put(store, artifact_id: str, payload: bytes, *, tenant_id: str = "tenant-a"):
    digest = hashlib.sha256(payload).hexdigest()
    request = ArtifactPutRequest(
        tenant_id=tenant_id,
        artifact_id=artifact_id,
        expected_digest=digest,
        expected_size_bytes=len(payload),
        content_type="application/json",
        sensitivity=ArtifactSensitivity.SOURCE_DERIVED,
        retention_class=RetentionClass.ANALYSIS_ARTIFACT,
    )
    return store.put(request, io.BytesIO(payload))


def _edge(artifact_id: str, relation: LineageRelation, target_id: str) -> ArtifactLineageEdge:
    return ArtifactLineageEdge(
        tenant_id="tenant-a",
        artifact_id=artifact_id,
        relation=relation,
        related_artifact_id=target_id,
        created_at=NOW,
    )


def _record(cls, store, artifact_id: str, *, lineage=()):
    payload = ("payload:" + artifact_id).encode("utf-8")
    metadata = _put(store, artifact_id, payload)
    return cls(
        artifact_id=artifact_id,
        tenant_id="tenant-a",
        repository_id="repository-a",
        revision_id="revision-a",
        schema_version="1.0",
        content_digest=metadata.content_digest,
        payload_locator=metadata.locator,
        payload_size_bytes=metadata.size_bytes,
        producer="repolens-test",
        producer_version="1.0",
        producer_config_digest=CONFIG_DIGEST,
        policy_snapshot_id="policy-a",
        created_at=NOW - timedelta(days=400),
        lineage=lineage,
        coverage=ArtifactCoverage(
            status=CoverageStatus.SUCCESSFULLY_ANALYZED,
            discovered_count=1,
            analyzed_count=1,
        ),
        sensitivity=ArtifactSensitivity.SOURCE_DERIVED,
        retention_class=RetentionClass.ANALYSIS_ARTIFACT,
    )


def test_local_store_is_atomic_content_addressed_and_tombstone_guarded(tmp_path: Path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    payload = b'{"safe":true}'
    first = _put(store, "artifact-a", payload)
    second = _put(store, "artifact-a", payload)

    assert first.locator == second.locator
    assert first.content_digest == hashlib.sha256(payload).hexdigest()
    with store.get(first.locator) as stream:
        assert stream.read() == payload
    assert store.verify_digest(first.locator, first.content_digest)

    assert store.tombstone(first.locator, reason_code="RETENTION_EXPIRED") is True
    assert store.tombstone(first.locator, reason_code="RETENTION_EXPIRED") is False
    assert not store.exists(first.locator)
    assert store.exists(first.locator, include_tombstoned=True)
    with pytest.raises(ArtifactTombstonedError):
        store.get(first.locator)
    with pytest.raises(ArtifactIntegrityError):
        store.delete(first.locator, expected_digest="0" * 64)

    deletion = store.delete(first.locator, expected_digest=first.content_digest)
    assert deletion.deleted is True
    assert not store.exists(first.locator, include_tombstoned=True)


class _MemoryBlobClient:
    def __init__(self):
        self.objects: dict[str, tuple[bytes, BlobObjectHead]] = {}

    def put_if_absent(
        self,
        key,
        payload,
        *,
        content_length,
        content_type,
        metadata,
        require_server_side_encryption,
    ):
        if key in self.objects:
            raise BlobAlreadyExists()
        value = payload.read()
        assert len(value) == content_length
        assert require_server_side_encryption is True
        complete_metadata = dict(metadata)
        complete_metadata["content-type"] = content_type
        head = BlobObjectHead(
            key=key,
            size_bytes=len(value),
            etag=hashlib.sha256(value).hexdigest(),
            content_type=content_type,
            metadata=complete_metadata,
            last_modified=NOW,
        )
        self.objects[key] = (value, head)
        return head

    def open_read(self, key):
        if key not in self.objects:
            raise ArtifactLifecycleConflict("missing test blob")
        return io.BytesIO(self.objects[key][0])

    def head(self, key):
        item = self.objects.get(key)
        return item[1] if item else None

    def delete_if_match(self, key, *, etag):
        item = self.objects.get(key)
        if item is None or item[1].etag != etag:
            return False
        del self.objects[key]
        return True


def test_vendor_neutral_blob_adapter_uses_conditional_publication_and_deletion():
    client = _MemoryBlobClient()
    store = ProductionBlobArtifactStore(ProductionBlobStoreConfig(), client)
    metadata = _put(store, "artifact-a", b"blob-payload")

    reused = _put(store, "artifact-a", b"blob-payload")
    assert reused.locator == metadata.locator
    assert reused.content_type == "application/json"
    assert store.tombstone(metadata.locator, reason_code="TENANT_DELETION")
    assert store.delete(metadata.locator, expected_digest=metadata.content_digest).deleted


def test_registry_enforces_traceability_and_reference_safe_reconciliation(db_session, tmp_path: Path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    registry = ArtifactRegistry(db_session, store=store)

    revision = _record(RepositoryRevisionArtifact, store, "revision-artifact")
    analyzer = _record(
        AnalyzerRunArtifact,
        store,
        "analyzer-artifact",
        lineage=(_edge("analyzer-artifact", LineageRelation.DERIVED_FROM, revision.artifact_id),),
    )
    evidence = _record(
        EvidenceArtifact,
        store,
        "evidence-artifact",
        lineage=(_edge("evidence-artifact", LineageRelation.PRODUCED_BY, analyzer.artifact_id),),
    )
    claim = _record(
        ClaimArtifact,
        store,
        "claim-artifact",
        lineage=(_edge("claim-artifact", LineageRelation.DERIVED_FROM, evidence.artifact_id),),
    )
    finding = _record(
        FindingArtifact,
        store,
        "finding-artifact",
        lineage=(_edge("finding-artifact", LineageRelation.DERIVED_FROM, claim.artifact_id),),
    )

    for artifact in (revision, analyzer, evidence, claim, finding):
        assert registry.register(artifact).reused is False
    assert registry.register(finding).reused is True
    registry.assert_finding_traceable(tenant_id="tenant-a", artifact_id=finding.artifact_id)

    orphan = _record(FindingArtifact, store, "orphan-finding")
    with pytest.raises(ArtifactProvenanceError):
        registry.register(orphan)

    reference = registry.acquire_reference(
        tenant_id="tenant-a",
        artifact_id=finding.artifact_id,
        referrer_kind="REPORT",
        referrer_id="report-a",
    )
    lifecycle = ArtifactLifecycleService(registry)
    blocked = lifecycle.request_deletion(
        tenant_id="tenant-a",
        artifact_id=finding.artifact_id,
        reason_code="RETENTION_EXPIRED",
        requested_by="system",
        request_id="delete-a",
        now=NOW,
    )
    assert blocked.status == "BLOCKED"
    assert "ACTIVE_RESOURCE_REFERENCE" in blocked.blocker_codes

    assert registry.release_reference(reference_id=reference.reference_id, reason_code="REPORT_RELEASED")
    requested = lifecycle.request_deletion(
        tenant_id="tenant-a",
        artifact_id=finding.artifact_id,
        reason_code="RETENTION_EXPIRED",
        requested_by="system",
        request_id="delete-a",
        now=NOW,
    )
    assert requested.status == "REQUESTED"
    db_session.flush()

    reconciler = ArtifactDeletionReconciler(registry, store, retry_interval=timedelta(0))
    summary = reconciler.reconcile(now=NOW)
    assert summary.deleted == 1
    assert not store.exists(finding.payload_locator, include_tombstoned=True)
    assert registry.get(tenant_id="tenant-a", artifact_id=finding.artifact_id).artifact_id == finding.artifact_id

    tenant_results = lifecycle.request_tenant_deletion(
        tenant_id="tenant-a",
        requested_by="system",
        request_id="tenant-delete-a",
        now=NOW,
    )
    assert tenant_results
    assert all(result.status == "REQUESTED" for result in tenant_results)
    final_summary = reconciler.reconcile(now=NOW)
    assert final_summary.deleted == 4
    assert all(
        not store.exists(artifact.payload_locator, include_tombstoned=True)
        for artifact in (revision, analyzer, evidence, claim, finding)
    )


def test_artifact_records_are_frozen_and_reject_ambiguous_coverage(tmp_path: Path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    artifact = _record(RepositoryRevisionArtifact, store, "revision-artifact")
    with pytest.raises(ValidationError):
        artifact.producer = "mutated"
    with pytest.raises(ValidationError):
        ArtifactCoverage(status=CoverageStatus.UNAVAILABLE)
