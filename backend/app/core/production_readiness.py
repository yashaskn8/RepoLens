"""Fail-closed, secret-safe production authority and storage preflight checks."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import tempfile
from typing import Callable
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.artifacts.schemas import ArtifactSensitivity, RetentionClass
from app.artifacts.service import get_artifact_store
from app.artifacts.store import (
    ArtifactPutRequest,
    ArtifactStore,
    LocalArtifactStore,
    ProductionBlobArtifactStore,
    artifact_locator,
)
from app.core.config import Settings


def validate_production_database_schema(session_factory: Callable[[], Session]) -> None:
    """Require PostgreSQL connectivity, current migrations, and all ORM tables."""
    from app.observability.operations import schema_readiness

    try:
        with session_factory() as db:
            bind = db.get_bind()
            if bind.dialect.name != "postgresql":
                raise RuntimeError("Production database dialect is invalid.")
            db.execute(text("SELECT 1"))
            readiness = schema_readiness(db)
    except Exception:
        # Database exceptions may embed connection strings or deployment paths.
        raise RuntimeError("Production PostgreSQL schema readiness validation failed.") from None
    if not readiness.get("ready"):
        raise RuntimeError("Production PostgreSQL schema is not fully migrated.")


def _probe_writable_directory(path: Path) -> None:
    probe_path: Path | None = None
    try:
        root = path.expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".repolens-write-check-", dir=str(root))
        probe_path = Path(name)
        os.close(descriptor)
    except Exception:
        raise RuntimeError("Configured production artifact storage is not writable.") from None
    finally:
        if probe_path is not None:
            try:
                probe_path.unlink(missing_ok=True)
            except OSError:
                raise RuntimeError("Production artifact storage write check could not be cleaned up.") from None


def validate_production_artifact_storage(settings: Settings) -> None:
    """Exercise the configured storage contract without retaining probe objects.

    Filesystem checks cannot prove that a mount survives replacement of the
    process/container. ``single_persistent_local`` is therefore an explicit
    operator deployment contract, not an inferred property of the path.
    """
    if settings.ARTIFACT_DEPLOYMENT_MODE == "shared":
        # get_artifact_store deliberately fails unless an actual conditional
        # adapter has been installed by application bootstrap.
        try:
            store = get_artifact_store(settings)
        except Exception:
            raise RuntimeError(
                "Shared artifact storage requires a configured ConditionalBlobClient adapter."
            ) from None
        if not isinstance(store, ProductionBlobArtifactStore):
            raise RuntimeError(
                "Shared artifact storage requires the conditional production blob adapter."
            )
        _probe_artifact_store(store)
    elif (
        settings.ARTIFACT_DEPLOYMENT_MODE == "single_persistent_local"
        and settings.ARTIFACT_STORAGE_BACKEND == "local"
    ):
        root = Path(settings.ARTIFACT_ROOT_DIR).expanduser().resolve()
        _probe_writable_directory(root)
        probe_parent = Path(tempfile.mkdtemp(prefix=".repolens-store-probe-", dir=str(root)))
        try:
            _probe_artifact_store(LocalArtifactStore(probe_parent))
        finally:
            import shutil

            shutil.rmtree(probe_parent, ignore_errors=False)
    else:
        raise RuntimeError("Production artifact storage mode is invalid or unsupported.")

    _probe_report_staging_directory(Path(settings.REPORT_ARTIFACT_DIR))


def _probe_artifact_store(store: ArtifactStore) -> None:
    """Use only bounded immutable test bytes and require read/digest/delete semantics."""
    payload = b"RepoLens production storage readiness probe v1"
    digest = hashlib.sha256(payload).hexdigest()
    artifact_id = uuid4().hex
    request = ArtifactPutRequest(
        tenant_id="repolens-readiness",
        artifact_id=artifact_id,
        expected_digest=digest,
        expected_size_bytes=len(payload),
        content_type="application/octet-stream",
        sensitivity=ArtifactSensitivity.INTERNAL,
        retention_class=RetentionClass.EPHEMERAL_REPOSITORY_SNAPSHOT,
    )
    metadata = None
    locator = artifact_locator(request)
    try:
        metadata = store.publish_atomic(request, io.BytesIO(payload))
        if metadata.content_digest != digest or metadata.size_bytes != len(payload):
            raise RuntimeError("Artifact storage probe metadata did not match.")
        if not store.verify_digest(metadata.locator, digest):
            raise RuntimeError("Artifact storage probe digest did not match.")
        with store.get(metadata.locator) as stream:
            if stream.read(len(payload) + 1) != payload:
                raise RuntimeError("Artifact storage probe read-back did not match.")
        duplicate = store.publish_atomic(request, io.BytesIO(payload))
        if duplicate.locator != metadata.locator:
            raise RuntimeError("Artifact storage probe conditional publication failed.")
    except Exception:
        raise RuntimeError("Configured artifact storage failed its atomic read-back integrity probe.") from None
    finally:
        if metadata is None and store.exists(locator, include_tombstoned=True):
            try:
                metadata = store.metadata(locator, include_tombstoned=True)
            except Exception:
                raise RuntimeError("Configured artifact storage probe cleanup failed.") from None
        if metadata is not None:
            try:
                store.tombstone(metadata.locator, reason_code="READINESS_PROBE")
                store.delete(metadata.locator, expected_digest=digest)
                if store.exists(metadata.locator, include_tombstoned=True):
                    raise RuntimeError("Artifact storage probe cleanup failed.")
            except Exception:
                raise RuntimeError("Configured artifact storage probe cleanup failed.") from None


def _probe_report_staging_directory(path: Path) -> None:
    """Exercise the temporary renderer path with fsync, read-back and replace."""
    directory: Path | None = None
    first: Path | None = None
    second: Path | None = None
    try:
        root = path.expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix=".repolens-report-probe-", dir=str(root)))
        first = directory / "first.tmp"
        second = directory / "published.tmp"
        payload = b"RepoLens report staging readiness probe v1"
        with first.open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if first.read_bytes() != payload:
            raise RuntimeError("Report staging read-back failed.")
        os.replace(first, second)
        if second.read_bytes() != payload:
            raise RuntimeError("Report staging atomic replace failed.")
    except Exception:
        raise RuntimeError("Configured report temporary storage failed its write/read/replace probe.") from None
    finally:
        if directory is not None:
            import shutil

            shutil.rmtree(directory, ignore_errors=True)


__all__ = [
    "validate_production_artifact_storage",
    "validate_production_database_schema",
]
