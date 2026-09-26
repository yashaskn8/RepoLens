"""Fail-closed, secret-safe production authority and storage preflight checks."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Callable

from sqlalchemy import text
from sqlalchemy.orm import Session

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
    """Verify local artifact directories before workers or traffic can use them."""
    configured_paths = [Path(settings.REPORT_ARTIFACT_DIR)]
    if settings.ARTIFACT_STORAGE_BACKEND == "local":
        configured_paths.append(Path(settings.ARTIFACT_ROOT_DIR))
    for configured_path in configured_paths:
        _probe_writable_directory(configured_path)


__all__ = [
    "validate_production_artifact_storage",
    "validate_production_database_schema",
]
