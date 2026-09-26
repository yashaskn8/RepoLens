"""Read-only readiness checks for schema required by repository analysis."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.orm import Session


REQUIRED_SCAN_STORAGE_TABLES = frozenset(
    {
        "index_writers",
        "index_snapshots",
        "index_trees",
        "index_entries",
        "index_projections",
        "index_pins",
        "index_facts",
        "index_postings",
        "index_signals",
    }
)


def missing_scan_storage_tables(db: Session) -> frozenset[str]:
    """Return missing scan-authority tables without mutating the database."""
    available = set(inspect(db.get_bind()).get_table_names())
    return REQUIRED_SCAN_STORAGE_TABLES.difference(available)


@lru_cache(maxsize=1)
def required_application_tables() -> frozenset[str]:
    """Return all ORM tables after importing the canonical model package once."""
    import app.models  # noqa: F401 - imports every mapped model module

    from app.models import Base

    return frozenset(Base.metadata.tables)


@lru_cache(maxsize=1)
def expected_alembic_heads() -> tuple[str, ...]:
    """Resolve immutable repository migration heads without connecting to a DB."""
    backend_root = Path(__file__).resolve().parents[2]
    ini_path = backend_root / "alembic.ini"
    if not ini_path.is_file():
        raise RuntimeError("Repository migration metadata is unavailable.") from None
    try:
        config = Config(str(ini_path))
        config.set_main_option("script_location", str(backend_root / "alembic"))
        heads = tuple(sorted(ScriptDirectory.from_config(config).get_heads()))
    except Exception:
        raise RuntimeError("Repository migration metadata is invalid.") from None
    if not heads:
        raise RuntimeError("Repository migration metadata has no head.")
    return heads


def current_alembic_heads(db: Session, available_tables: set[str] | None = None) -> tuple[str, ...]:
    """Read current database migration heads without applying migrations."""
    available = available_tables
    if available is None:
        available = set(inspect(db.get_bind()).get_table_names())
    if "alembic_version" not in available:
        return ()
    try:
        return tuple(sorted(MigrationContext.configure(db.connection()).get_current_heads()))
    except Exception:
        # Driver exceptions can contain the database URL or deployment details.
        return ()


def migration_revision_is_current(db: Session, available_tables: set[str] | None = None) -> bool:
    """Require exact equality with all current repository Alembic heads."""
    try:
        expected = expected_alembic_heads()
        current = current_alembic_heads(db, available_tables)
    except Exception:
        return False
    return bool(expected) and current == expected


__all__ = [
    "REQUIRED_SCAN_STORAGE_TABLES",
    "current_alembic_heads",
    "expected_alembic_heads",
    "migration_revision_is_current",
    "missing_scan_storage_tables",
    "required_application_tables",
]
