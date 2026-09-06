"""Read-only readiness checks for schema required by repository analysis."""

from __future__ import annotations

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


__all__ = ["REQUIRED_SCAN_STORAGE_TABLES", "missing_scan_storage_tables"]
