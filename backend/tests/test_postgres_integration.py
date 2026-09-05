"""Opt-in PostgreSQL persistence, recovery, and pgvector integration proofs."""

from dataclasses import replace
import os
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.graph.persistent import PersistentRepositoryGraph
from app.indexing.facts import select_candidates
from app.indexing.persistent import IndexLimits, PersistentIndex
from app.ingestion.git_inventory import InventoryBound
from tests.test_alembic_migrations import _get_alembic_config


POSTGRES_URL = os.environ.get("REPOLENS_POSTGRES_TEST_URL", "")
pytestmark = [pytest.mark.integration,
    pytest.mark.skipif(not POSTGRES_URL, reason="REPOLENS_POSTGRES_TEST_URL is not configured")]


def _driver_url() -> str:
    if POSTGRES_URL.startswith("postgresql://"):
        return "postgresql+psycopg://" + POSTGRES_URL.removeprefix("postgresql://")
    if POSTGRES_URL.startswith("postgres://"):
        return "postgresql+psycopg://" + POSTGRES_URL.removeprefix("postgres://")
    return POSTGRES_URL


def _repository(path: Path) -> tuple[str, str]:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "postgres-test@invalid"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "RepoLens PostgreSQL Test"], check=True)
    (path / "service.py").write_text(
        "import time\nasync def refresh(value):\n    time.sleep(1)\n    return value\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-qm", "fixture"], check=True)
    sha = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    return str(path), sha


def test_postgres_persistent_index_pin_candidates_reader_writer_and_timeout(tmp_path):
    config = _get_alembic_config(_driver_url())
    command.upgrade(config, "head")
    engine = create_engine(_driver_url(), pool_pre_ping=True, pool_timeout=2)
    sessions = sessionmaker(bind=engine)
    first_db, reader_db = sessions(), sessions()
    repo, sha = _repository(tmp_path / "repo")
    tenant, repository_url = f"pg-test-{uuid4()}", f"benchmark://{uuid4()}"
    limits = replace(IndexLimits(), query_seconds=0.05)
    first = PersistentIndex(first_db, tenant_id=tenant, repository_url=repository_url,
                            repo_dir=repo, commit_sha=sha, limits=limits)
    first.build_manifest()
    first.pin(str(uuid4()), owner_kind="evidence")
    assert select_candidates(first, "bug")
    reader = PersistentIndex(reader_db, tenant_id=tenant, repository_url=repository_url,
                             repo_dir=repo, commit_sha=sha, limits=limits)
    reader.open_snapshot(first.snapshot_id)
    assert PersistentRepositoryGraph(reader).get_node("file:service.py") is not None
    first._acquire_writer()
    try:
        contender_db = sessions()
        contender = PersistentIndex(contender_db, tenant_id=tenant, repository_url=repository_url,
                                    repo_dir=repo, commit_sha=sha, limits=limits)
        with pytest.raises(InventoryBound, match="index_writer_busy"):
            contender._acquire_writer()
        contender_db.close()
    finally:
        first._release_writer()
    assert first.query_rows(text("SELECT pg_sleep(0.25)")) == []
    assert first.query_coverage["query_budget_exhausted"]
    assert first.query_rows(text("SELECT 1"))[0][0] == 1
    first_db.close()
    reader_db.close()
    engine.dispose()


@pytest.mark.skipif(os.environ.get("REPOLENS_POSTGRES_TEST_ALLOW_SCHEMA_RESET") != "1",
                    reason="schema reset requires explicit disposable-database authorization")
def test_postgres_migration_round_trip_on_explicit_disposable_database():
    config = _get_alembic_config(_driver_url())
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    engine = create_engine(_driver_url())
    try:
        tables = set(inspect(engine).get_table_names())
        expected = {"index_snapshots", "index_signals"}
        if os.environ.get("ENABLE_PGVECTOR", "").lower() in {"1", "true", "yes", "on"}:
            expected.add("code_embeddings")
        assert expected.issubset(tables)
    finally:
        engine.dispose()
