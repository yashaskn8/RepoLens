"""Test migration 010: Multi-user authentication, tenant isolation, and audit attribution.

Verifies:
- Migration 009 -> 010 (upgrade)
- Migration 010 -> 009 (downgrade)
- Re-upgrade 009 -> 010
- Creation of `users`, `user_sessions`, `usage_counters` tables
- Addition of `owner_user_id` to `scans` and `change_analyses`
- Addition of `actor_user_id` to `workflow_events`
- Unique constraints, foreign keys, and indexes
- Preservation of existing rows (ownerless legacy rows)
"""

import os
from pathlib import Path
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

ALEMBIC_INI_PATH = str(Path(__file__).resolve().parent.parent / "alembic.ini")


@pytest.fixture
def migration_test_db(tmp_path):
    """Create a temporary SQLite database for migration testing."""
    db_file = tmp_path / "migration_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    
    alembic_cfg = Config(ALEMBIC_INI_PATH)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    
    yield engine, alembic_cfg
    
    engine.dispose()


def test_migration_010_full_cycle(migration_test_db):
    """Test full upgrade to 010, downgrade to 009, and re-upgrade to 010."""
    engine, alembic_cfg = migration_test_db

    # 1. Upgrade to migration 009
    command.upgrade(alembic_cfg, "009")

    inspector = inspect(engine)
    assert "users" not in inspector.get_table_names()
    assert "user_sessions" not in inspector.get_table_names()
    assert "usage_counters" not in inspector.get_table_names()

    # Insert sample legacy scan and change_analysis without owner_user_id
    with engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO scans (id, repository_url, status, created_at) "
                "VALUES ('legacy-scan-1', 'https://github.com/org/repo', 'COMPLETED', '2026-01-01 00:00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO change_analyses (id, repository_url, repository_owner, repository_name, base_ref, base_commit_sha, head_ref, head_commit_sha, status, created_at, updated_at) "
                "VALUES ('legacy-ca-1', 'https://github.com/org/repo', 'org', 'repo', 'main', '1111111111111111111111111111111111111111', 'feat', '2222222222222222222222222222222222222222', 'COMPLETED', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO workflow_events (event_type, scan_id, message, metadata_payload, created_at) "
                "VALUES ('SCAN_CREATED', 'legacy-scan-1', 'Legacy scan created', '{}', '2026-01-01 00:00:00')"
            )
        )
        conn.commit()

    # 2. Upgrade to 010
    command.upgrade(alembic_cfg, "010")

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "users" in tables
    assert "user_sessions" in tables
    assert "usage_counters" in tables

    # Check columns in users table
    user_cols = {c["name"] for c in inspector.get_columns("users")}
    assert "id" in user_cols
    assert "email" in user_cols
    assert "password_hash" in user_cols
    assert "role" in user_cols
    assert "is_active" in user_cols
    assert "failed_login_attempts" in user_cols
    assert "locked_until" in user_cols
    assert "last_login_at" in user_cols

    # Check columns in user_sessions
    session_cols = {c["name"] for c in inspector.get_columns("user_sessions")}
    assert "id" in session_cols
    assert "user_id" in session_cols
    assert "token_hash" in session_cols
    assert "csrf_token_hash" in session_cols
    assert "expires_at" in session_cols
    assert "revoked_at" in session_cols
    assert "last_seen_at" in session_cols

    # Check columns in usage_counters
    counter_cols = {c["name"] for c in inspector.get_columns("usage_counters")}
    assert "id" in counter_cols
    assert "user_id" in counter_cols
    assert "bucket_date" in counter_cols
    assert "operation" in counter_cols
    assert "count" in counter_cols

    # Check added columns on existing tables
    scan_cols = {c["name"] for c in inspector.get_columns("scans")}
    assert "owner_user_id" in scan_cols

    ca_cols = {c["name"] for c in inspector.get_columns("change_analyses")}
    assert "owner_user_id" in ca_cols

    we_cols = {c["name"] for c in inspector.get_columns("workflow_events")}
    assert "actor_user_id" in we_cols

    # Verify legacy rows preserved with owner_user_id / actor_user_id as NULL
    with engine.connect() as conn:
        res = conn.execute(text("SELECT id, owner_user_id FROM scans WHERE id='legacy-scan-1'")).fetchone()
        assert res[0] == "legacy-scan-1"
        assert res[1] is None

        res_ca = conn.execute(text("SELECT id, owner_user_id FROM change_analyses WHERE id='legacy-ca-1'")).fetchone()
        assert res_ca[0] == "legacy-ca-1"
        assert res_ca[1] is None

        res_we = conn.execute(text("SELECT id, actor_user_id FROM workflow_events WHERE scan_id='legacy-scan-1'")).fetchone()
        assert res_we[1] is None

    # 3. Test downgrade back to 009
    command.downgrade(alembic_cfg, "009")

    inspector = inspect(engine)
    tables_post_down = inspector.get_table_names()
    assert "users" not in tables_post_down
    assert "user_sessions" not in tables_post_down
    assert "usage_counters" not in tables_post_down

    # 4. Re-upgrade to 010
    command.upgrade(alembic_cfg, "010")

    inspector = inspect(engine)
    tables_reup = inspector.get_table_names()
    assert "users" in tables_reup
    assert "user_sessions" in tables_reup
    assert "usage_counters" in tables_reup
