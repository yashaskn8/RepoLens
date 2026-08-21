"""Tests for Phase 3.5K: Database Schema Correctness and Alembic Migrations Authority."""

import os
import tempfile
from uuid import uuid4
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict


def _get_alembic_config(db_url: str) -> Config:
    """Create Alembic Config pointing to the backend's alembic.ini with custom test database URL."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ini_path = os.path.join(base_dir, "alembic.ini")
    cfg = Config(ini_path)
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.set_main_option("script_location", os.path.join(base_dir, "alembic"))
    return cfg


def test_alembic_upgrade_head_on_empty_db_creates_complete_schema():
    """Verify that 'alembic upgrade head' on a clean empty database creates all required tables,
    columns, foreign keys, and indexes matching the ORM models exactly.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_migration.db")
        db_url = f"sqlite:///{db_path}"

        alembic_cfg = _get_alembic_config(db_url)

        # 1. Run Alembic upgrade to head
        command.upgrade(alembic_cfg, "head")

        # 2. Inspect created schema
        engine = create_engine(db_url)
        try:
            inspector = inspect(engine)

            table_names = set(inspector.get_table_names())
            expected_tables = {"scans", "findings", "evidences", "patches", "alembic_version"}
            assert expected_tables.issubset(table_names), f"Missing tables: {expected_tables - table_names}"

            # 3. Verify 'patches' table columns
            patch_cols = {col["name"]: col for col in inspector.get_columns("patches")}
            expected_patch_cols = {
                "id", "finding_id", "plan_id", "scan_id", "thread_id", "status",
                "unified_diff", "files_modified", "explanation", "expected_behavior_change",
                "generated_tests_or_test_plan", "verification_report", "critic_report",
                "user_feedback", "approved_by", "approved_at", "rejected_reason",
                "model_metadata", "created_at", "updated_at",
            }
            assert expected_patch_cols.issubset(set(patch_cols.keys())), f"Missing patch columns: {expected_patch_cols - set(patch_cols.keys())}"

            # 4. Verify 'patches' foreign keys
            fks = inspector.get_foreign_keys("patches")
            fk_targets = {fk["referred_table"] for fk in fks}
            assert "findings" in fk_targets
            assert "scans" in fk_targets

            # 5. Verify 'patches' indexes
            indexes = {idx["name"] for idx in inspector.get_indexes("patches")}
            assert any("ix_patches_id" in idx for idx in indexes)
            assert any("ix_patches_finding_id" in idx for idx in indexes)
            assert any("ix_patches_scan_id" in idx for idx in indexes)
            assert any("ix_patches_thread_id" in idx for idx in indexes)
            assert any("ix_patches_status" in idx for idx in indexes)

            # 6. Verify ORM read/write compatibility against migrated database
            SessionLocal = sessionmaker(bind=engine)
            db = SessionLocal()

            scan = ScanModel(
                id=str(uuid4()),
                repository_url="https://github.com/fastapi/fastapi",
                status=ScanStatus.COMPLETED.value,
                commit_hash="abcdef123456",
            )
            db.add(scan)

            finding = FindingModel(
                id=str(uuid4()),
                scan_id=scan.id,
                title="Insecure cookie",
                description="Missing flags",
                severity=Severity.HIGH.value,
                status=FindingStatus.OPEN.value,
                verification_verdict=VerificationVerdict.CONFIRMED.value,
            )
            db.add(finding)

            evidence = EvidenceModel(
                id=str(uuid4()),
                finding_id=finding.id,
                file_path="app/auth.py",
                start_line=1,
                end_line=2,
                code_snippet="set_cookie()",
            )
            db.add(evidence)

            patch = PatchModel(
                id=str(uuid4()),
                finding_id=finding.id,
                scan_id=scan.id,
                thread_id=f"remediation-{uuid4()}",
                status=PatchStatus.VERIFIED.value,
                unified_diff="--- a/auth.py\n+++ b/auth.py\n",
                files_modified=["app/auth.py"],
                explanation="Hardened cookie",
                expected_behavior_change="Flags added",
                verification_report={"status": "PASSED"},
            )
            db.add(patch)
            db.commit()

            # Read back and verify relationships
            persisted_patch = db.query(PatchModel).filter(PatchModel.id == patch.id).first()
            assert persisted_patch is not None
            assert persisted_patch.finding.title == "Insecure cookie"
            assert persisted_patch.scan.repository_url == "https://github.com/fastapi/fastapi"
            assert persisted_patch.status == "VERIFIED"

            db.close()
        finally:
            engine.dispose()


def test_alembic_migration_upgrade_downgrade_reupgrade_cycle():
    """Verify upgrade -> downgrade one revision -> upgrade again works cleanly without errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_cycle.db")
        db_url = f"sqlite:///{db_path}"

        alembic_cfg = _get_alembic_config(db_url)
        engine = create_engine(db_url)

        try:
            # 1. Upgrade to head (002_patches_table)
            command.upgrade(alembic_cfg, "head")
            inspector = inspect(engine)
            assert "patches" in inspector.get_table_names()
            assert "findings" in inspector.get_table_names()

            # 2. Downgrade one revision (back to 001_initial_schema)
            command.downgrade(alembic_cfg, "001_initial_schema")
            inspector = inspect(engine)
            assert "patches" not in inspector.get_table_names()
            assert "findings" in inspector.get_table_names()
            assert "scans" in inspector.get_table_names()
            assert "evidences" in inspector.get_table_names()

            # 3. Upgrade again to head
            command.upgrade(alembic_cfg, "head")
            inspector = inspect(engine)
            assert "patches" in inspector.get_table_names()
            patch_cols = {col["name"] for col in inspector.get_columns("patches")}
            assert "thread_id" in patch_cols
            assert "verification_report" in patch_cols

            # 4. Downgrade all the way to base
            command.downgrade(alembic_cfg, "base")
            inspector = inspect(engine)
            user_tables = [t for t in inspector.get_table_names() if t != "alembic_version"]
            assert len(user_tables) == 0, f"Expected zero user tables after downgrade to base, got {user_tables}"

            # 5. Re-upgrade all the way to head
            command.upgrade(alembic_cfg, "head")
            inspector = inspect(engine)
            assert {"scans", "findings", "evidences", "patches"}.issubset(set(inspector.get_table_names()))
        finally:
            engine.dispose()


@pytest.mark.asyncio
async def test_production_startup_does_not_mutate_schema_silently():
    """Verify that application lifespan startup does NOT execute Base.metadata.create_all() silently."""
    from app.main import app, lifespan

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "unmigrated.db")
        db_url = f"sqlite:///{db_path}"

        raw_engine = create_engine(db_url)
        try:
            inspector_before = inspect(raw_engine)
            assert len(inspector_before.get_table_names()) == 0

            # Execute lifespan
            async with lifespan(app):
                pass

            inspector_after = inspect(raw_engine)
            # Verify startup did NOT create tables silently in production
            assert len(inspector_after.get_table_names()) == 0
        finally:
            raw_engine.dispose()
