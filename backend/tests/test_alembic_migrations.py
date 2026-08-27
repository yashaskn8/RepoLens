"""Tests for Phase 3.5K: Database Schema Correctness and Alembic Migrations Authority."""

import os
import tempfile
from uuid import UUID, uuid4
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.models.delivery import DeliveryModel
from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
from app.schemas.enums import DeliveryStatus, FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict


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
            expected_tables = {"scans", "findings", "evidences", "patches", "workflow_events", "deliveries", "alembic_version"}
            assert expected_tables.issubset(table_names), f"Missing tables: {expected_tables - table_names}"

            # 3. Verify 'patches' table columns
            patch_cols = {col["name"]: col for col in inspector.get_columns("patches")}
            expected_patch_cols = {
                "id", "finding_id", "plan_id", "scan_id", "parent_patch_id", "revision_number", "thread_id", "status",
                "machine_verdict", "unified_diff", "files_modified", "explanation", "expected_behavior_change",
                "generated_tests_or_test_plan", "verification_report", "critic_report",
                "user_feedback", "approved_by", "approved_at", "rejected_reason",
                "model_metadata", "created_at", "updated_at", "fix_plan_snapshot",
            }
            assert expected_patch_cols.issubset(set(patch_cols.keys())), f"Missing patch columns: {expected_patch_cols - set(patch_cols.keys())}"

            # 4. Verify 'findings' table columns
            finding_cols = {col["name"]: col for col in inspector.get_columns("findings")}
            expected_finding_cols = {
                "id", "scan_id", "title", "description", "severity", "status",
                "rule_id", "category", "mitigation_guidance", "verification_verdict",
                "verification_reason", "source_tool", "detector_id", "detector_kind",
                "model_metadata", "created_at", "updated_at",
            }
            assert expected_finding_cols.issubset(set(finding_cols.keys())), f"Missing finding columns: {expected_finding_cols - set(finding_cols.keys())}"

            # 5. Verify 'workflow_events' table columns
            event_cols = {col["name"]: col for col in inspector.get_columns("workflow_events")}
            expected_event_cols = {
                "id", "event_type", "scan_id", "finding_id", "patch_id", "delivery_id", "thread_id", "commit_sha",
                "stage", "tool_name", "provider", "model_name", "message", "metadata_payload", "created_at",
            }
            assert expected_event_cols.issubset(set(event_cols.keys())), f"Missing event columns: {expected_event_cols - set(event_cols.keys())}"

            # 6. Verify 'deliveries' table columns
            delivery_cols = {col["name"]: col for col in inspector.get_columns("deliveries")}
            expected_delivery_cols = {
                "id", "scan_id", "finding_id", "patch_id", "provider", "repository_url",
                "repository_owner", "repository_name", "base_branch", "scanned_base_sha",
                "observed_base_sha", "head_branch", "head_sha", "pr_number", "pr_url",
                "status", "failure_code", "failure_message", "idempotency_key",
                "requested_by", "attempt_count", "last_attempt_at", "created_at",
                "updated_at", "completed_at",
            }
            assert expected_delivery_cols.issubset(set(delivery_cols.keys())), f"Missing delivery columns: {expected_delivery_cols - set(delivery_cols.keys())}"

            # 7. Verify 'workflow_events' foreign keys
            event_fks = inspector.get_foreign_keys("workflow_events")
            event_fk_targets = {fk["referred_table"] for fk in event_fks}
            assert "scans" in event_fk_targets
            assert "findings" in event_fk_targets
            assert "patches" in event_fk_targets
            assert "deliveries" in event_fk_targets

            # 8. Verify 'deliveries' foreign keys
            del_fks = inspector.get_foreign_keys("deliveries")
            del_fk_targets = {fk["referred_table"] for fk in del_fks}
            assert "scans" in del_fk_targets
            assert "findings" in del_fk_targets
            assert "patches" in del_fk_targets

            # 9. Verify 'deliveries' indexes
            del_indexes = {idx["name"] for idx in inspector.get_indexes("deliveries")}
            assert any("ix_deliveries_id" in idx for idx in del_indexes)
            assert any("ix_deliveries_scan_id" in idx for idx in del_indexes)
            assert any("ix_deliveries_finding_id" in idx for idx in del_indexes)
            assert any("ix_deliveries_patch_id" in idx for idx in del_indexes)
            assert any("ix_deliveries_status" in idx for idx in del_indexes)
            assert any("ix_deliveries_idempotency_key" in idx for idx in del_indexes)

            # 10. Verify ORM read/write compatibility against migrated database
            SessionLocal = sessionmaker(bind=engine)
            db = SessionLocal()

            scan = ScanModel(
                id=str(uuid4()),
                repository_url="https://github.com/fastapi/fastapi",
                status=ScanStatus.COMPLETED.value,
                commit_hash="abcdef1234567890abcdef1234567890abcdef12",
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
                source_tool="semgrep",
                detector_id="python.cookie.missing-httponly",
                detector_kind="static_scanner",
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

            plan_id = uuid4()
            fix_plan = FixPlan(
                id=plan_id,
                finding_id=UUID(finding.id),
                root_cause="Insecure cookie flags",
                objective="Add Secure and HttpOnly flags",
                files_expected_to_change=["app/auth.py"],
                symbols_expected_to_change=[],
                ordered_changes=[
                    OrderedChangeStep(step_number=1, target_file="app/auth.py", description="Add flags", rationale="Security")
                ],
                validation_plan=["pytest"],
                estimated_scope=FixScope.FILE,
            )

            patch = PatchModel(
                id=str(uuid4()),
                finding_id=finding.id,
                plan_id=str(plan_id),
                fix_plan_snapshot=fix_plan.model_dump(mode="json"),
                scan_id=scan.id,
                thread_id=f"remediation-{uuid4()}",
                status=PatchStatus.APPROVED.value,
                machine_verdict="PASSED",
                unified_diff="--- a/auth.py\n+++ b/auth.py\n",
                files_modified=["app/auth.py"],
                explanation="Hardened cookie",
                expected_behavior_change="Flags added",
                verification_report={"status": "PASSED"},
                revision_number=0,
            )
            db.add(patch)

            delivery = DeliveryModel(
                id=str(uuid4()),
                scan_id=scan.id,
                finding_id=finding.id,
                patch_id=patch.id,
                provider="github",
                repository_url="https://github.com/fastapi/fastapi",
                repository_owner="fastapi",
                repository_name="fastapi",
                base_branch="main",
                scanned_base_sha="abcdef1234567890abcdef1234567890abcdef12",
                observed_base_sha="abcdef1234567890abcdef1234567890abcdef12",
                head_branch="repolens/fix-abc-123",
                head_sha="1234567890abcdef1234567890abcdef12345678",
                pr_number=42,
                pr_url="https://github.com/fastapi/fastapi/pull/42",
                status=DeliveryStatus.PR_CREATED.value,
                idempotency_key="key-12345",
                requested_by="security-team",
            )
            db.add(delivery)
            db.commit()

            # Read back and verify relationships and FixPlan JSON round-trip
            persisted_delivery = db.query(DeliveryModel).filter(DeliveryModel.id == delivery.id).first()
            assert persisted_delivery is not None
            assert persisted_delivery.pr_number == 42
            assert persisted_delivery.status == DeliveryStatus.PR_CREATED.value
            assert persisted_delivery.patch.status == PatchStatus.APPROVED.value
            assert persisted_delivery.patch.fix_plan_snapshot is not None
            round_trip_plan = FixPlan.model_validate(persisted_delivery.patch.fix_plan_snapshot)
            assert str(round_trip_plan.id) == persisted_delivery.patch.plan_id
            assert str(round_trip_plan.finding_id) == persisted_delivery.patch.finding_id
            assert persisted_delivery.finding.title == "Insecure cookie"
            assert persisted_delivery.scan.repository_url == "https://github.com/fastapi/fastapi"

            db.close()
        finally:
            engine.dispose()


def test_alembic_migration_upgrade_downgrade_reupgrade_cycle():
    """Verify upgrade -> downgrade revisions -> upgrade again works cleanly without errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_cycle.db")
        db_url = f"sqlite:///{db_path}"

        alembic_cfg = _get_alembic_config(db_url)
        engine = create_engine(db_url)

        try:
            # 1. Upgrade to head (007_patch_fix_plan_snapshot)
            command.upgrade(alembic_cfg, "head")
            inspector = inspect(engine)
            assert "deliveries" in inspector.get_table_names()
            assert "workflow_events" in inspector.get_table_names()
            assert "patches" in inspector.get_table_names()
            assert "findings" in inspector.get_table_names()
            patch_cols_head = {col["name"] for col in inspector.get_columns("patches")}
            assert "fix_plan_snapshot" in patch_cols_head

            # 2. Downgrade one revision (007 -> 006: drop fix_plan_snapshot)
            command.downgrade(alembic_cfg, "006_deliveries_table")
            inspector = inspect(engine)
            patch_cols_006 = {col["name"] for col in inspector.get_columns("patches")}
            assert "fix_plan_snapshot" not in patch_cols_006
            assert "deliveries" in inspector.get_table_names()

            # 3. Re-upgrade 006 -> 007 (idempotent re-add)
            command.upgrade(alembic_cfg, "007_patch_fix_plan_snapshot")
            inspector = inspect(engine)
            patch_cols_007 = {col["name"] for col in inspector.get_columns("patches")}
            assert "fix_plan_snapshot" in patch_cols_007

            # 4. Downgrade to 005_workflow_events_table
            command.downgrade(alembic_cfg, "005_workflow_events_table")
            inspector = inspect(engine)
            assert "deliveries" not in inspector.get_table_names()
            assert "workflow_events" in inspector.get_table_names()
            event_cols_005 = {col["name"] for col in inspector.get_columns("workflow_events")}
            assert "delivery_id" not in event_cols_005

            # 5. Downgrade to 004_patch_machine_verdict
            command.downgrade(alembic_cfg, "004_patch_machine_verdict")
            inspector = inspect(engine)
            assert "workflow_events" not in inspector.get_table_names()
            assert "patches" in inspector.get_table_names()
            patch_cols_004 = {col["name"] for col in inspector.get_columns("patches")}
            assert "machine_verdict" in patch_cols_004

            # 6. Downgrade to 003_phase36_durability_and_provenance
            command.downgrade(alembic_cfg, "003_phase36_durability_and_provenance")
            inspector = inspect(engine)
            patch_cols_003 = {col["name"] for col in inspector.get_columns("patches")}
            assert "machine_verdict" not in patch_cols_003
            assert "parent_patch_id" in patch_cols_003

            # 7. Downgrade to 002_patches_table
            command.downgrade(alembic_cfg, "002_patches_table")
            inspector = inspect(engine)
            patch_cols_002 = {col["name"] for col in inspector.get_columns("patches")}
            assert "parent_patch_id" not in patch_cols_002

            # 8. Downgrade to 001_initial_schema
            command.downgrade(alembic_cfg, "001_initial_schema")
            inspector = inspect(engine)
            assert "patches" not in inspector.get_table_names()
            assert "findings" in inspector.get_table_names()
            assert "scans" in inspector.get_table_names()

            # 9. Downgrade all the way to base
            command.downgrade(alembic_cfg, "base")
            inspector = inspect(engine)
            user_tables = [t for t in inspector.get_table_names() if t != "alembic_version"]
            assert len(user_tables) == 0, f"Expected zero user tables after downgrade to base, got {user_tables}"

            # 10. Re-upgrade all the way to head
            command.upgrade(alembic_cfg, "head")
            inspector = inspect(engine)
            assert {"scans", "findings", "evidences", "patches", "workflow_events", "deliveries"}.issubset(set(inspector.get_table_names()))
            patch_cols_final = {col["name"] for col in inspector.get_columns("patches")}
            assert "fix_plan_snapshot" in patch_cols_final
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


def test_alembic_007_fix_plan_snapshot_orm_read_write():
    """Verify that migration 007 fix_plan_snapshot column supports ORM JSON read/write correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_007.db")
        db_url = f"sqlite:///{db_path}"

        alembic_cfg = _get_alembic_config(db_url)
        command.upgrade(alembic_cfg, "head")

        engine = create_engine(db_url)
        try:
            SessionLocal = sessionmaker(bind=engine)
            db = SessionLocal()

            scan = ScanModel(
                id=str(uuid4()),
                repository_url="https://github.com/test-org/test-repo",
                status=ScanStatus.COMPLETED.value,
                commit_hash="aabbccdd" * 5,
            )
            db.add(scan)

            finding = FindingModel(
                id=str(uuid4()),
                scan_id=scan.id,
                title="Test finding for 007",
                description="Validates fix_plan_snapshot column",
                severity=Severity.MEDIUM.value,
                status=FindingStatus.OPEN.value,
                verification_verdict="CONFIRMED",
            )
            db.add(finding)

            plan_id = uuid4()
            fix_plan = FixPlan(
                id=plan_id,
                finding_id=UUID(finding.id),
                root_cause="Test root cause",
                objective="Test objective",
                files_expected_to_change=["app/main.py"],
                symbols_expected_to_change=[],
                ordered_changes=[
                    OrderedChangeStep(step_number=1, target_file="app/main.py", description="Fix", rationale="Reason")
                ],
                validation_plan=["Check fix"],
                estimated_scope=FixScope.FILE,
            )
            snapshot_data = fix_plan.model_dump(mode="json")

            # 1. Write patch WITH fix_plan_snapshot
            patch_with = PatchModel(
                id=str(uuid4()),
                finding_id=finding.id,
                plan_id=str(plan_id),
                fix_plan_snapshot=snapshot_data,
                scan_id=scan.id,
                thread_id=f"remediation-{uuid4()}",
                status=PatchStatus.VERIFIED.value,
                machine_verdict="PASSED",
                unified_diff="--- a/app/main.py\n+++ b/app/main.py\n",
                files_modified=["app/main.py"],
                explanation="Test patch",
                expected_behavior_change="Fixed",
            )
            db.add(patch_with)

            # 2. Write patch WITHOUT fix_plan_snapshot (nullable)
            patch_without = PatchModel(
                id=str(uuid4()),
                finding_id=finding.id,
                scan_id=scan.id,
                thread_id=f"remediation-{uuid4()}",
                status=PatchStatus.DRAFT.value,
                machine_verdict="NEEDS_REVIEW",
                unified_diff="--- a/app/main.py\n+++ b/app/main.py\n",
                files_modified=["app/main.py"],
                explanation="Draft patch",
                expected_behavior_change="None",
            )
            db.add(patch_without)
            db.commit()

            # 3. Read back and verify
            loaded_with = db.query(PatchModel).filter(PatchModel.id == patch_with.id).first()
            assert loaded_with is not None
            assert loaded_with.fix_plan_snapshot is not None
            round_trip = FixPlan.model_validate(loaded_with.fix_plan_snapshot)
            assert str(round_trip.id) == loaded_with.plan_id
            assert str(round_trip.finding_id) == loaded_with.finding_id
            assert round_trip.root_cause == "Test root cause"
            assert round_trip.files_expected_to_change == ["app/main.py"]
            assert loaded_with.plan_id == str(plan_id)

            loaded_without = db.query(PatchModel).filter(PatchModel.id == patch_without.id).first()
            assert loaded_without is not None
            assert loaded_without.fix_plan_snapshot is None
            assert loaded_without.plan_id is None

            db.close()
        finally:
            engine.dispose()
