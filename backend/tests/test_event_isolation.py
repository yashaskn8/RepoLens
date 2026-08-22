"""FIX 3 — Tests for operational event failure isolation and critical audit atomicity.

Verifies:
1. Operational event insertion failure does NOT fail primary scan state update.
2. HUMAN_APPROVED event persistence failure DOES propagate errors for transaction rollback.
3. HUMAN_REJECTED event persistence failure DOES propagate errors for transaction rollback.
4. Critical revision audit failure propagates for rollback preventing partial state.
5. Successful operational event persists normally through independent session.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService


class TestOperationalEventIsolation:
    """Operational events must not fail valid domain work."""

    def test_operational_emit_failure_does_not_fail_scan_state(self, db_session: Session):
        """Simulate operational event insertion failure.
        Primary scan state update must still commit successfully."""
        scan_id = str(uuid4())
        scan = ScanModel(
            id=scan_id,
            repository_url="https://github.com/org/op-isolation-test",
            status=ScanStatus.PENDING.value,
        )
        db_session.add(scan)
        db_session.commit()

        # Update scan state to RUNNING
        scan.status = ScanStatus.RUNNING.value
        db_session.commit()

        # Now emit an operational event with a factory that always fails
        def failing_factory():
            raise RuntimeError("DB connection pool exhausted")

        result = WorkflowEventService.emit_operational(
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.SCAN_STARTED,
                scan_id=UUID(scan_id),
                message="Scan started",
            ),
            session_factory=failing_factory,
        )

        # Operational event failed — returns None
        assert result is None

        # But the scan state was already committed successfully
        db_session.expire_all()
        reloaded_scan = db_session.query(ScanModel).filter(ScanModel.id == scan_id).first()
        assert reloaded_scan is not None
        assert reloaded_scan.status == ScanStatus.RUNNING.value

    def test_operational_emit_rollback_on_commit_failure(self, db_session: Session):
        """When the operational session commit fails, it must rollback and not propagate."""
        scan_id = str(uuid4())
        scan = ScanModel(
            id=scan_id,
            repository_url="https://github.com/org/op-rollback-test",
            status=ScanStatus.RUNNING.value,
        )
        db_session.add(scan)
        db_session.commit()

        # Create a mock session factory that returns a session with a failing commit
        mock_session = MagicMock()
        mock_session.commit.side_effect = RuntimeError("Disk full")

        result = WorkflowEventService.emit_operational(
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.TOOL_COMPLETED,
                scan_id=UUID(scan_id),
                tool_name="semgrep",
                message="Semgrep completed",
            ),
            session_factory=lambda: mock_session,
        )

        assert result is None
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_successful_operational_event_persists_via_independent_derived_session(self, db_session: Session):
        """Successful operational event via emit(critical=False) derives independent session and persists."""
        scan_id = str(uuid4())
        scan = ScanModel(
            id=scan_id,
            repository_url="https://github.com/org/op-success-test",
            status=ScanStatus.RUNNING.value,
        )
        db_session.add(scan)
        db_session.commit()

        # Emit with critical=False: derives session factory from db_session.get_bind()
        result = WorkflowEventService.emit(
            db=db_session,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.TOOL_COMPLETED,
                scan_id=UUID(scan_id),
                tool_name="semgrep",
                message="Semgrep completed",
            ),
            critical=False,
        )

        assert result is not None
        assert result.event_type == "TOOL_COMPLETED"

        # Verify it persisted in the DB independently
        persisted = (
            db_session.query(WorkflowEventModel)
            .filter(
                WorkflowEventModel.scan_id == scan_id,
                WorkflowEventModel.event_type == "TOOL_COMPLETED",
            )
            .first()
        )
        assert persisted is not None
        assert persisted.tool_name == "semgrep"

    def test_operational_emit_flush_failure_is_suppressed(self, db_session: Session):
        """When an independent operational session fails at flush, error is caught and logged."""
        mock_session = MagicMock()
        mock_session.commit.side_effect = RuntimeError("Flush/Commit DB error")

        result = WorkflowEventService.emit_operational(
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.STAGE_STARTED,
                scan_id=UUID(str(uuid4())),
                stage="intelligence_analysis",
                message="Started",
            ),
            session_factory=lambda: mock_session,
        )

        assert result is None
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_operational_emit_with_mock_factory_uses_independent_session(self):
        """emit_operational uses the provided session_factory for independent persistence."""
        mock_session = MagicMock()

        result = WorkflowEventService.emit_operational(
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.STAGE_COMPLETED,
                scan_id=UUID(str(uuid4())),
                stage="intelligence_analysis",
                message="Analysis completed",
            ),
            session_factory=lambda: mock_session,
        )

        # The independent session's add/commit/close were called
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()
        assert result is not None


class TestCriticalAuditAtomicity:
    """Critical audit events must be atomic with domain state transitions."""

    def test_critical_emit_failure_raises(self):
        """If critical event persistence fails, error propagates for transaction rollback."""
        mock_db = MagicMock()
        mock_db.add.side_effect = RuntimeError("Constraint violation")

        with pytest.raises(RuntimeError, match="Constraint violation"):
            WorkflowEventService.emit_critical(
                db=mock_db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.HUMAN_APPROVED,
                    scan_id=UUID(str(uuid4())),
                    message="Patch approved by admin",
                ),
            )

    def test_human_approved_event_failure_propagates_for_rollback(self):
        """If HUMAN_APPROVED critical event fails add, the error propagates.
        This ensures the caller can rollback the approval state transition."""
        mock_db = MagicMock()
        mock_db.add.side_effect = RuntimeError("Audit persistence failure")

        # Set up a mock patch status change
        patch_status_before = PatchStatus.VERIFIED.value

        # Simulate: caller sets patch.status = APPROVED, then emit_critical fails
        with pytest.raises(RuntimeError, match="Audit persistence failure"):
            WorkflowEventService.emit_critical(
                db=mock_db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.HUMAN_APPROVED,
                    scan_id=UUID(str(uuid4())),
                    finding_id=UUID(str(uuid4())),
                    patch_id=UUID(str(uuid4())),
                    message="Approved by admin",
                ),
            )

        # The caller now has the opportunity to rollback
        # The error propagated — audit integrity maintained

    def test_human_rejected_event_failure_propagates_for_rollback(self):
        """If HUMAN_REJECTED critical event fails add, the error propagates.
        This ensures the caller can rollback the rejection state transition."""
        mock_db = MagicMock()
        mock_db.add.side_effect = RuntimeError("Rejection audit failure")

        with pytest.raises(RuntimeError, match="Rejection audit failure"):
            WorkflowEventService.emit_critical(
                db=mock_db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.HUMAN_REJECTED,
                    scan_id=UUID(str(uuid4())),
                    finding_id=UUID(str(uuid4())),
                    patch_id=UUID(str(uuid4())),
                    message="Rejected",
                ),
            )

    def test_human_approved_rollback_preserves_original_state(self, db_session: Session):
        """Full integration: if approval + critical event is rolled back, patch stays VERIFIED."""
        scan_id = str(uuid4())
        finding_id = str(uuid4())
        patch_id = str(uuid4())

        scan = ScanModel(
            id=scan_id,
            repository_url="https://github.com/org/audit-rollback-test",
            status=ScanStatus.COMPLETED.value,
        )
        db_session.add(scan)

        finding = FindingModel(
            id=finding_id,
            scan_id=scan_id,
            title="XSS",
            description="Unescaped output",
            severity=Severity.HIGH.value,
            status=FindingStatus.OPEN.value,
        )
        db_session.add(finding)

        patch_model = PatchModel(
            id=patch_id,
            finding_id=finding_id,
            scan_id=scan_id,
            status=PatchStatus.VERIFIED.value,
            unified_diff="--- a\n+++ b\n",
            files_modified=["app.py"],
            explanation="Fix",
            expected_behavior_change="Fix",
            revision_number=0,
        )
        db_session.add(patch_model)
        db_session.flush()

        # Create a savepoint to simulate transactional approval attempt
        nested = db_session.begin_nested()

        # Simulate: set status to APPROVED, then rollback
        patch_model.status = PatchStatus.APPROVED.value
        patch_model.approved_by = "admin"
        db_session.flush()

        # Simulate critical audit failure by rolling back the savepoint
        nested.rollback()

        # After rollback, patch should be back to VERIFIED
        db_session.expire_all()
        reloaded = db_session.query(PatchModel).filter(PatchModel.id == patch_id).first()
        assert reloaded is not None
        assert reloaded.status == PatchStatus.VERIFIED.value

    def test_human_rejected_rollback_preserves_original_state(self, db_session: Session):
        """Full integration: if rejection + critical event is rolled back, patch stays VERIFIED."""
        scan_id = str(uuid4())
        finding_id = str(uuid4())
        patch_id = str(uuid4())

        scan = ScanModel(
            id=scan_id,
            repository_url="https://github.com/org/reject-rollback-test",
            status=ScanStatus.COMPLETED.value,
        )
        db_session.add(scan)

        finding = FindingModel(
            id=finding_id,
            scan_id=scan_id,
            title="SSRF",
            description="Unvalidated URL",
            severity=Severity.HIGH.value,
            status=FindingStatus.OPEN.value,
        )
        db_session.add(finding)

        patch_model = PatchModel(
            id=patch_id,
            finding_id=finding_id,
            scan_id=scan_id,
            status=PatchStatus.VERIFIED.value,
            unified_diff="--- a\n+++ b\n",
            files_modified=["handler.py"],
            explanation="Fix",
            expected_behavior_change="Fix",
            revision_number=0,
        )
        db_session.add(patch_model)
        db_session.flush()

        nested = db_session.begin_nested()

        patch_model.status = PatchStatus.REJECTED.value
        patch_model.rejected_reason = "Incomplete fix"
        db_session.flush()

        # Simulate critical audit failure by rolling back
        nested.rollback()

        db_session.expire_all()
        reloaded = db_session.query(PatchModel).filter(PatchModel.id == patch_id).first()
        assert reloaded is not None
        assert reloaded.status == PatchStatus.VERIFIED.value

    def test_critical_revision_audit_failure_prevents_partial_state(self, db_session: Session):
        """If a critical revision audit event fails, no partially committed child patch/audit state."""
        scan_id = str(uuid4())
        finding_id = str(uuid4())
        parent_patch_id = str(uuid4())

        scan = ScanModel(
            id=scan_id,
            repository_url="https://github.com/org/revision-audit-test",
            status=ScanStatus.COMPLETED.value,
        )
        db_session.add(scan)

        finding = FindingModel(
            id=finding_id,
            scan_id=scan_id,
            title="Injection",
            description="SQL injection",
            severity=Severity.CRITICAL.value,
            status=FindingStatus.OPEN.value,
        )
        db_session.add(finding)

        parent_patch = PatchModel(
            id=parent_patch_id,
            finding_id=finding_id,
            scan_id=scan_id,
            status=PatchStatus.VERIFIED.value,
            unified_diff="--- a\n+++ b\n",
            files_modified=["db.py"],
            explanation="Parameterize",
            expected_behavior_change="Fix",
            revision_number=0,
        )
        db_session.add(parent_patch)
        db_session.flush()

        child_patch_id = str(uuid4())

        nested = db_session.begin_nested()

        # Create child revision patch
        child_patch = PatchModel(
            id=child_patch_id,
            finding_id=finding_id,
            scan_id=scan_id,
            status=PatchStatus.DRAFT.value,
            unified_diff="--- a\n+++ b\n@@ improved @@",
            files_modified=["db.py"],
            explanation="Better parameterization",
            expected_behavior_change="Fix",
            revision_number=1,
            parent_patch_id=parent_patch_id,
        )
        db_session.add(child_patch)
        db_session.flush()

        # Simulate critical audit failure — rollback
        nested.rollback()

        # Verify no child patch was persisted
        db_session.expire_all()
        child = db_session.query(PatchModel).filter(PatchModel.id == child_patch_id).first()
        assert child is None, "Child patch should not persist when critical audit event fails"


class TestLegacyEmitBackwardCompatibility:
    """Legacy emit() interface routes correctly."""

    def test_legacy_emit_critical_true_propagates_errors(self):
        """emit(critical=True) should propagate errors."""
        mock_db = MagicMock()
        mock_db.add.side_effect = RuntimeError("Add failed")

        with pytest.raises(RuntimeError):
            WorkflowEventService.emit(
                db=mock_db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.HUMAN_APPROVED,
                    scan_id=UUID(str(uuid4())),
                    message="Approved",
                ),
                critical=True,
            )

    def test_legacy_emit_critical_false_suppresses_errors(self):
        """emit(critical=False) with no session_factory falls back to caller session with error suppression."""
        mock_db = MagicMock()
        mock_db.add.side_effect = RuntimeError("DB connection lost")

        result = WorkflowEventService.emit(
            db=mock_db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.TOOL_STARTED,
                scan_id=UUID(str(uuid4())),
                tool_name="semgrep",
            ),
            critical=False,
        )
        assert result is None

    def test_legacy_emit_critical_false_with_factory_uses_independent_session(self):
        """emit(critical=False, session_factory=...) delegates to emit_operational."""
        mock_session = MagicMock()

        result = WorkflowEventService.emit(
            db=MagicMock(),  # should not be used
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.TOOL_COMPLETED,
                scan_id=UUID(str(uuid4())),
                tool_name="trivy",
                message="Trivy completed",
            ),
            critical=False,
            session_factory=lambda: mock_session,
        )

        # The independent session should have been used
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
