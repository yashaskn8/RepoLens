"""Unit tests for human revision request, lineage tracking, and verdict semantics."""

from datetime import datetime, timezone
import os
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.main import app
from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.patching.schemas import CriticVerdict, PatchCriticReport, PatchProposal, PatchVerificationResult, PatchWorkflowResult, VerificationStatus
from app.planning.schemas import FixPlan, OrderedChangeStep
from app.schemas.enums import FindingStatus, PatchStatus, Severity, VerificationVerdict





def _setup_scan_finding_patch(db_session, status=PatchStatus.VERIFIED.value, revision_number=0):
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/test-repo",
        commit_hash="abcdef1234567890abcdef1234567890abcdef12",
        status="COMPLETED",
    )
    db_session.add(scan)

    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title="SQL Injection Defect",
        description="Unsafe string formatting",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
        source_tool="semgrep",
        detector_id="python.sql.injection",
        detector_kind="static_scanner",
    )
    db_session.add(finding)

    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=finding.id,
        file_path="app/query.py",
        start_line=5,
        end_line=6,
        code_snippet="cursor.execute(f'SELECT...')",
    )
    db_session.add(evidence)

    patch = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan.id,
        thread_id=f"remediation-{uuid4()}",
        status=status,
        unified_diff="--- a/query.py\n+++ b/query.py\n@@ -5,1 +5,1 @@\n-cursor.execute(f'SELECT...')\n+cursor.execute('SELECT...', (id,))\n",
        files_modified=["app/query.py"],
        explanation="Parameterized query",
        expected_behavior_change="Safe query execution",
        verification_report={"status": "PASSED"},
        revision_number=revision_number,
    )
    db_session.add(patch)
    db_session.commit()
    return scan, finding, patch


def test_revise_rejected_on_approved_patch(client, db_session):
    """Verify that requesting revision on an APPROVED patch returns 400."""
    _, _, patch = _setup_scan_finding_patch(db_session, status=PatchStatus.APPROVED.value)

    resp = client.post(f"/api/v1/patches/{patch.id}/revise", json={"user_feedback": "Change parameter names"})
    assert resp.status_code == 400
    assert "already APPROVED" in resp.json()["detail"]


def test_revise_rejected_on_rejected_patch(client, db_session):
    """Verify that requesting revision on a REJECTED patch returns 400."""
    _, _, patch = _setup_scan_finding_patch(db_session, status=PatchStatus.REJECTED.value)

    resp = client.post(f"/api/v1/patches/{patch.id}/revise", json={"user_feedback": "Try again"})
    assert resp.status_code == 400
    assert "REJECTED" in resp.json()["detail"]


def test_revise_rejected_when_revision_number_ge_1(client, db_session):
    """Verify that a child revision (revision_number >= 1) cannot be revised again."""
    _, _, patch = _setup_scan_finding_patch(db_session, status=PatchStatus.VERIFIED.value, revision_number=1)

    resp = client.post(f"/api/v1/patches/{patch.id}/revise", json={"user_feedback": "Third revision"})
    assert resp.status_code == 400
    assert "Maximum of 1 human revision allowed" in resp.json()["detail"]


def test_revise_rejected_when_child_already_exists(client, db_session):
    """Verify concurrency safety: cannot create two child revisions from same parent patch."""
    scan, finding, parent_patch = _setup_scan_finding_patch(db_session, status=PatchStatus.VERIFIED.value, revision_number=0)

    # Add existing child
    child = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        scan_id=scan.id,
        parent_patch_id=parent_patch.id,
        revision_number=1,
        status=PatchStatus.VERIFIED.value,
        unified_diff="diff",
        files_modified=["app/query.py"],
        explanation="Child",
        expected_behavior_change="Child behavior",
    )
    db_session.add(child)
    db_session.commit()

    resp = client.post(f"/api/v1/patches/{parent_patch.id}/revise", json={"user_feedback": "Duplicate child request"})
    assert resp.status_code == 400
    assert "already been created" in resp.json()["detail"]


def test_revise_race_condition_returns_409(client, db_session):
    """Simulate a race condition where two concurrent revision requests both pass
    the pre-check. The losing request must get HTTP 409, not 500.

    Strategy: Insert a conflicting child directly into the DB, then mock the
    pre-check query (existing_child lookup) to return None — simulating the
    window where Request B's pre-check runs before Request A's commit.
    The actual db.commit() will then hit the UNIQUE constraint on parent_patch_id.
    """
    from contextlib import asynccontextmanager

    scan, finding, parent_patch = _setup_scan_finding_patch(db_session, status=PatchStatus.VERIFIED.value, revision_number=0)

    # Capture IDs as strings before any potential rollback invalidates ORM state
    parent_patch_id = parent_patch.id
    finding_id = finding.id
    scan_id = scan.id

    # Pre-insert a conflicting child (simulating Request A already committed)
    conflicting_child = PatchModel(
        id=str(uuid4()),
        finding_id=finding_id,
        scan_id=scan_id,
        parent_patch_id=parent_patch_id,
        revision_number=1,
        status=PatchStatus.VERIFIED.value,
        unified_diff="--- a/query.py\n+++ b/query.py\n@@ -5,1 +5,1 @@\n-old\n+fixed\n",
        files_modified=["app/query.py"],
        explanation="First child",
        expected_behavior_change="Fixed",
    )
    db_session.add(conflicting_child)
    db_session.commit()

    @asynccontextmanager
    async def _mock_open_snapshot(*args, **kwargs):
        with tempfile.TemporaryDirectory() as td:
            yield td

    mock_plan_id = uuid4()
    mock_revised_plan = FixPlan(
        id=mock_plan_id,
        finding_id=UUID(finding_id),
        root_cause="Race condition in query",
        objective="Fix race condition",
        files_expected_to_change=["app/query.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/query.py",
                description="Fix race",
                rationale="Thread safety",
            )
        ],
        validation_plan=["Check race"],
    )

    mock_wf_result = MagicMock()
    mock_wf_result.machine_verdict = "PASSED"
    mock_wf_result.proposal = PatchProposal(
        finding_id=UUID(finding_id),
        plan_id=mock_plan_id,
        unified_diff="--- a/query.py\n+++ b/query.py\n@@ -5,1 +5,1 @@\n-old\n+new\n",
        files_modified=["app/query.py"],
        explanation="Race fix",
        expected_behavior_change="Fixed",
    )
    mock_wf_result.verification_result = None
    mock_wf_result.critic_report = None

    # Store reference to real query method
    _real_query = db_session.query

    def _patched_query(model):
        """Return a query wrapper that makes the existing_child lookup return None,
        simulating the race window where Request B hasn't seen Request A's child yet."""
        real_q = _real_query(model)
        if model is PatchModel:
            class _RaceConditionPatchQuery(type(real_q)):
                def filter(self, *args):
                    filter_str = str(args[0]) if args else ""
                    if "parent_patch_id" in filter_str:
                        mock_result = MagicMock()
                        mock_result.first.return_value = None
                        return mock_result
                    return super().filter(*args)

            real_q.__class__ = _RaceConditionPatchQuery
        return real_q

    with patch("app.ingestion.snapshot.RepositorySnapshotService.open_snapshot", _mock_open_snapshot), \
         patch("app.analysis.service.RepositoryIntelligenceService.analyze_repository", AsyncMock()), \
         patch("app.context.runtime.ScanIntelligenceRuntime.build", AsyncMock()), \
         patch("app.planning.service.FixPlanningService.create_fix_plan", AsyncMock(return_value=mock_revised_plan)), \
         patch("app.patching.workflow.PatchWorkflowCoordinator.execute_patch_workflow", AsyncMock(return_value=mock_wf_result)):
        # Monkey-patch query on the session to bypass the pre-check
        original_query = db_session.query
        db_session.query = _patched_query
        try:
            resp = client.post(
                f"/api/v1/patches/{parent_patch_id}/revise",
                json={"user_feedback": "Please improve error handling"},
            )
        finally:
            db_session.query = original_query

    # The endpoint must return 409 Conflict, not 500
    assert resp.status_code == 409
    assert "already been created" in resp.json()["detail"]



