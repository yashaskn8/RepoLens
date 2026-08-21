"""Unit tests for human revision request, lineage tracking, and verdict semantics."""

from datetime import datetime, timezone
import os
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.main import app
from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.patching.schemas import CriticVerdict, PatchCriticReport, PatchProposal, PatchVerificationResult, PatchWorkflowResult, VerificationStatus
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
