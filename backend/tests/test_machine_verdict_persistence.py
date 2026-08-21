"""Tests for Fix 1: Machine verdict is durably persisted in PatchModel,
survives DB reload, and is independent of human PatchStatus transitions."""

from uuid import uuid4

import pytest

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity


def _setup_scan_and_finding(db_session):
    """Create minimal scan + finding for patch tests."""
    scan_id = str(uuid4())
    finding_id = str(uuid4())

    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/test/repo.git",
        status=ScanStatus.COMPLETED.value,
        commit_hash="a" * 40,
    )
    db_session.add(scan)

    from app.models.finding import EvidenceModel
    from app.schemas.enums import VerificationVerdict

    finding = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Insecure Cookie",
        description="Missing httponly flag",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
    )
    db_session.add(finding)

    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=finding_id,
        file_path="app/routes.py",
        start_line=10,
        end_line=10,
        code_snippet="set_cookie(key='sid', value=token)",
    )
    db_session.add(evidence)
    db_session.commit()
    return scan_id, finding_id


def test_machine_verdict_persisted_and_survives_reload(db_session):
    """Verify machine_verdict is durably stored and survives DB reload."""
    scan_id, finding_id = _setup_scan_and_finding(db_session)

    patch_id = str(uuid4())
    patch = PatchModel(
        id=patch_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.VERIFIED.value,
        machine_verdict="PASSED",
        unified_diff="--- a/app/routes.py\n+++ b/app/routes.py\n@@ -10,1 +10,1 @@\n-old\n+new\n",
        files_modified=["app/routes.py"],
        explanation="Hardened cookie",
        expected_behavior_change="Secure cookie",
        verification_report={"status": "PASSED"},
    )
    db_session.add(patch)
    db_session.commit()

    # 1. machine_verdict is PASSED
    assert patch.machine_verdict == "PASSED"
    # 2. status is VERIFIED (not APPROVED — machine cannot human-approve)
    assert patch.status == PatchStatus.VERIFIED.value
    assert patch.status != PatchStatus.APPROVED.value

    # 3. Reload from DB
    db_session.expire_all()
    reloaded = db_session.query(PatchModel).filter(PatchModel.id == patch_id).first()
    assert reloaded is not None
    assert reloaded.machine_verdict == "PASSED"
    assert reloaded.status == PatchStatus.VERIFIED.value


def test_machine_verdict_unchanged_after_human_approval(db_session):
    """Verify human approval sets status=APPROVED but machine_verdict remains PASSED."""
    scan_id, finding_id = _setup_scan_and_finding(db_session)

    patch_id = str(uuid4())
    patch = PatchModel(
        id=patch_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.VERIFIED.value,
        machine_verdict="PASSED",
        unified_diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
        files_modified=["x.py"],
        explanation="Fix",
        expected_behavior_change="Fixed",
    )
    db_session.add(patch)
    db_session.commit()

    # Simulate human approval via direct model update (same as approve endpoint)
    patch.status = PatchStatus.APPROVED.value
    patch.approved_by = "SecurityTeamLead"
    db_session.commit()

    # Reload and verify
    db_session.expire_all()
    reloaded = db_session.query(PatchModel).filter(PatchModel.id == patch_id).first()
    assert reloaded.status == PatchStatus.APPROVED.value
    assert reloaded.machine_verdict == "PASSED"  # machine_verdict unchanged


def test_machine_verdict_needs_review_persisted(db_session):
    """Verify NEEDS_REVIEW machine_verdict is persisted correctly."""
    scan_id, finding_id = _setup_scan_and_finding(db_session)

    patch_id = str(uuid4())
    patch = PatchModel(
        id=patch_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.NEEDS_REVIEW.value,
        machine_verdict="NEEDS_REVIEW",
        unified_diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
        files_modified=["x.py"],
        explanation="Fix",
        expected_behavior_change="Fixed",
    )
    db_session.add(patch)
    db_session.commit()

    db_session.expire_all()
    reloaded = db_session.query(PatchModel).filter(PatchModel.id == patch_id).first()
    assert reloaded.machine_verdict == "NEEDS_REVIEW"
    assert reloaded.status == PatchStatus.NEEDS_REVIEW.value


def test_child_revision_persists_machine_verdict(db_session):
    """Verify child revision patch also durably stores machine_verdict."""
    scan_id, finding_id = _setup_scan_and_finding(db_session)

    parent_id = str(uuid4())
    parent = PatchModel(
        id=parent_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.VERIFIED.value,
        machine_verdict="PASSED",
        unified_diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
        files_modified=["x.py"],
        explanation="Original fix",
        expected_behavior_change="Fixed",
        revision_number=0,
    )
    db_session.add(parent)
    db_session.commit()

    child_id = str(uuid4())
    child = PatchModel(
        id=child_id,
        finding_id=finding_id,
        scan_id=scan_id,
        parent_patch_id=parent_id,
        revision_number=1,
        status=PatchStatus.NEEDS_REVIEW.value,
        machine_verdict="NEEDS_REVIEW",
        unified_diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+c\n",
        files_modified=["x.py"],
        explanation="Revised fix",
        expected_behavior_change="Better fix",
    )
    db_session.add(child)
    db_session.commit()

    # Reload both
    db_session.expire_all()
    p = db_session.query(PatchModel).filter(PatchModel.id == parent_id).first()
    c = db_session.query(PatchModel).filter(PatchModel.id == child_id).first()

    assert p.machine_verdict == "PASSED"
    assert c.machine_verdict == "NEEDS_REVIEW"
    assert c.parent_patch_id == parent_id
    assert c.revision_number == 1


def test_api_exposes_machine_verdict(client, db_session):
    """Verify GET /api/v1/patches/{id} exposes persisted machine_verdict."""
    scan_id, finding_id = _setup_scan_and_finding(db_session)

    patch_id = str(uuid4())
    patch = PatchModel(
        id=patch_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.VERIFIED.value,
        machine_verdict="PASSED",
        unified_diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
        files_modified=["x.py"],
        explanation="Fix",
        expected_behavior_change="Fixed",
    )
    db_session.add(patch)
    db_session.commit()

    res = client.get(f"/api/v1/patches/{patch_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["machine_verdict"] == "PASSED"
    assert data["status"] == "VERIFIED"

    # Now approve via API
    approve_res = client.post(
        f"/api/v1/patches/{patch_id}/approve",
        json={"approved_by": "Reviewer", "notes": "LGTM"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "APPROVED"
    assert approve_res.json()["machine_verdict"] == "PASSED"  # unchanged
