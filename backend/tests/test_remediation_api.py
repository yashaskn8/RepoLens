from contextlib import asynccontextmanager
import os
import tempfile
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.patching.schemas import (
    PatchProposal,
    PatchVerificationResult,
    PatchWorkflowResult,
    VerificationStatus,
)
from app.planning.schemas import FixPlan, OrderedChangeStep
from app.research.schemas import ResearchEvidence, ResearchResult, SourceTier
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict


@asynccontextmanager
async def _mock_open_snapshot_ctx(scan_id, db=None):
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "app"), exist_ok=True)
        with open(os.path.join(tmpdir, "app", "db.py"), "w") as f:
            f.write("def query(): pass\n")
        with open(os.path.join(tmpdir, "app", "auth_cookie.py"), "w") as f:
            f.write("def cookie(): pass\n")
        yield tmpdir


def test_get_finding_by_id_and_not_found(client, db_session):
    """Verify GET /api/v1/findings/{finding_id} retrieves finding or returns 404."""
    # 1. Nonexistent finding returns 404
    non_existent = str(uuid4())
    res_404 = client.get(f"/api/v1/findings/{non_existent}")
    assert res_404.status_code == 404

    # 2. Existing finding returns finding details
    scan_id = str(uuid4())
    sm = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fastapi/fastapi",
        commit_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(sm)

    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Path Traversal In Static Files",
        description="Path traversal in file reader",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        rule_id="sec-path-01",
        category="security",
        verification_verdict=VerificationVerdict.POSSIBLE.value,
    )
    db_session.add(fm)
    db_session.commit()

    # POSSIBLE findings are still readable/inspectable via GET
    res = client.get(f"/api/v1/findings/{finding_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == finding_id
    assert data["title"] == "Path Traversal In Static Files"
    assert data["severity"] == "HIGH"
    assert data["verification_verdict"] == "POSSIBLE"


def test_request_finding_research_endpoint(client, db_session):
    """Verify POST /api/v1/findings/{finding_id}/research returns structured ResearchResult for CONFIRMED findings."""
    scan_id = str(uuid4())
    sm = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fastapi/fastapi",
        commit_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(sm)

    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Pydantic V1 Deprecation Warning",
        description="Deprecated .dict() method used",
        severity=Severity.MEDIUM.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
    )
    db_session.add(fm)
    db_session.commit()

    mock_research = ResearchResult(
        target_framework="pydantic",
        recommended_version="v2.x",
        migration_summary="Migrate .dict() to .model_dump()",
        repository_impact="Affects schema serialization in models/finding.py",
        evidences=[
            ResearchEvidence(
                source_url="https://docs.pydantic.dev/migration/",
                source_title="Pydantic V2 Migration Guide",
                source_tier=SourceTier.OFFICIAL_DOCS,
                supported_claim="Use model_dump instead of dict",
                confidence=1.0,
            )
        ],
    )

    with patch("app.ingestion.snapshot.RepositorySnapshotService.open_snapshot", side_effect=_mock_open_snapshot_ctx), \
         patch("app.research.service.ResearchService.research_finding", new_callable=AsyncMock) as mock_res_fn:
        mock_res_fn.return_value = mock_research

        res = client.post(f"/api/v1/findings/{finding_id}/research")
        assert res.status_code == 200
        data = res.json()
        assert data["target_framework"] == "pydantic"
        assert data["recommended_version"] == "v2.x"
        assert "model_dump" in data["migration_summary"]


def test_request_fix_plan_endpoint(client, db_session):
    """Verify POST /api/v1/findings/{finding_id}/plan returns validated FixPlan for CONFIRMED findings."""
    scan_id = str(uuid4())
    sm = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fastapi/fastapi",
        commit_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(sm)

    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Unsanitized SQL Query",
        description="String formatting in sql",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
    )
    db_session.add(fm)
    db_session.commit()

    mock_plan = FixPlan(
        finding_id=uuid4(),
        root_cause="Query string formatting",
        objective="Use parameterized query",
        files_expected_to_change=["app/db.py"],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/db.py",
                description="Use parameter placeholder",
                rationale="Prevents injection",
            )
        ],
        validation_plan=["pytest tests/test_db.py"],
    )

    with patch("app.ingestion.snapshot.RepositorySnapshotService.open_snapshot", side_effect=_mock_open_snapshot_ctx), \
         patch("app.planning.service.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_plan_fn:
        mock_plan_fn.return_value = mock_plan

        res = client.post(f"/api/v1/findings/{finding_id}/plan")
        assert res.status_code == 200
        data = res.json()
        assert data["objective"] == "Use parameterized query"
        assert "app/db.py" in data["files_expected_to_change"]


def test_request_patch_generation_endpoint(client, db_session):
    """Verify POST /api/v1/findings/{finding_id}/patch executes workflow and persists proposal for CONFIRMED findings."""
    scan_id = str(uuid4())
    sm = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fastapi/fastapi",
        commit_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(sm)

    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Insecure Cookie Header",
        description="Missing Secure and HttpOnly flags",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
    )
    db_session.add(fm)
    db_session.commit()

    mock_plan = FixPlan(
        finding_id=uuid4(),
        root_cause="Cookie flags missing",
        objective="Add Secure and HttpOnly flags",
        files_expected_to_change=["app/auth/cookie.py"],
        ordered_changes=[
            OrderedChangeStep(step_number=1, target_file="app/auth/cookie.py", description="Add flags", rationale="Security")
        ],
        validation_plan=["pytest"],
    )

    mock_proposal = PatchProposal(
        finding_id=uuid4(),
        plan_id=mock_plan.id,
        unified_diff="--- a/app/auth/cookie.py\n+++ b/app/auth/cookie.py\n@@ -1,1 +1,1 @@\n-s\n+s; Secure; HttpOnly\n",
        files_modified=["app/auth/cookie.py"],
        explanation="Add Secure and HttpOnly flags",
        expected_behavior_change="Cookies hardened",
    )

    mock_verif = PatchVerificationResult(
        patch_id=mock_proposal.id,
        finding_id=mock_proposal.finding_id,
        status=VerificationStatus.PASSED,
        syntax_valid=True,
        security_clean=True,
        contract_aligned=True,
        target_finding_resolved=True,
        explanation="All 12 sandbox verification checks passed cleanly",
    )

    mock_workflow_res = PatchWorkflowResult(
        finding_id=mock_proposal.finding_id,
        proposal=mock_proposal,
        verification_result=mock_verif,
        critic_escalated=False,
        revision_count=0,
        final_verdict="APPROVED",
    )

    with patch("app.ingestion.snapshot.RepositorySnapshotService.open_snapshot", side_effect=_mock_open_snapshot_ctx), \
         patch("app.planning.service.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_plan_fn, \
         patch("app.patching.workflow.PatchWorkflowCoordinator.execute_patch_workflow", new_callable=AsyncMock) as mock_wf_fn:
        
        mock_plan_fn.return_value = mock_plan
        mock_wf_fn.return_value = mock_workflow_res

        res = client.post(f"/api/v1/findings/{finding_id}/patch")
        assert res.status_code == 200
        data = res.json()
        assert data["final_verdict"] == "APPROVED"
        assert data["proposal"]["files_modified"] == ["app/auth/cookie.py"]
        assert data["verification_result"]["status"] == "PASSED"

        # Verify patch was persisted in DB
        persisted = db_session.query(PatchModel).filter(PatchModel.finding_id == finding_id).first()
        assert persisted is not None
        assert persisted.status == PatchStatus.VERIFIED.value


# =========================================================================
# Phase 3.5I: Strict Remediation Eligibility Tests
# =========================================================================

def test_remediation_eligibility_enforced_across_all_endpoints(client, db_session):
    """Verify strict eligibility:
    - CONFIRMED -> allowed (200)
    - POSSIBLE -> rejected (422)
    - REJECTED -> rejected (422)
    - missing verdict -> rejected (422)
    Tested across research, planning, and patch generation endpoints.
    """
    scan_id = str(uuid4())
    sm = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fastapi/fastapi",
        commit_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(sm)

    # 1. Create findings for each verdict state
    confirmed_id = str(uuid4())
    fm_confirmed = FindingModel(
        id=confirmed_id,
        scan_id=scan_id,
        title="Confirmed Vulnerability",
        description="Real confirmed issue",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
    )

    possible_id = str(uuid4())
    fm_possible = FindingModel(
        id=possible_id,
        scan_id=scan_id,
        title="Possible Flaw",
        description="Possible but unconfirmed issue",
        severity=Severity.MEDIUM.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.POSSIBLE.value,
    )

    rejected_id = str(uuid4())
    fm_rejected = FindingModel(
        id=rejected_id,
        scan_id=scan_id,
        title="False Positive",
        description="Rejected issue",
        severity=Severity.LOW.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.REJECTED.value,
    )

    missing_id = str(uuid4())
    fm_missing = FindingModel(
        id=missing_id,
        scan_id=scan_id,
        title="Unverified Issue",
        description="No verification verdict",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=None,
    )

    db_session.add_all([fm_confirmed, fm_possible, fm_rejected, fm_missing])
    db_session.commit()

    endpoints = ["research", "plan", "patch"]

    # 2. Test POSSIBLE -> rejected (422)
    for ep in endpoints:
        res = client.post(f"/api/v1/findings/{possible_id}/{ep}")
        assert res.status_code == 422, f"Endpoint {ep} should reject POSSIBLE finding with 422"
        assert "not eligible for remediation" in res.json()["detail"]
        assert "POSSIBLE" in res.json()["detail"]

    # 3. Test REJECTED -> rejected (422)
    for ep in endpoints:
        res = client.post(f"/api/v1/findings/{rejected_id}/{ep}")
        assert res.status_code == 422, f"Endpoint {ep} should reject REJECTED finding with 422"
        assert "not eligible for remediation" in res.json()["detail"]
        assert "REJECTED" in res.json()["detail"]

    # 4. Test missing verdict -> rejected (422)
    for ep in endpoints:
        res = client.post(f"/api/v1/findings/{missing_id}/{ep}")
        assert res.status_code == 422, f"Endpoint {ep} should reject missing verdict finding with 422"
        assert "not eligible for remediation" in res.json()["detail"]
        assert "NONE" in res.json()["detail"]

    # 5. Test CONFIRMED -> allowed (200) when dependencies succeed
    mock_plan = FixPlan(
        finding_id=uuid4(),
        root_cause="Confirmed issue root cause",
        objective="Fix confirmed issue",
        files_expected_to_change=["app/db.py"],
        ordered_changes=[
            OrderedChangeStep(step_number=1, target_file="app/db.py", description="Fix", rationale="Security")
        ],
        validation_plan=["pytest"],
    )
    mock_proposal = PatchProposal(
        finding_id=uuid4(),
        plan_id=mock_plan.id,
        unified_diff="--- a/app/db.py\n+++ b/app/db.py\n@@ -1 +1 @@\n-old\n+new\n",
        files_modified=["app/db.py"],
        explanation="Fix",
        expected_behavior_change="Fix",
    )
    mock_verif = PatchVerificationResult(
        patch_id=mock_proposal.id,
        finding_id=mock_proposal.finding_id,
        status=VerificationStatus.PASSED,
        syntax_valid=True,
        security_clean=True,
        contract_aligned=True,
        target_finding_resolved=True,
        explanation="Clean",
    )
    mock_workflow_res = PatchWorkflowResult(
        finding_id=mock_proposal.finding_id,
        proposal=mock_proposal,
        verification_result=mock_verif,
        critic_escalated=False,
        revision_count=0,
        final_verdict="APPROVED",
    )
    mock_research = ResearchResult(
        target_framework="FastAPI",
        recommended_version="0.110.0",
        migration_summary="Fix issue",
        repository_impact="Impact",
        evidences=[],
    )

    with patch("app.ingestion.snapshot.RepositorySnapshotService.open_snapshot", side_effect=_mock_open_snapshot_ctx), \
         patch("app.research.service.ResearchService.research_finding", new_callable=AsyncMock) as mock_res_fn, \
         patch("app.planning.service.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_plan_fn, \
         patch("app.patching.workflow.PatchWorkflowCoordinator.execute_patch_workflow", new_callable=AsyncMock) as mock_wf_fn:

        mock_res_fn.return_value = mock_research
        mock_plan_fn.return_value = mock_plan
        mock_wf_fn.return_value = mock_workflow_res

        # CONFIRMED -> allowed
        res_res = client.post(f"/api/v1/findings/{confirmed_id}/research")
        assert res_res.status_code == 200

        res_plan = client.post(f"/api/v1/findings/{confirmed_id}/plan")
        assert res_plan.status_code == 200

        res_patch = client.post(f"/api/v1/findings/{confirmed_id}/patch")
        assert res_patch.status_code == 200
