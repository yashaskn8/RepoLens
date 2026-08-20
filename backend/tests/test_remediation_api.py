"""Tests for Phase 3G: Remediation API contracts, research, fix plan, and patch workflow endpoints."""

from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.patching.schemas import (
    PatchProposal,
    PatchVerificationResult,
    PatchWorkflowResult,
    VerificationStatus,
)
from app.planning.schemas import FixPlan, OrderedChangeStep
from app.research.schemas import ResearchEvidence, ResearchResult
from app.schemas.enums import FindingStatus, PatchStatus, Severity


def test_get_finding_by_id_and_not_found(client, db_session):
    """Verify GET /api/v1/findings/{finding_id} retrieves finding or returns 404."""
    # 1. Nonexistent finding returns 404
    non_existent = str(uuid4())
    res_404 = client.get(f"/api/v1/findings/{non_existent}")
    assert res_404.status_code == 404

    # 2. Existing finding returns finding details
    scan_res = client.post("/api/v1/scans", json={"repository_url": "https://github.com/fastapi/fastapi"})
    assert scan_res.status_code == 202
    scan_id = scan_res.json()["id"]

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
    )
    db_session.add(fm)
    db_session.commit()

    res = client.get(f"/api/v1/findings/{finding_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == finding_id
    assert data["title"] == "Path Traversal In Static Files"
    assert data["severity"] == "HIGH"


def test_request_finding_research_endpoint(client, db_session):
    """Verify POST /api/v1/findings/{finding_id}/research returns structured ResearchResult."""
    scan_res = client.post("/api/v1/scans", json={"repository_url": "https://github.com/fastapi/fastapi"})
    scan_id = scan_res.json()["id"]

    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Pydantic V1 Deprecation Warning",
        description="Deprecated .dict() method used",
        severity=Severity.MEDIUM.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(fm)
    db_session.commit()

    from app.research.schemas import SourceTier
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

    with patch("app.research.service.ResearchService.research_finding", new_callable=AsyncMock) as mock_res_fn:
        mock_res_fn.return_value = mock_research

        res = client.post(f"/api/v1/findings/{finding_id}/research")
        assert res.status_code == 200
        data = res.json()
        assert data["target_framework"] == "pydantic"
        assert data["recommended_version"] == "v2.x"
        assert "model_dump" in data["migration_summary"]


def test_request_fix_plan_endpoint(client, db_session):
    """Verify POST /api/v1/findings/{finding_id}/plan returns validated FixPlan."""
    scan_res = client.post("/api/v1/scans", json={"repository_url": "https://github.com/fastapi/fastapi"})
    scan_id = scan_res.json()["id"]

    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Unsanitized SQL Query",
        description="String formatting in sql",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
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

    with patch("app.planning.service.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_plan_fn:
        mock_plan_fn.return_value = mock_plan

        res = client.post(f"/api/v1/findings/{finding_id}/plan")
        assert res.status_code == 200
        data = res.json()
        assert data["objective"] == "Use parameterized query"
        assert "app/db.py" in data["files_expected_to_change"]


def test_request_patch_generation_endpoint(client, db_session):
    """Verify POST /api/v1/findings/{finding_id}/patch executes workflow and persists proposal."""
    scan_res = client.post("/api/v1/scans", json={"repository_url": "https://github.com/fastapi/fastapi"})
    scan_id = scan_res.json()["id"]

    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Insecure Cookie Header",
        description="Missing Secure and HttpOnly flags",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
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

    with patch("app.planning.service.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_plan_fn, \
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
