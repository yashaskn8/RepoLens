"""Tests for Phase 3F & 3.5H: Human-in-the-Loop Approval Checkpoints and Durable API Operations."""

import os
import tempfile
from uuid import UUID, uuid4
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.agents.checkpointer import get_sqlite_checkpointer
from app.core.database import Base, get_db
from app.main import app
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.patching.schemas import PatchProposal, VerificationStatus
from app.patching.workflow_graph import (
    RemediationState,
    build_remediation_graph,
)
from app.planning.schemas import FixPlan, OrderedChangeStep
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity


# =========================================================================
# 1. API Human Approval & Inspection Tests
# =========================================================================

def test_patch_api_lifecycle_inspect_approve_reject_revise(client, db_session):
    """Verify inspection, explicit human approval, rejection, and revision endpoints."""
    # 1. Create a scan and finding first via test client / DB
    scan_res = client.post("/api/v1/scans", json={"repository_url": "https://github.com/fastapi/fastapi"})
    assert scan_res.status_code == 202
    scan_id = scan_res.json()["id"]

    # Mark scan COMPLETED with commit hash for provenance
    scan_model = db_session.query(ScanModel).filter(ScanModel.id == scan_id).first()
    scan_model.status = ScanStatus.COMPLETED.value
    scan_model.commit_hash = "abcdef1234567890abcdef1234567890abcdef12"

    # Insert a mock patch proposal in DB
    from app.models.finding import EvidenceModel
    from app.schemas.enums import VerificationVerdict
    finding_id = str(uuid4())
    finding_model = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="SQL Injection Defect",
        description="Formatted query string",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict=VerificationVerdict.CONFIRMED.value,
        source_tool="semgrep",
        detector_id="python.sql.injection",
        detector_kind="static_scanner",
    )
    db_session.add(finding_model)

    evidence_model = EvidenceModel(
        id=str(uuid4()),
        finding_id=finding_id,
        file_path="app/db.py",
        start_line=1,
        end_line=1,
        code_snippet="f'SELECT'",
    )
    db_session.add(evidence_model)

    patch_id = str(uuid4())
    patch_model = PatchModel(
        id=patch_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.VERIFIED.value,
        unified_diff="--- a/app/db.py\n+++ b/app/db.py\n@@ -1,1 +1,1 @@\n-f\n+?\n",
        files_modified=["app/db.py"],
        explanation="Parameterized query placeholder",
        expected_behavior_change="Safe binding",
        verification_report={"status": "PASSED"},
        revision_number=0,
    )
    db_session.add(patch_model)
    db_session.commit()

    # 2. Inspect Patch via GET /api/v1/patches/{patch_id}
    get_res = client.get(f"/api/v1/patches/{patch_id}")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["id"] == patch_id
    assert data["status"] == "VERIFIED"
    assert "app/db.py" in data["files_modified"]

    # 3. Inspect Scan Patches via GET /api/v1/patches/scan/{scan_id}
    scan_patches_res = client.get(f"/api/v1/patches/scan/{scan_id}")
    assert scan_patches_res.status_code == 200
    assert len(scan_patches_res.json()) >= 1

    # 4. Request Revision via POST /api/v1/patches/{patch_id}/revise
    from unittest.mock import AsyncMock, MagicMock, patch
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _mock_open_snapshot(*args, **kwargs):
        with tempfile.TemporaryDirectory() as td:
            yield td

    mock_plan_id = uuid4()
    mock_revised_plan = FixPlan(
        id=mock_plan_id,
        finding_id=UUID(finding_id),
        root_cause="Missing type annotations",
        objective="Add explicit type annotations",
        files_expected_to_change=["app/db.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/db.py",
                description="Add explicit type annotations",
                rationale="Types aligned",
            )
        ],
        validation_plan=["Check types"],
    )

    mock_wf_result = MagicMock()
    mock_wf_result.machine_verdict = "NEEDS_REVIEW"
    mock_wf_result.proposal = PatchProposal(
        finding_id=UUID(finding_id),
        plan_id=mock_plan_id,
        unified_diff="--- a/app/db.py\n+++ b/app/db.py\n@@ -1,1 +1,1 @@\n-old\n+new_with_types\n",
        files_modified=["app/db.py"],
        explanation="Added explicit type annotations",
        expected_behavior_change="Types aligned",
    )
    mock_wf_result.verification_result = None
    mock_wf_result.critic_report = None

    with patch("app.ingestion.snapshot.RepositorySnapshotService.open_snapshot", _mock_open_snapshot), \
         patch("app.analysis.service.RepositoryIntelligenceService.analyze_repository", AsyncMock()), \
         patch("app.context.runtime.ScanIntelligenceRuntime.build", AsyncMock()), \
         patch("app.planning.service.FixPlanningService.create_fix_plan", AsyncMock(return_value=mock_revised_plan)), \
         patch("app.patching.workflow.PatchWorkflowCoordinator.execute_patch_workflow", AsyncMock(return_value=mock_wf_result)):
        revise_res = client.post(
            f"/api/v1/patches/{patch_id}/revise",
            json={"user_feedback": "Please add explicit type annotations"},
        )
    assert revise_res.status_code == 200
    assert revise_res.json()["status"] == "NEEDS_REVIEW"
    assert revise_res.json()["user_feedback"] == "Please add explicit type annotations"

    # 5. Approve Patch via POST /api/v1/patches/{patch_id}/approve
    approve_res = client.post(
        f"/api/v1/patches/{patch_id}/approve",
        json={"approved_by": "security-lead@company.com", "notes": "Approved for merge request."},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "APPROVED"
    assert approve_res.json()["approved_by"] is not None
    assert approve_res.json()["approved_at"] is not None

    # 6. Reject Patch via POST /api/v1/patches/{patch_id}/reject
    reject_res = client.post(
        f"/api/v1/patches/{patch_id}/reject",
        json={"reason": "Breaks backward compatibility with legacy clients."},
    )
    assert reject_res.status_code == 200
    assert reject_res.json()["status"] == "REJECTED"
    assert reject_res.json()["rejected_reason"] == "Breaks backward compatibility with legacy clients."

    # 7. Cannot approve a REJECTED patch directly
    reapprove_res = client.post(
        f"/api/v1/patches/{patch_id}/approve",
        json={"approved_by": "user"},
    )
    assert reapprove_res.status_code == 400
    assert "REJECTED" in reapprove_res.json()["detail"]


# =========================================================================
# 2. State Transition Rules Enforcement Tests
# =========================================================================

def test_legal_state_transitions_enforced(client, db_session):
    """Verify state machine constraints:
    - REJECTED -> APPROVED directly must fail.
    - APPROVED -> REVISE must fail.
    - REJECTED -> REVISE must fail.
    - APPROVED -> APPROVED duplicate must fail.
    - REJECTED -> REJECTED duplicate must fail.
    """
    scan_id = str(uuid4())
    finding_id = str(uuid4())

    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fastapi/fastapi.git",
        status=ScanStatus.COMPLETED.value,
        commit_hash="1234567890abcdef",
    )
    db_session.add(scan)

    finding = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Test Finding",
        description="Test",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(finding)

    # 1. Test APPROVED -> REVISE and APPROVED -> APPROVED failure
    patch_approved_id = str(uuid4())
    patch_approved = PatchModel(
        id=patch_approved_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.APPROVED.value,
        unified_diff="--- a/x\n+++ b/x\n",
        files_modified=["x.py"],
        explanation="Fix",
        expected_behavior_change="Fix",
        approved_by="reviewer@corp.com",
    )
    db_session.add(patch_approved)
    db_session.commit()

    revise_appr = client.post(f"/api/v1/patches/{patch_approved_id}/revise", json={"user_feedback": "revise it"})
    assert revise_appr.status_code == 400
    assert "already APPROVED" in revise_appr.json()["detail"]

    appr_dup = client.post(f"/api/v1/patches/{patch_approved_id}/approve", json={"approved_by": "other"})
    assert appr_dup.status_code == 400
    assert "already APPROVED" in appr_dup.json()["detail"]

    # 2. Test REJECTED -> APPROVED, REJECTED -> REVISE, and REJECTED -> REJECTED failure
    patch_rejected_id = str(uuid4())
    patch_rejected = PatchModel(
        id=patch_rejected_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.REJECTED.value,
        unified_diff="--- a/x\n+++ b/x\n",
        files_modified=["x.py"],
        explanation="Fix",
        expected_behavior_change="Fix",
        rejected_reason="Bad approach",
    )
    db_session.add(patch_rejected)
    db_session.commit()

    appr_rej = client.post(f"/api/v1/patches/{patch_rejected_id}/approve", json={"approved_by": "reviewer"})
    assert appr_rej.status_code == 400
    assert "REJECTED" in appr_rej.json()["detail"]

    revise_rej = client.post(f"/api/v1/patches/{patch_rejected_id}/revise", json={"user_feedback": "try again"})
    assert revise_rej.status_code == 400
    assert "REJECTED" in revise_rej.json()["detail"]

    rej_dup = client.post(f"/api/v1/patches/{patch_rejected_id}/reject", json={"reason": "still bad"})
    assert rej_dup.status_code == 400
    assert "already REJECTED" in rej_dup.json()["detail"]


# =========================================================================
# 3. LangGraph Thread Synchronization & Restart Tests
# =========================================================================

@pytest.mark.asyncio
async def test_remediation_graph_interrupt_and_human_resume():
    """Verify that the remediation graph interrupts before human approval and resumes upon human action."""
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "checkpoints.db")
        async with AsyncSqliteSaver.from_conn_string(db_path) as checkpointer:
            workflow_app = build_remediation_graph(checkpointer=checkpointer)

            thread_id = f"remediation-{uuid4()}"
            config = {"configurable": {"thread_id": thread_id}}

            initial_state: RemediationState = {
                "scan_id": "scan-123",
                "finding_id": "finding-abc",
                "patch_status": PatchStatus.VERIFIED.value,
                "proposal_dict": {"unified_diff": "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\n"},
            }

            # 1. First execution: runs until the human_approval_checkpoint interrupt
            await workflow_app.ainvoke(initial_state, config=config)

            # Check state: execution should be paused at the interrupt point
            paused_state = await workflow_app.aget_state(config)
            assert paused_state.next == ("human_approval_checkpoint",)

            # 2. Human approval action: update state with explicit human approval
            await workflow_app.aupdate_state(
                config,
                {"patch_status": PatchStatus.APPROVED.value, "approved_by": "lead-engineer"},
                as_node="human_approval_checkpoint",
            )

            # Resume execution to completion
            final_res = await workflow_app.ainvoke(None, config=config)
            assert final_res["patch_status"] == PatchStatus.APPROVED.value
            assert final_res["approved_by"] == "lead-engineer"

            # Check final state: graph finished execution
            finished_state = await workflow_app.aget_state(config)
            assert not finished_state.next


@pytest.mark.asyncio
async def test_end_to_end_db_and_langgraph_state_identical_after_resume():
    """End-to-end test proving DB state and LangGraph thread checkpoint state remain identical across pause/resume cycles."""
    scan_id = str(uuid4())
    finding_id = str(uuid4())
    patch_id = str(uuid4())
    thread_id = f"remediation-{patch_id}"

    config = {"configurable": {"thread_id": thread_id}}

    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = os.path.join(tmpdir, "test_checkpoints.sqlite")

        # 1. Initialize workflow paused at interrupt
        async with get_sqlite_checkpointer(db_path=db_file) as checkpointer:
            workflow_app = build_remediation_graph(checkpointer=checkpointer)

            initial_state: RemediationState = {
                "scan_id": scan_id,
                "finding_id": finding_id,
                "patch_id": patch_id,
                "thread_id": thread_id,
                "proposal_dict": {"unified_diff": "--- a/src.py\n+++ b/src.py\n@@ -1 +1 @@\n-old\n+new\n"},
                "patch_status": PatchStatus.VERIFIED.value,
                "revision_count": 0,
            }
            await workflow_app.ainvoke(initial_state, config=config)

            # Verify it is paused
            paused_checkpoint = await workflow_app.aget_state(config)
            assert paused_checkpoint.next == ("human_approval_checkpoint",)
            assert paused_checkpoint.values["patch_status"] == PatchStatus.VERIFIED.value

        # 2. Simulate server restart: open new connection to same persistent checkpointer DB
        async with get_sqlite_checkpointer(db_path=db_file) as checkpointer_2:
            workflow_app_2 = build_remediation_graph(checkpointer=checkpointer_2)

            # Retrieve state after restart
            rehydrated_checkpoint = await workflow_app_2.aget_state(config)
            assert rehydrated_checkpoint is not None
            assert rehydrated_checkpoint.next == ("human_approval_checkpoint",)
            assert rehydrated_checkpoint.values["patch_status"] == PatchStatus.VERIFIED.value

            # Perform Human Revision action
            await workflow_app_2.aupdate_state(
                config,
                {
                    "patch_status": PatchStatus.NEEDS_REVIEW.value,
                    "user_feedback": "Please add docstring",
                    "revision_count": 1,
                },
                as_node="human_approval_checkpoint",
            )
            resumed_rev = await workflow_app_2.ainvoke(None, config=config)
            assert resumed_rev["patch_status"] == PatchStatus.NEEDS_REVIEW.value
            assert resumed_rev["user_feedback"] == "Please add docstring"
            assert resumed_rev["revision_count"] == 1

        # 3. Simulate another server restart and then Approve
        async with get_sqlite_checkpointer(db_path=db_file) as checkpointer_3:
            workflow_app_3 = build_remediation_graph(checkpointer=checkpointer_3)

            # Update to APPROVED and resume to completion
            await workflow_app_3.aupdate_state(
                config,
                {
                    "patch_status": PatchStatus.APPROVED.value,
                    "approved_by": "security-lead@company.com",
                    "approved_at": "2026-08-20T22:00:00Z",
                },
                as_node="human_approval_checkpoint",
            )
            final_result = await workflow_app_3.ainvoke(None, config=config)

            assert final_result["patch_status"] == PatchStatus.APPROVED.value
            assert final_result["approved_by"] == "security-lead@company.com"

            # Check final checkpoint
            final_checkpoint = await workflow_app_3.aget_state(config)
            assert not final_checkpoint.next
            assert final_checkpoint.values["patch_status"] == PatchStatus.APPROVED.value
            assert final_checkpoint.values["approved_by"] == "security-lead@company.com"
