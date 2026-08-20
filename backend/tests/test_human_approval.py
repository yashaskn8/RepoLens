"""Tests for Phase 3F: Human-in-the-Loop Approval Checkpoints and Durable API Operations."""

import os
import tempfile
from uuid import uuid4
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

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

    # Insert a mock patch proposal in DB
    finding_id = str(uuid4())
    finding_model = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="SQL Injection Defect",
        description="Formatted query string",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(finding_model)

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
    assert approve_res.json()["approved_by"] == "security-lead@company.com"
    assert approve_res.json()["approved_at"] is not None

    # 6. Reject Patch via POST /api/v1/patches/{patch_id}/reject
    reject_res = client.post(
        f"/api/v1/patches/{patch_id}/reject",
        json={"reason": "Breaks backward compatibility with legacy clients."},
    )
    assert reject_res.status_code == 200
    assert reject_res.json()["status"] == "REJECTED"
    assert reject_res.json()["rejected_reason"] == "Breaks backward compatibility with legacy clients."

    # 7. Cannot approve a REJECTED patch
    reapprove_res = client.post(
        f"/api/v1/patches/{patch_id}/approve",
        json={"approved_by": "user"},
    )
    assert reapprove_res.status_code == 400
    assert "REJECTED" in reapprove_res.json()["detail"]


# =========================================================================
# 2. Durable LangGraph Human Approval Interrupt / Resume Tests
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
