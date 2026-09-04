"""Integration tests for Phase 3.5G: Durable LangGraph execution connected to production scans."""

import asyncio
import json
import os
import tempfile
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from app.api.routes.scans import execute_background_scan
from app.llm.types import LLMProvider, LLMResponse, ModelCapability
from app.models.finding import FindingModel
from app.models.scan import ScanModel
from app.schemas.enums import ScanStatus, Severity
from app.schemas.metadata import ModelExecutionMetadata
from tests.conftest import TestingSessionLocal


@pytest.mark.asyncio
async def test_production_scan_interruption_resume_and_deduplication():
    """Verify that execute_background_scan:
    1. Runs with durable SQLite checkpointer;
    2. Survives an interruption after initial nodes (mapper & specialists);
    3. Resumes in a simulated new runtime without duplicating previously completed node work;
    4. Rehydrates exact repository snapshot on resume;
    5. Persists verified findings into DB exactly once without duplicates;
    6. Marks scan COMPLETED upon successful finish.
    """
    scan_id = str(uuid4())
    repo_url = "https://github.com/org/durable-test-repo.git"
    commit_sha = "e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"
    branch = "main"

    dummy_metadata = ModelExecutionMetadata(
        model_name="mock-model",
        provider="mock",
        execution_time_ms=10.0,
    )
    mock_llm_resp = LLMResponse(
        content='''{
            "confidence": 0.95,
            "findings": [
                {
                    "title": "SQL Injection in User Query",
                    "description": "Unsanitized user input formatted directly into SQL query.",
                    "severity": "HIGH",
                    "category": "security",
                    "rule_id": "semgrep.py-sql",
                    "evidence_refs": ["chunk:e1a2b3c4d5e6:app/main.py:get_user:1"],
                    "source_behavior": "The query is constructed with an f-string.",
                    "trigger_condition": "get_user receives a user identifier.",
                    "failure_mechanism": "The identifier is interpolated into SQL text.",
                    "impact_claim": "The query structure may be altered by input.",
                    "counter_evidence_considered": [],
                    "mitigation_guidance": "Use parameterized queries."
                }
            ]
        }''',
        model="mock-model",
        provider=LLMProvider.GEMINI,
        metadata=dummy_metadata,
    )
    verifier_response = LLMResponse(
        content='''{
            "confidence": 0.95,
            "evaluations": [{
                "index": 0,
                "verdict": "CONFIRMED",
                "justified_severity": "HIGH",
                "reason": "The attested source constructs a SQL query from user input."
                ,"claims": [
                    {"claim_type": "SOURCE_BEHAVIOR", "state": "SUPPORTED"},
                    {"claim_type": "TRIGGER", "state": "SUPPORTED"},
                    {"claim_type": "MECHANISM", "state": "SUPPORTED"},
                    {"claim_type": "IMPACT", "state": "SUPPORTED"},
                    {"claim_type": "SEVERITY", "state": "SUPPORTED"}
                ]
            }]
        }''',
        model="mock-verifier",
        provider=LLMProvider.NVIDIA,
        metadata=dummy_metadata,
    )

    async def mock_llm_generate(request):
        if request.capability == ModelCapability.VERIFICATION:
            return verifier_response
        content = request.messages[1].content
        if "<UNTRUSTED_REPOSITORY_DATA>" not in content:
            return mock_llm_resp
        payload = content.split("<UNTRUSTED_REPOSITORY_DATA>", 1)[1].split(
            "</UNTRUSTED_REPOSITORY_DATA>", 1
        )[0]
        candidate_id = json.loads(payload)["hypotheses"][0]["candidate_id"]
        response_payload = json.loads(mock_llm_resp.content)
        response_payload["findings"][0]["candidate_id"] = candidate_id
        return mock_llm_resp.model_copy(update={"content": json.dumps(response_payload)})

    with tempfile.TemporaryDirectory(prefix="durable_scan_integration_") as shared_dir:
        # Create a persistent SQLite checkpoint DB file for cross-process simulation
        checkpoint_db_file = os.path.join(shared_dir, "checkpoints.sqlite")

        # Create a mock repo directory that clone/snapshot can point to
        repo_workspace = os.path.join(shared_dir, "repo")
        os.makedirs(os.path.join(repo_workspace, "app"), exist_ok=True)
        with open(os.path.join(repo_workspace, "app", "main.py"), "w", encoding="utf-8") as f:
            f.write("def get_user(user_id):\n    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n")

        # 1. Create DB record in PENDING status
        db = TestingSessionLocal()
        try:
            scan_record = ScanModel(
                id=scan_id,
                repository_url=repo_url,
                branch=branch,
                status=ScanStatus.PENDING.value,
            )
            db.add(scan_record)
            db.commit()
        finally:
            db.close()

        # Phase 1: Simulate initial scan execution with interruption at verifier
        with patch("app.api.routes.scans.SessionLocal", side_effect=TestingSessionLocal), \
             patch("app.api.routes.scans.clone_repository", return_value=(repo_workspace, commit_sha)), \
             patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
            mock_gen.side_effect = mock_llm_generate

            # Inject failure into verifier to interrupt workflow after specialists
            with patch("app.agents.graph.run_verifier_agent", side_effect=RuntimeError("Simulated interruption during verifier")):
                await execute_background_scan(
                    scan_id=scan_id,
                    repo_url=repo_url,
                    branch=branch,
                    checkpoint_db_path=checkpoint_db_file,
                )

        # Inspect DB after interruption: scan was marked FAILED because of the terminal node error
        db = TestingSessionLocal()
        try:
            scan_after_p1 = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            assert scan_after_p1 is not None
            assert scan_after_p1.commit_hash == commit_sha
            assert scan_after_p1.status == ScanStatus.FAILED.value
            # No findings persisted yet because workflow was interrupted before completion
            findings_p1 = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
            assert len(findings_p1) == 0
        finally:
            db.close()

        # Phase 2: Simulate new process/runtime resuming the same scan_id
        # Reset scan status to RUNNING to simulate restart
        db = TestingSessionLocal()
        try:
            scan_record = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            scan_record.status = ScanStatus.RUNNING.value
            db.commit()
        finally:
            db.close()

        # Rehydration should materialize exact snapshot using commit_sha
        snapshot_materialize_called = False

        def mock_materialize(repository_url, commit_hash, branch=None):
            nonlocal snapshot_materialize_called
            snapshot_materialize_called = True
            assert commit_hash == commit_sha
            rehydrated_dir = tempfile.mkdtemp(prefix="rehydrated_repo_")
            os.makedirs(os.path.join(rehydrated_dir, "app"), exist_ok=True)
            with open(os.path.join(rehydrated_dir, "app", "main.py"), "w", encoding="utf-8") as f:
                f.write("def get_user(user_id):\n    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n")
            return rehydrated_dir

        # Track mapper calls during resume to prove already-completed nodes are NOT rerun
        mapper_call_count = 0

        async def tracking_mapper(state):
            nonlocal mapper_call_count
            mapper_call_count += 1
            from app.agents.mapper import run_repository_mapper
            return await run_repository_mapper(state)

        with patch("app.api.routes.scans.SessionLocal", side_effect=TestingSessionLocal), \
             patch("app.ingestion.snapshot.RepositorySnapshotService.materialize_snapshot_from_metadata", side_effect=mock_materialize), \
             patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen, \
             patch("app.agents.graph.run_repository_mapper", side_effect=tracking_mapper):
            mock_gen.side_effect = mock_llm_generate

            # Run resumed scan with healthy verifier
            await execute_background_scan(
                scan_id=scan_id,
                repo_url=repo_url,
                branch=branch,
                checkpoint_db_path=checkpoint_db_file,
            )

        # 4. Verify snapshot rehydration was invoked
        assert snapshot_materialize_called is True

        # 5. Verify mapper was NOT rerun because it completed in Phase 1
        assert mapper_call_count == 0

        # 6. Verify scan is now COMPLETED and findings persisted
        db = TestingSessionLocal()
        try:
            scan_final = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            assert scan_final is not None
            assert scan_final.status == ScanStatus.COMPLETED.value
            assert scan_final.completed_at is not None

            findings_final = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
            assert len(findings_final) >= 1
            initial_count = len(findings_final)

            # Phase 3: Verify idempotency / deduplication on repeated resume
            # Re-running execute_background_scan should not create duplicate findings
            with patch("app.api.routes.scans.SessionLocal", side_effect=TestingSessionLocal), \
                 patch("app.ingestion.snapshot.RepositorySnapshotService.materialize_snapshot_from_metadata", side_effect=mock_materialize), \
                 patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
                mock_gen.side_effect = mock_llm_generate

                await execute_background_scan(
                    scan_id=scan_id,
                    repo_url=repo_url,
                    branch=branch,
                    checkpoint_db_path=checkpoint_db_file,
                )

            findings_after_repeat = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
            assert len(findings_after_repeat) == initial_count, "Findings must not be duplicated on repeat execution"
        finally:
            db.close()


@pytest.mark.asyncio
async def test_production_scan_terminal_workflow_failure_marks_scan_failed():
    """Verify that when a workflow fails terminally without recovery, the DB scan is marked FAILED."""
    scan_id = str(uuid4())
    repo_url = "https://github.com/org/failed-scan-repo.git"
    commit_sha = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"

    with tempfile.TemporaryDirectory(prefix="failed_scan_test_") as shared_dir:
        checkpoint_db_file = os.path.join(shared_dir, "checkpoints.sqlite")
        repo_workspace = os.path.join(shared_dir, "repo")
        os.makedirs(os.path.join(repo_workspace, "src"), exist_ok=True)
        with open(os.path.join(repo_workspace, "src", "index.py"), "w", encoding="utf-8") as f:
            f.write("x = 1\n")

        db = TestingSessionLocal()
        try:
            scan_record = ScanModel(
                id=scan_id,
                repository_url=repo_url,
                branch="main",
                status=ScanStatus.PENDING.value,
            )
            db.add(scan_record)
            db.commit()
        finally:
            db.close()

        with patch("app.api.routes.scans.SessionLocal", side_effect=TestingSessionLocal), \
             patch("app.api.routes.scans.clone_repository", return_value=(repo_workspace, commit_sha)), \
             patch("app.agents.graph.run_repository_mapper", side_effect=RuntimeError("Fatal repository mapping crash")):
            await execute_background_scan(
                scan_id=scan_id,
                repo_url=repo_url,
                branch="main",
                checkpoint_db_path=checkpoint_db_file,
            )

        db = TestingSessionLocal()
        try:
            scan_record = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            assert scan_record is not None
            assert scan_record.status == ScanStatus.FAILED.value
            assert scan_record.completed_at is not None
            assert "error" in scan_record.model_metadata
        finally:
            db.close()
