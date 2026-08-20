"""Tests for Phase 2E: durable LangGraph execution, SQLite checkpointing, and interruption/resume behavior."""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
import aiosqlite
import pytest
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from app.agents.checkpointer import get_sqlite_checkpointer
from app.agents.graph import build_analysis_graph, run_analysis_workflow
from app.analysis.store import EvidenceStore
from app.ingestion.schemas import (
    FileEntry,
    FrameworkDetected,
    ParsedSymbol,
    RepositoryManifest,
    SymbolKind,
)
from app.llm.types import LLMProvider, LLMResponse
from app.schemas.enums import Severity
from app.schemas.finding import Evidence, Finding
from app.schemas.metadata import ModelExecutionMetadata


@pytest.fixture
def sample_evidence_store():
    """Setup a sample EvidenceStore for workflow testing."""
    manifest = RepositoryManifest(
        repository_url="https://github.com/org/repo.git",
        commit_hash="1234567890abcdef1234567890abcdef12345678",
        total_files=1,
        total_size_bytes=100,
        languages={"python": 1},
        frameworks=[FrameworkDetected(name="FastAPI", version="0.115.0", evidence="import fastapi")],
        files=[
            FileEntry(
                path="app/main.py",
                language="python",
                size_bytes=100,
                lines_count=10,
                symbols=[
                    ParsedSymbol(
                        name="root",
                        kind=SymbolKind.FASTAPI_ROUTE,
                        start_line=1,
                        end_line=5,
                        details={"http_method": "GET", "path": "/"},
                    ),
                ],
            ),
        ],
    )
    return EvidenceStore(manifest=manifest)


@pytest.mark.asyncio
async def test_sqlite_checkpointer_initialization():
    """Verify get_sqlite_checkpointer initializes tables cleanly in :memory:."""
    async with get_sqlite_checkpointer(":memory:") as checkpointer:
        assert isinstance(checkpointer, AsyncSqliteSaver)


@pytest.mark.asyncio
async def test_durable_workflow_full_execution(sample_evidence_store):
    """Verify full workflow execution with SQLite checkpointer persisting thread state."""
    scan_id = "scan-durable-001"

    dummy_metadata = ModelExecutionMetadata(
        model_name="mock-model",
        provider="mock",
        execution_time_ms=10.0,
    )
    mock_resp = LLMResponse(
        content='{"findings": []}',
        model="mock-model",
        provider=LLMProvider.GEMINI,
        metadata=dummy_metadata,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a real file so verifier doesn't reject
        app_dir = os.path.join(tmpdir, "app")
        os.makedirs(app_dir, exist_ok=True)
        with open(os.path.join(app_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("@app.get('/')\ndef root(): return {'status': 'ok'}\n")

        with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = mock_resp

            async with get_sqlite_checkpointer(":memory:") as checkpointer:
                final_state = await run_analysis_workflow(
                    evidence_store=sample_evidence_store,
                    scan_id=scan_id,
                    repo_dir=tmpdir,
                    checkpointer=checkpointer,
                )

                assert final_state["scan_id"] == scan_id
                assert final_state["status"] == "COMPLETED"
                assert "mapper" in final_state["completed_nodes"]
                assert "verifier" in final_state["completed_nodes"]

                # Verify thread state is saved in checkpointer
                app = build_analysis_graph(checkpointer=checkpointer)
                saved_state = await app.aget_state({"configurable": {"thread_id": scan_id}})
                assert saved_state is not None
                assert saved_state.values["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_durable_workflow_interruption_and_resumption(sample_evidence_store):
    """Verify workflow resumes from checkpoint after a failure without rerunning completed nodes."""
    scan_id = "scan-interrupted-002"

    dummy_metadata = ModelExecutionMetadata(
        model_name="mock-model",
        provider="mock",
        execution_time_ms=10.0,
    )
    mock_resp = LLMResponse(
        content='{"findings": []}',
        model="mock-model",
        provider=LLMProvider.GEMINI,
        metadata=dummy_metadata,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a real file
        app_dir = os.path.join(tmpdir, "app")
        os.makedirs(app_dir, exist_ok=True)
        with open(os.path.join(app_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("@app.get('/')\ndef root(): return {'status': 'ok'}\n")

        async with get_sqlite_checkpointer(":memory:") as checkpointer:
            # Phase 1: Simulate failure in verifier node
            with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
                mock_gen.return_value = mock_resp

                # Mock verifier to fail on first attempt
                with patch("app.agents.graph.run_verifier_agent", side_effect=RuntimeError("Simulated provider outage")):
                    try:
                        await run_analysis_workflow(
                            evidence_store=sample_evidence_store,
                            scan_id=scan_id,
                            repo_dir=tmpdir,
                            checkpointer=checkpointer,
                        )
                    except RuntimeError:
                        pass

            # Inspect checkpointer state: mapper and parallel specialists finished before verifier failed
            app = build_analysis_graph(checkpointer=checkpointer)
            config = {"configurable": {"thread_id": scan_id}}
            checkpoint_state = await app.aget_state(config)

            assert checkpoint_state is not None
            assert checkpoint_state.values is not None
            completed = checkpoint_state.values.get("completed_nodes", [])
            assert "mapper" in completed

            # Phase 2: Resume execution with healthy verifier
            with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
                mock_gen.return_value = mock_resp

                resumed_state = await run_analysis_workflow(
                    evidence_store=sample_evidence_store,
                    scan_id=scan_id,
                    repo_dir=tmpdir,
                    checkpointer=checkpointer,
                    resume_if_exists=True,
                )

                assert resumed_state["scan_id"] == scan_id
                assert resumed_state["status"] == "COMPLETED"
                assert "verifier" in resumed_state["completed_nodes"]


@pytest.mark.asyncio
async def test_already_completed_scan_returns_immediately(sample_evidence_store):
    """Verify that calling run_analysis_workflow on an already-completed thread returns without rerunning."""
    scan_id = "scan-cached-003"
    dummy_metadata = ModelExecutionMetadata(
        model_name="mock-model",
        provider="mock",
        execution_time_ms=10.0,
    )
    mock_resp = LLMResponse(
        content='{"findings": []}',
        model="mock-model",
        provider=LLMProvider.GEMINI,
        metadata=dummy_metadata,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = os.path.join(tmpdir, "app")
        os.makedirs(app_dir, exist_ok=True)
        with open(os.path.join(app_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("@app.get('/')\ndef root(): return 1\n")

        with patch("app.llm.router.LLMRouter.generate", new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = mock_resp

            async with get_sqlite_checkpointer(":memory:") as checkpointer:
                # 1. First run completes
                first_state = await run_analysis_workflow(
                    evidence_store=sample_evidence_store,
                    scan_id=scan_id,
                    repo_dir=tmpdir,
                    checkpointer=checkpointer,
                )
                assert first_state["status"] == "COMPLETED"
                initial_call_count = mock_gen.call_count

                # 2. Second run returns cached state without invoking LLM again
                second_state = await run_analysis_workflow(
                    evidence_store=sample_evidence_store,
                    scan_id=scan_id,
                    repo_dir=tmpdir,
                    checkpointer=checkpointer,
                    resume_if_exists=True,
                )
                assert second_state["status"] == "COMPLETED"
                assert mock_gen.call_count == initial_call_count
