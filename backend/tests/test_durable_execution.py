"""Tests for Phase 2E: durable LangGraph execution, SQLite checkpointing, and interruption/resume behavior."""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
import aiosqlite
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph

from app.agents.checkpointer import get_sqlite_checkpointer
from app.agents.graph import (
    _checkpoint_requires_investigator,
    build_analysis_graph,
    run_analysis_workflow,
)
from app.agents.state import AnalysisState
from app.analysis.store import EvidenceStore
from app.context.runtime import AnalysisRuntimeContext
from app.core.config import get_settings
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


@pytest.mark.asyncio
async def test_resume_rejects_different_commit_without_persistent_index(sample_evidence_store):
    """A scan-local checkpoint cannot be replayed against a different repository generation."""

    with tempfile.TemporaryDirectory() as tmpdir:
        app_dir = os.path.join(tmpdir, "app")
        os.makedirs(app_dir, exist_ok=True)
        with open(os.path.join(app_dir, "main.py"), "w", encoding="utf-8") as source:
            source.write("def root():\n    return 1\n")
        checkpoint_state = {
            "scan_id": "scan-drift",
            "commit_hash": "b" * 40,
            "status": "RUNNING",
            "manifest_summary": {"index_authority": None},
            "verified_findings": [{"id": "stale"}],
        }
        app = MagicMock()
        app.aget_state = AsyncMock(return_value=MagicMock(values=checkpoint_state, next=("verifier",)))
        app.ainvoke = AsyncMock(return_value=checkpoint_state)
        with patch("app.agents.graph.build_analysis_graph", return_value=app):
            result = await run_analysis_workflow(
                evidence_store=sample_evidence_store,
                scan_id="scan-drift",
                repo_dir=tmpdir,
                checkpointer=object(),
            )
        assert result["status"] == "FAILED"
        assert "generation is incompatible" in result["errors"][0]
        assert not result.get("verified_findings")
        app.ainvoke.assert_not_awaited()


def _checkpointed_resume_app(checkpointer, next_node, seen_runtime):
    """Build a real checkpointer-backed app paused immediately before next_node."""

    async def seed(state):
        return {"completed_nodes": ["seed"]}

    async def resume_node(state, runtime):
        seen_runtime.append(runtime.context.agent_tools)
        return {"status": "COMPLETED", "completed_nodes": [next_node]}

    builder = StateGraph(AnalysisState, context_schema=AnalysisRuntimeContext)
    builder.add_node("seed", seed)
    builder.add_node(next_node, resume_node)
    builder.add_edge(START, "seed")
    builder.add_edge("seed", next_node)
    builder.add_edge(next_node, END)
    return builder.compile(checkpointer=checkpointer, interrupt_after=["seed"])


def _checkpoint_values(sample_evidence_store, *, investigator_enabled):
    return {
        "scan_id": "resume-mode-test",
        "commit_hash": sample_evidence_store.manifest.commit_hash,
        "manifest_summary": {"index_authority": None},
        "agent_investigator_enabled": investigator_enabled,
        "investigator": {"active": {"budget": {"tool_calls": 1}}}
        if investigator_enabled else {},
        "status": "RUNNING",
        "ai_cloud_budget": {},
        "completed_nodes": ["seed"],
        "errors": [],
    }


@pytest.mark.asyncio
async def test_true_to_false_resume_reconstructs_investigator_runtime(sample_evidence_store):
    """A checkpointed investigator workflow survives a later flag disablement."""

    checkpointer = InMemorySaver()
    seen_runtime = []
    app = _checkpointed_resume_app(checkpointer, "investigator_decide", seen_runtime)
    config = {"configurable": {"thread_id": "resume-mode-test"}}
    await app.ainvoke(
        _checkpoint_values(sample_evidence_store, investigator_enabled=True),
        config=config,
        context=AnalysisRuntimeContext(scan_runtime=object()),
    )
    saved = await app.aget_state(config)
    assert saved.next == ("investigator_decide",)

    settings_false = get_settings().model_copy(
        update={"AGENT_INVESTIGATOR_ENABLED": False}
    )
    registry = object()
    with (
        patch("app.agents.graph.build_analysis_graph", return_value=app),
        patch("app.agents.graph.RepositorySnapshot.create", return_value=object()),
        patch("app.agents.graph.AgentToolContext.from_snapshot", return_value=object()),
        patch("app.agents.graph.create_agent_tool_registry", return_value=registry) as create_registry,
        patch("app.agents.graph.get_settings", return_value=settings_false),
    ):
        resumed = await run_analysis_workflow(
            evidence_store=sample_evidence_store,
            scan_id="resume-mode-test",
            repo_dir=".",
            checkpointer=checkpointer,
            context_engine=MagicMock(),
            repository_graph=MagicMock(),
        )

    assert resumed["status"] == "COMPLETED"
    assert seen_runtime == [registry]
    create_registry.assert_called_once()


@pytest.mark.asyncio
async def test_false_to_true_resume_keeps_legacy_checkpoint_path(sample_evidence_store):
    """Enabling the flag later cannot migrate a legacy checkpoint."""

    checkpointer = InMemorySaver()
    seen_runtime = []
    app = _checkpointed_resume_app(checkpointer, "revise", seen_runtime)
    config = {"configurable": {"thread_id": "legacy-resume-mode-test"}}
    values = _checkpoint_values(sample_evidence_store, investigator_enabled=False)
    values["scan_id"] = "legacy-resume-mode-test"
    await app.ainvoke(values, config=config, context=AnalysisRuntimeContext(scan_runtime=object()))
    saved = await app.aget_state(config)
    assert saved.next == ("revise",)

    settings_true = get_settings().model_copy(
        update={"AGENT_INVESTIGATOR_ENABLED": True}
    )
    with (
        patch("app.agents.graph.build_analysis_graph", return_value=app),
        patch("app.agents.graph.create_agent_tool_registry") as create_registry,
        patch("app.agents.graph.get_settings", return_value=settings_true),
    ):
        resumed = await run_analysis_workflow(
            evidence_store=sample_evidence_store,
            scan_id="legacy-resume-mode-test",
            repo_dir=".",
            checkpointer=checkpointer,
            context_engine=MagicMock(),
            repository_graph=MagicMock(),
        )

    assert resumed["status"] == "COMPLETED"
    assert seen_runtime == [None]
    create_registry.assert_not_called()


def test_checkpoint_mode_detection_is_strict_and_node_aware():
    assert _checkpoint_requires_investigator(
        MagicMock(values={"agent_investigator_enabled": True}, next=("revise",))
    )
    assert not _checkpoint_requires_investigator(
        MagicMock(values={"agent_investigator_enabled": False}, next=("revise",))
    )
    assert _checkpoint_requires_investigator(
        MagicMock(values={"agent_investigator_enabled": False}, next=("investigator_decide",))
    )


@pytest.mark.asyncio
async def test_completed_checkpoint_does_not_rebuild_investigator_runtime(sample_evidence_store):
    """A completed workflow is returned directly even if the current flag is enabled."""

    checkpointer = InMemorySaver()
    config = {"configurable": {"thread_id": "completed-mode-test"}}
    completed = _checkpoint_values(sample_evidence_store, investigator_enabled=True)
    completed["scan_id"] = "completed-mode-test"
    completed["status"] = "COMPLETED"
    builder = StateGraph(AnalysisState, context_schema=AnalysisRuntimeContext)
    builder.add_node("done", lambda state: {"status": "COMPLETED"})
    builder.add_edge(START, "done")
    builder.add_edge("done", END)
    app = builder.compile(checkpointer=checkpointer)
    await app.ainvoke(completed, config=config, context=AnalysisRuntimeContext(scan_runtime=object()))

    settings_true = get_settings().model_copy(
        update={"AGENT_INVESTIGATOR_ENABLED": True}
    )
    with (
        patch("app.agents.graph.build_analysis_graph", return_value=app),
        patch("app.agents.graph.create_agent_tool_registry") as create_registry,
        patch("app.agents.graph.get_settings", return_value=settings_true),
    ):
        resumed = await run_analysis_workflow(
            evidence_store=sample_evidence_store,
            scan_id="completed-mode-test",
            repo_dir=".",
            checkpointer=checkpointer,
            context_engine=MagicMock(),
            repository_graph=MagicMock(),
        )

    assert resumed["status"] == "COMPLETED"
    create_registry.assert_not_called()
