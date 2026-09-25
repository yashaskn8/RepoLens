"""Durable graph checkpoint backend, serialization, and process-reopen tests."""

import asyncio
import operator
import os
import sys
import tempfile
import types
from typing import Annotated, TypedDict
from unittest.mock import patch

import pytest
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel

from app.agents.checkpointer import (
    CheckpointBackend,
    CheckpointerConfigurationError,
    _strict_serializer,
    get_analysis_checkpointer,
    get_sqlite_checkpointer,
    normalize_postgres_checkpoint_url,
    resolve_checkpoint_backend,
    setup_analysis_checkpointer,
)
from app.core.config import Settings
from app.schemas.metadata import ModelExecutionMetadata


class _PlainState(TypedDict):
    events: Annotated[list[str], operator.add]


class _UnapprovedModel(BaseModel):
    value: str


def _settings(**updates) -> Settings:
    return Settings(_env_file=None, **updates)


def test_checkpoint_backend_selection_fails_closed_in_production():
    local = _settings(CHECKPOINT_BACKEND="AUTO", DATABASE_URL="sqlite:///local.db")
    assert resolve_checkpoint_backend(local) == CheckpointBackend.SQLITE

    auto_postgres = _settings(
        CHECKPOINT_BACKEND="AUTO",
        DATABASE_URL="sqlite:///local.db",
        CHECKPOINT_DATABASE_URL="postgresql+psycopg://user:pass@db/repolens",
    )
    assert resolve_checkpoint_backend(auto_postgres) == CheckpointBackend.POSTGRES

    production_sqlite = local.model_copy(update={"ENVIRONMENT": "production"})
    with pytest.raises(CheckpointerConfigurationError, match="requires the PostgreSQL"):
        resolve_checkpoint_backend(production_sqlite)

    production_memory = local.model_copy(
        update={
            "ENVIRONMENT": "production",
            "CHECKPOINT_BACKEND": "MEMORY_TEST_ONLY",
            "DATABASE_URL": "postgresql://user:pass@db/repolens",
        }
    )
    with pytest.raises(CheckpointerConfigurationError, match="requires the PostgreSQL"):
        resolve_checkpoint_backend(production_memory)


def test_postgres_url_normalization_preserves_components_without_logging():
    source = "postgresql+psycopg://agent:p%40ss@[2001:db8::1]:5433/repolens?sslmode=require&application_name=checkpoint"
    normalized = normalize_postgres_checkpoint_url(source)
    assert normalized.startswith("postgresql://agent:p%40ss@[2001:db8::1]:5433/repolens?")
    assert "sslmode=require" in normalized
    assert "application_name=checkpoint" in normalized
    with pytest.raises(CheckpointerConfigurationError, match="must use PostgreSQL"):
        normalize_postgres_checkpoint_url("sqlite:///not-postgres.db")


def test_checkpoint_serializer_round_trips_only_allowlisted_model_types():
    serializer = _strict_serializer("analysis")
    metadata = ModelExecutionMetadata(
        model_name="fixture-model",
        provider="fixture",
        execution_time_ms=1.0,
    )
    encoded = serializer.dumps_typed(metadata)
    restored = serializer.loads_typed(encoded)
    assert isinstance(restored, ModelExecutionMetadata)
    assert restored.model_name == "fixture-model"

    unapproved = serializer.dumps_typed(_UnapprovedModel(value="must-not-load"))
    rejected = serializer.loads_typed(unapproved)
    assert not isinstance(rejected, _UnapprovedModel)


@pytest.mark.asyncio
async def test_sqlite_saver_is_official_and_initializes_local_schema():
    async with get_analysis_checkpointer(db_path=":memory:", state_profile="plain") as saver:
        assert isinstance(saver, AsyncSqliteSaver)


@pytest.mark.asyncio
async def test_sqlite_pending_parallel_write_survives_saver_reopen():
    """A completed sibling in a failed superstep is not rerun after process-style reopen."""
    with tempfile.TemporaryDirectory(prefix="checkpoint_reopen_") as directory:
        database = os.path.join(directory, "graph.sqlite")
        left_runs = 0
        right_runs = 0
        left_finished = asyncio.Event()

        async def left(_state):
            nonlocal left_runs
            left_runs += 1
            left_finished.set()
            return {"events": ["left"]}

        async def right(_state):
            nonlocal right_runs
            right_runs += 1
            await left_finished.wait()
            if right_runs == 1:
                raise RuntimeError("intentional one-time interruption")
            return {"events": ["right"]}

        def build(saver):
            builder = StateGraph(_PlainState)
            builder.add_node("left", left)
            builder.add_node("right", right)
            builder.add_edge(START, "left")
            builder.add_edge(START, "right")
            builder.add_edge("left", END)
            builder.add_edge("right", END)
            return builder.compile(checkpointer=saver)

        config = {"configurable": {"thread_id": "pending-write-reopen"}}
        with patch("app.agents.checkpointer.get_settings", return_value=_settings()):
            async with get_analysis_checkpointer(
                db_path=database,
                state_profile="plain",
            ) as saver:
                graph = build(saver)
                with pytest.raises(RuntimeError, match="intentional one-time interruption"):
                    await graph.ainvoke({"events": []}, config=config, durability="sync")

            async with get_analysis_checkpointer(
                db_path=database,
                state_profile="plain",
            ) as saver:
                resumed = await build(saver).ainvoke(None, config=config, durability="sync")
                saved = await build(saver).aget_state(config)

        assert left_runs == 1
        assert right_runs == 2
        assert sorted(resumed["events"]) == ["left", "right"]
        assert sorted(saved.values["events"]) == ["left", "right"]


@pytest.mark.asyncio
async def test_change_analysis_workspace_binding_is_invocation_local():
    from app.analysis.workflow_graph import (
        _workspace_for,
        bind_change_workspaces,
        reset_change_workspaces,
        run_acquire_node,
    )

    state = {
        "base_workspace": "stale-base-path",
        "head_workspace": "stale-head-path",
        "completed_nodes": [],
    }
    token = bind_change_workspaces("fresh-base-path", "fresh-head-path")
    try:
        assert _workspace_for(state, "base_workspace") == "fresh-base-path"
        assert _workspace_for(state, "head_workspace") == "fresh-head-path"
        acquired = await run_acquire_node(state)
        assert acquired["completed_nodes"] == ["acquire"]
        assert "base_workspace" not in acquired
        assert "head_workspace" not in acquired
        raise RuntimeError("exercise context cleanup")
    except RuntimeError as exc:
        assert str(exc) == "exercise context cleanup"
    finally:
        reset_change_workspaces(token)

    assert _workspace_for(state, "base_workspace") == "stale-base-path"


@pytest.mark.asyncio
async def test_postgres_open_does_not_run_schema_setup(monkeypatch):
    """Per-scan Postgres opening uses the official saver without implicit setup()."""
    connection_state = {"closed": False, "kwargs": None, "dsn": None}

    class FakeConnection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            connection_state["closed"] = True

    class FakeAsyncConnection:
        @staticmethod
        async def connect(dsn, **kwargs):
            connection_state["dsn"] = dsn
            connection_state["kwargs"] = kwargs
            return FakeConnection()

    class FakeSaver:
        def __init__(self, connection, *, serde):
            self.connection = connection
            self.serde = serde
            self.setup_calls = 0

        async def setup(self):
            self.setup_calls += 1

    psycopg = types.ModuleType("psycopg")
    psycopg.__path__ = []
    psycopg.AsyncConnection = FakeAsyncConnection
    rows = types.ModuleType("psycopg.rows")
    rows.dict_row = object()
    postgres_package = types.ModuleType("langgraph.checkpoint.postgres")
    postgres_package.__path__ = []
    postgres_aio = types.ModuleType("langgraph.checkpoint.postgres.aio")
    postgres_aio.AsyncPostgresSaver = FakeSaver
    monkeypatch.setitem(sys.modules, "psycopg", psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.rows", rows)
    monkeypatch.setitem(sys.modules, "langgraph.checkpoint.postgres", postgres_package)
    monkeypatch.setitem(sys.modules, "langgraph.checkpoint.postgres.aio", postgres_aio)
    settings = _settings(
        CHECKPOINT_BACKEND="POSTGRES",
        CHECKPOINT_DATABASE_URL="postgresql+psycopg://worker:s%40cret@db.invalid/repolens?sslmode=require",
    )
    monkeypatch.setattr("app.agents.checkpointer.get_settings", lambda: settings)

    async with get_analysis_checkpointer(state_profile="plain") as saver:
        assert isinstance(saver, FakeSaver)
        assert saver.setup_calls == 0

    assert connection_state["closed"]
    assert connection_state["kwargs"]["autocommit"] is True
    assert connection_state["kwargs"]["prepare_threshold"] == 0
    assert "sslmode=require" in connection_state["dsn"]


@pytest.mark.asyncio
async def test_postgres_schema_setup_is_explicit(monkeypatch):
    class FakeSaver:
        def __init__(self):
            self.setup_calls = 0

        async def setup(self):
            self.setup_calls += 1

    saver = FakeSaver()
    settings = _settings(
        CHECKPOINT_BACKEND="POSTGRES",
        CHECKPOINT_DATABASE_URL="postgresql://worker:secret@db.invalid/repolens",
    )
    monkeypatch.setattr("app.agents.checkpointer.get_settings", lambda: settings)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_open(**_kwargs):
        yield saver

    monkeypatch.setattr("app.agents.checkpointer.get_analysis_checkpointer", fake_open)
    assert await setup_analysis_checkpointer() == CheckpointBackend.POSTGRES
    assert saver.setup_calls == 1


@pytest.mark.asyncio
async def test_legacy_sqlite_helper_fails_closed_in_production(monkeypatch):
    settings = _settings(
        CHECKPOINT_BACKEND="POSTGRES",
        CHECKPOINT_DATABASE_URL="postgresql://worker:secret@db.invalid/repolens",
        ENVIRONMENT="development",
    ).model_copy(update={"ENVIRONMENT": "production"})
    monkeypatch.setattr("app.agents.checkpointer.get_settings", lambda: settings)
    with pytest.raises(CheckpointerConfigurationError, match="unavailable in production"):
        async with get_sqlite_checkpointer(":memory:"):
            pytest.fail("legacy SQLite helper opened in production")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_optional_postgres_checkpoint_round_trip():
    url = os.environ.get("TEST_POSTGRES_URL")
    if not url:
        pytest.skip("TEST_POSTGRES_URL is not configured")

    settings = _settings(
        CHECKPOINT_BACKEND="POSTGRES",
        CHECKPOINT_DATABASE_URL=url,
    )
    state = {"events": []}
    builder = StateGraph(_PlainState)
    builder.add_node("done", lambda _state: {"events": ["postgres"]})
    builder.add_edge(START, "done")
    builder.add_edge("done", END)
    thread_id = f"test-postgres-checkpoint-{os.urandom(8).hex()}"
    config = {"configurable": {"thread_id": thread_id}}
    with patch("app.agents.checkpointer.get_settings", return_value=settings):
        async with get_analysis_checkpointer(state_profile="plain") as saver:
            await saver.setup()
            graph = builder.compile(checkpointer=saver)
            await graph.ainvoke(state, config=config, durability="sync")
            checkpoint = await graph.aget_state(config)
            assert checkpoint.values["events"] == ["postgres"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_postgres_pending_parallel_write_survives_real_saver_reopen():
    """A completed PostgreSQL sibling is not rerun when a new saver resumes the thread."""
    url = os.environ.get("TEST_POSTGRES_URL")
    if not url:
        pytest.skip("TEST_POSTGRES_URL is not configured")

    settings = _settings(
        CHECKPOINT_BACKEND="POSTGRES",
        CHECKPOINT_DATABASE_URL=url,
    )
    left_runs = 0
    right_runs = 0
    left_finished = asyncio.Event()

    async def left(_state):
        nonlocal left_runs
        left_runs += 1
        left_finished.set()
        return {"events": ["left"]}

    async def right(_state):
        nonlocal right_runs
        right_runs += 1
        await left_finished.wait()
        if right_runs == 1:
            raise RuntimeError("intentional one-time PostgreSQL interruption")
        return {"events": ["right"]}

    def build(saver):
        builder = StateGraph(_PlainState)
        builder.add_node("left", left)
        builder.add_node("right", right)
        builder.add_edge(START, "left")
        builder.add_edge(START, "right")
        builder.add_edge("left", END)
        builder.add_edge("right", END)
        return builder.compile(checkpointer=saver)

    config = {"configurable": {"thread_id": f"postgres-sibling-reopen-{os.urandom(12).hex()}"}}
    with patch("app.agents.checkpointer.get_settings", return_value=settings):
        async with get_analysis_checkpointer(
            backend=CheckpointBackend.POSTGRES,
            database_url=url,
            state_profile="plain",
        ) as saver_a:
            await saver_a.setup()
            graph_a = build(saver_a)
            with pytest.raises(RuntimeError, match="intentional one-time PostgreSQL interruption"):
                await graph_a.ainvoke({"events": []}, config=config, durability="sync")

        async with get_analysis_checkpointer(
            backend=CheckpointBackend.POSTGRES,
            database_url=url,
            state_profile="plain",
        ) as saver_b:
            graph_b = build(saver_b)
            resumed = await graph_b.ainvoke(None, config=config, durability="sync")
            saved = await graph_b.aget_state(config)

    assert left_runs == 1
    assert right_runs == 2
    assert sorted(resumed["events"]) == ["left", "right"]
    assert sorted(saved.values["events"]) == ["left", "right"]
