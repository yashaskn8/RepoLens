"""Official LangGraph checkpointer selection and lifecycle for RepoLens workflows."""

from __future__ import annotations

from contextlib import asynccontextmanager
from enum import Enum
from typing import AsyncIterator, Literal, Optional

import aiosqlite
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from sqlalchemy.engine import URL, make_url

from app.core.config import Settings, get_settings


class CheckpointBackend(str, Enum):
    AUTO = "AUTO"
    SQLITE = "SQLITE"
    POSTGRES = "POSTGRES"
    MEMORY_TEST_ONLY = "MEMORY_TEST_ONLY"


CheckpointStateProfile = Literal["analysis", "change_analysis", "plain"]


class CheckpointerConfigurationError(RuntimeError):
    """Raised when the configured durable graph store cannot be used safely."""


def normalize_postgres_checkpoint_url(value: str) -> str:
    """Return a psycopg-compatible PostgreSQL URI without losing URL components.

    SQLAlchemy URLs such as ``postgresql+psycopg://`` are normalized through
    SQLAlchemy's URL parser so credentials, IPv6 hosts, ports, database names,
    and query parameters survive unchanged. The returned URI must never be logged.
    """

    try:
        parsed: URL = make_url(value)
    except Exception:
        raise CheckpointerConfigurationError(
            "The checkpoint database URL is invalid."
        ) from None
    if parsed.get_backend_name() in {"postgresql", "postgres"}:
        parsed = parsed.set(drivername="postgresql")
    else:
        raise CheckpointerConfigurationError(
            "The checkpoint database URL must use PostgreSQL."
        )
    return parsed.render_as_string(hide_password=False)


def _database_is_postgres(value: str) -> bool:
    try:
        return make_url(value).get_backend_name() in {"postgresql", "postgres"}
    except Exception:
        return False


def resolve_checkpoint_backend(
    settings: Settings,
    *,
    backend: CheckpointBackend | str | None = None,
    db_path: str | None = None,
    database_url: str | None = None,
) -> CheckpointBackend:
    """Resolve the closed backend policy, failing closed for production SQLite."""

    raw = backend if backend is not None else settings.CHECKPOINT_BACKEND
    try:
        requested = raw if isinstance(raw, CheckpointBackend) else CheckpointBackend(str(raw).upper())
    except ValueError:
        raise CheckpointerConfigurationError("Unsupported checkpoint backend.") from None

    if requested == CheckpointBackend.AUTO:
        if db_path is not None and database_url:
            raise CheckpointerConfigurationError(
                "Choose either a local checkpoint path or a PostgreSQL checkpoint URL, not both."
            )
        if db_path is not None:
            selected = CheckpointBackend.SQLITE
        elif database_url or settings.CHECKPOINT_DATABASE_URL:
            configured_url = database_url or settings.CHECKPOINT_DATABASE_URL
            if not _database_is_postgres(configured_url):
                raise CheckpointerConfigurationError(
                    "The configured checkpoint URL must use PostgreSQL."
                )
            selected = CheckpointBackend.POSTGRES
        elif _database_is_postgres(settings.DATABASE_URL):
            selected = CheckpointBackend.POSTGRES
        else:
            selected = CheckpointBackend.SQLITE
    else:
        selected = requested

    if settings.is_production and selected != CheckpointBackend.POSTGRES:
        raise CheckpointerConfigurationError(
            "Production graph execution requires the PostgreSQL checkpointer."
        )
    if selected == CheckpointBackend.POSTGRES:
        configured_url = database_url or settings.CHECKPOINT_DATABASE_URL or settings.DATABASE_URL
        if not _database_is_postgres(configured_url):
            raise CheckpointerConfigurationError(
                "PostgreSQL checkpointing requires a PostgreSQL checkpoint or application database URL."
            )
    return selected


def _checkpoint_url(settings: Settings, override: str | None = None) -> str:
    value = override or settings.CHECKPOINT_DATABASE_URL or settings.DATABASE_URL
    return normalize_postgres_checkpoint_url(value)


def _strict_serializer(profile: CheckpointStateProfile) -> JsonPlusSerializer:
    """Use LangGraph's safe msgpack types plus exact RepoLens state model types.

    AnalysisState currently checkpoints only ``Finding`` and
    ``ModelExecutionMetadata`` Pydantic instances. Change-analysis state has a
    separate exact allowlist. Arbitrary application module loading and pickle
    fallback are deliberately disabled.
    """

    models: tuple[type, ...]
    if profile == "analysis":
        from app.schemas.finding import Finding
        from app.schemas.metadata import ModelExecutionMetadata

        models = (Finding, ModelExecutionMetadata)
    elif profile == "change_analysis":
        from app.schemas.change_analysis import (
            BlastRadiusReport,
            ChangeReviewReport,
            StructuralDiffResult,
        )

        models = (StructuralDiffResult, BlastRadiusReport, ChangeReviewReport)
    elif profile == "plain":
        models = ()
    else:  # Guard against callers bypassing the closed Literal at runtime.
        raise CheckpointerConfigurationError("Unsupported checkpoint state profile.")

    exact_symbols = tuple((model.__module__, model.__name__) for model in models)
    return JsonPlusSerializer(
        pickle_fallback=False,
        allowed_json_modules=exact_symbols,
        allowed_msgpack_modules=models,
    )


@asynccontextmanager
async def get_analysis_checkpointer(
    *,
    db_path: Optional[str] = None,
    backend: CheckpointBackend | str | None = None,
    database_url: str | None = None,
    state_profile: CheckpointStateProfile = "analysis",
) -> AsyncIterator[object]:
    """Open the configured official LangGraph checkpointer.

    SQLite remains the local/test default and initializes its idempotent schema
    on open. PostgreSQL uses a per-execution managed async psycopg connection;
    its schema is initialized only by the explicit operator setup command.
    """

    settings = get_settings()
    selected = resolve_checkpoint_backend(
        settings,
        backend=backend,
        db_path=db_path,
        database_url=database_url,
    )
    serde = _strict_serializer(state_profile)

    if selected == CheckpointBackend.SQLITE:
        target_path = db_path if db_path is not None else settings.CHECKPOINT_DB_FILE
        async with aiosqlite.connect(target_path) as conn:
            saver = AsyncSqliteSaver(conn, serde=serde)
            await saver.setup()
            yield saver
        return

    if selected == CheckpointBackend.MEMORY_TEST_ONLY:
        if settings.is_production:
            raise CheckpointerConfigurationError(
                "The in-memory checkpointer is restricted to tests."
            )
        from langgraph.checkpoint.memory import InMemorySaver

        yield InMemorySaver(serde=serde)
        return

    if selected != CheckpointBackend.POSTGRES:
        raise CheckpointerConfigurationError("No supported checkpoint backend was selected.")

    try:
        from psycopg import AsyncConnection
        from psycopg.rows import dict_row
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    except ImportError:
        raise CheckpointerConfigurationError(
            "PostgreSQL checkpointing requires the optional 'postgres' dependencies."
        ) from None

    dsn = _checkpoint_url(settings, database_url)
    try:
        connection = await AsyncConnection.connect(
            dsn,
            autocommit=True,
            prepare_threshold=0,
            row_factory=dict_row,
        )
    except Exception:
        # Driver exceptions can include the full connection URL. Never allow
        # credentials or host-specific details to reach scan/error telemetry.
        raise CheckpointerConfigurationError(
            "The PostgreSQL checkpoint connection could not be opened."
        ) from None
    async with connection:
        yield AsyncPostgresSaver(connection, serde=serde)


@asynccontextmanager
async def get_sqlite_checkpointer(
    db_path: Optional[str] = None,
) -> AsyncIterator[AsyncSqliteSaver]:
    """Compatibility helper for explicitly local/test SQLite workflows.

    Production callers must use :func:`get_analysis_checkpointer`, which
    selects PostgreSQL and rejects SQLite.
    """

    settings = get_settings()
    if settings.is_production:
        raise CheckpointerConfigurationError(
            "The SQLite compatibility checkpointer is unavailable in production."
        )
    async with get_analysis_checkpointer(
        db_path=db_path,
        backend=CheckpointBackend.SQLITE,
        state_profile="analysis",
    ) as saver:
        yield saver  # type: ignore[misc]


async def setup_analysis_checkpointer() -> CheckpointBackend:
    """Initialize the official saver schema for an explicit deployment setup."""

    settings = get_settings()
    selected = resolve_checkpoint_backend(settings)
    if selected == CheckpointBackend.MEMORY_TEST_ONLY:
        raise CheckpointerConfigurationError("The in-memory backend has no persistent schema.")
    async with get_analysis_checkpointer(backend=selected) as saver:
        if selected == CheckpointBackend.POSTGRES:
            await saver.setup()  # type: ignore[attr-defined]
    return selected


async def validate_analysis_checkpointer_ready() -> None:
    """Verify production backend connectivity and initialized schema without setup."""

    settings = get_settings()
    selected = resolve_checkpoint_backend(settings)
    if not settings.is_production:
        return
    try:
        async with get_analysis_checkpointer(backend=selected) as saver:
            await saver.aget_tuple(
                {"configurable": {"thread_id": "repolens-checkpointer-readiness-v1"}}
            )
    except Exception:
        # Driver messages can include deployment-specific connection metadata.
        raise CheckpointerConfigurationError(
            "The production PostgreSQL checkpointer is unavailable or not initialized."
        ) from None


__all__ = [
    "CheckpointBackend",
    "CheckpointerConfigurationError",
    "get_analysis_checkpointer",
    "get_sqlite_checkpointer",
    "normalize_postgres_checkpoint_url",
    "resolve_checkpoint_backend",
    "setup_analysis_checkpointer",
    "validate_analysis_checkpointer_ready",
]
