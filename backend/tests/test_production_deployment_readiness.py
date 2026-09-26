"""Zero-network deployment contract tests for production readiness and startup."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import tomllib
from types import SimpleNamespace

import pytest
from fastapi import Response
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from app.cli.production_preflight import (
    PRODUCTION_REQUIRED_MODULES,
    ProductionDependencyError,
    check_production_dependencies,
    require_production_dependencies,
)
from app.core.config import Settings
from app.core.production_readiness import (
    validate_production_artifact_storage,
    validate_production_database_schema,
)
from app.core.schema_readiness import (
    current_alembic_heads,
    expected_alembic_heads,
    migration_revision_is_current,
    required_application_tables,
)
from app.models import Base


def _production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "ENVIRONMENT": "production",
        "DATABASE_URL": "postgresql+psycopg://repolens:secret@db.example/repolens",
        "CHECKPOINT_BACKEND": "POSTGRES",
        "CHECKPOINT_DATABASE_URL": "postgresql+psycopg://repolens:secret@db.example/repolens",
        "AUTH_COOKIE_SECURE": True,
        "ARTIFACT_DEPLOYMENT_MODE": "single_persistent_local",
        "CORS_ORIGINS": ["https://app.example"],
        "TRUSTED_HOSTS": ["app.example"],
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _sqlite_schema(*, missing: set[str] | None = None, revision: str | None = None):
    engine = create_engine("sqlite:///:memory:")
    omitted = missing or set()
    tables = [table for table in Base.metadata.sorted_tables if table.name not in omitted]
    Base.metadata.create_all(engine, tables=tables)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        if revision is not None:
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": revision},
            )
    return engine


def test_production_preflight_fails_closed_for_missing_mandatory_import_without_leaking(monkeypatch) -> None:
    settings = _production_settings()
    secret_url = settings.DATABASE_URL

    def importer(name: str):
        if name in {"psycopg", "langgraph.checkpoint.postgres.aio"}:
            raise ImportError(f"missing {name}; configured URL was {secret_url}")
        return object()

    result = check_production_dependencies(settings, importer=importer)
    assert result.production and not result.ready
    assert result.missing_modules == ("langgraph.checkpoint.postgres.aio", "psycopg")
    with pytest.raises(ProductionDependencyError) as raised:
        require_production_dependencies(settings, importer=importer)
    assert secret_url not in str(raised.value)
    assert "db.example" not in str(raised.value)


def test_optional_local_ml_and_exporter_imports_are_not_production_requirements() -> None:
    settings = _production_settings()

    def importer(name: str):
        if name in {"sentence_transformers", "opentelemetry.exporter.otlp.proto.http.trace_exporter"}:
            raise ImportError(name)
        return object()

    result = check_production_dependencies(settings, importer=importer)
    assert result.ready
    assert "sentence_transformers" not in PRODUCTION_REQUIRED_MODULES
    assert not any(name.startswith("opentelemetry.exporter") for name in PRODUCTION_REQUIRED_MODULES)


def test_development_preflight_skips_production_extras_without_import_attempts() -> None:
    settings = Settings(_env_file=None, ENVIRONMENT="development")
    calls: list[str] = []

    def importer(name: str):
        calls.append(name)
        raise ImportError(name)

    result = check_production_dependencies(settings, importer=importer)
    assert not result.production and result.ready
    assert not calls


def test_dependency_metadata_has_one_explicit_production_contract() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    extras = project["project"]["optional-dependencies"]
    assert {item.split(">=")[0].split("[")[0] for item in extras["production"]} == {
        "psycopg",
        "langgraph-checkpoint-postgres",
    }
    assert not any("pytest" in item for item in extras["production"])
    requirements = Path("requirements.txt").read_text(encoding="utf-8")
    assert "-e .[dev]" in requirements
    assert "production deployments must use" in requirements.lower()
    assert "psycopg" not in requirements


def test_repository_migration_identity_and_metadata_are_complete() -> None:
    assert len(expected_alembic_heads()) == 1
    tables = required_application_tables()
    assert {"users", "reports", "execution_work_items", "index_entries"}.issubset(tables)
    assert "alembic_version" not in tables


def test_migration_revision_must_exactly_match_repository_head() -> None:
    head = expected_alembic_heads()[0]
    engine = _sqlite_schema(revision=head)
    try:
        with Session(engine) as db:
            names = set(inspect(engine).get_table_names())
            assert current_alembic_heads(db, names) == (head,)
            assert migration_revision_is_current(db, names)
    finally:
        engine.dispose()

    for revision in (None, "older-revision", "unknown-revision"):
        engine = _sqlite_schema(revision=revision)
        try:
            with Session(engine) as db:
                names = set(__import__("sqlalchemy").inspect(engine).get_table_names())
                assert not migration_revision_is_current(db, names)
        finally:
            engine.dispose()

    engine = create_engine("sqlite:///:memory:")
    try:
        with Session(engine) as db:
            assert current_alembic_heads(db, set()) == ()
            assert not migration_revision_is_current(db, set())
    finally:
        engine.dispose()


@pytest.mark.parametrize("missing", ["users", "reports", "execution_work_items", "index_entries"])
def test_current_revision_cannot_mask_missing_required_application_table(missing: str) -> None:
    engine = _sqlite_schema(missing={missing}, revision=expected_alembic_heads()[0])
    try:
        from app.observability.operations import schema_readiness

        with Session(engine) as db:
            result = schema_readiness(db)
        assert not result["ready"]
        assert result["migration_current"]
    finally:
        engine.dispose()


def test_complete_tables_with_stale_migration_revision_are_not_ready() -> None:
    engine = _sqlite_schema(revision="older-revision")
    try:
        from app.observability.operations import schema_readiness

        with Session(engine) as db:
            result = schema_readiness(db)
        assert not result["ready"]
        assert not result["migration_current"]
    finally:
        engine.dispose()


def test_complete_schema_and_current_revision_are_required_for_schema_readiness() -> None:
    engine = _sqlite_schema(revision=expected_alembic_heads()[0])
    try:
        from app.observability.operations import schema_readiness

        with Session(engine) as db:
            assert schema_readiness(db)["ready"]
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_readiness_endpoint_fails_closed_and_keeps_public_body_minimal(monkeypatch) -> None:
    from app.api.routes.health import readiness
    from app.observability import operations

    class BrokenDatabase:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("postgres://private-user:secret@private-host/db")

    response = Response()
    result = await readiness(response, BrokenDatabase())  # type: ignore[arg-type]
    assert response.status_code == 503
    assert result == {"status": "not_ready"}

    probe_calls: list[str] = []

    async def checkpointer(settings):
        probe_calls.append("checkpointer")
        return {"ready": True}

    monkeypatch.setattr(operations, "check_checkpointer_readiness", checkpointer)
    monkeypatch.setattr(operations, "schema_readiness", lambda _db: {"ready": True})

    class ReadyDatabase:
        def execute(self, *_args, **_kwargs):
            return None

    response = Response()
    result = await readiness(response, ReadyDatabase())  # type: ignore[arg-type]
    assert response.status_code == 200
    assert result == {"status": "ready"}
    assert probe_calls == ["checkpointer"]
    assert not any(key in str(result).lower() for key in ("database", "provider", "host", "migration", "checkpoint"))

    async def unavailable_checkpointer(_settings):
        return {"ready": False, "host": "private-host", "state": "schema error"}

    monkeypatch.setattr(operations, "check_checkpointer_readiness", unavailable_checkpointer)
    response = Response()
    result = await readiness(response, ReadyDatabase())  # type: ignore[arg-type]
    assert response.status_code == 503
    assert result == {"status": "not_ready"}


@pytest.mark.asyncio
async def test_readiness_does_not_probe_checkpointer_for_incomplete_schema(monkeypatch) -> None:
    from app.api.routes.health import readiness
    from app.observability import operations

    async def forbidden_probe(_settings):
        raise AssertionError("checkpointer is not authoritative until DB/schema are ready")

    monkeypatch.setattr(operations, "schema_readiness", lambda _db: {"ready": False})
    monkeypatch.setattr(operations, "check_checkpointer_readiness", forbidden_probe)

    class ConnectedDatabase:
        def execute(self, *_args, **_kwargs):
            return None

    response = Response()
    assert await readiness(response, ConnectedDatabase()) == {"status": "not_ready"}  # type: ignore[arg-type]
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_checkpointer_readiness_is_time_bounded_and_sanitized(monkeypatch) -> None:
    from app.observability import operations
    from app.agents.checkpointer import CheckpointBackend

    async def slow_probe():
        await asyncio.sleep(0.1)

    monkeypatch.setattr(operations, "resolve_checkpoint_backend", lambda _settings: CheckpointBackend.POSTGRES)
    monkeypatch.setattr(operations, "validate_analysis_checkpointer_ready", slow_probe)
    settings = SimpleNamespace(
        CHECKPOINT_BACKEND="POSTGRES",
        DATABASE_POOL_TIMEOUT_SECONDS=0.001,
        is_production=True,
    )
    result = await operations.check_checkpointer_readiness(settings)
    assert result == {"ready": False, "backend": "UNKNOWN", "state": "UNAVAILABLE"}


def test_production_settings_reject_unsafe_database_cookie_origins_and_hosts() -> None:
    for overrides in (
        {"DATABASE_URL": "sqlite:///production.db"},
        {"AUTH_COOKIE_SECURE": False},
        {"CORS_ORIGINS": []},
        {"CORS_ORIGINS": ["*"]},
        {"CORS_ORIGINS": ["http://localhost:3000"]},
        {"CORS_ORIGINS": ["https://localhost.:8443"]},
        {"TRUSTED_HOSTS": []},
        {"TRUSTED_HOSTS": ["*"]},
        {"TRUSTED_HOSTS": ["localhost", "testserver"]},
        {"TRUSTED_HOSTS": ["localhost."]},
        {"CHECKPOINT_BACKEND": "SQLITE"},
        {"CHECKPOINT_BACKEND": "MEMORY_TEST_ONLY"},
        {"CHECKPOINT_DATABASE_URL": "sqlite:///checkpoints.db"},
    ):
        with pytest.raises(ValidationError):
            _production_settings(**overrides)


def test_production_settings_allow_local_proxy_hosts_alongside_real_origins() -> None:
    config = _production_settings(
        CORS_ORIGINS=["https://app.example", "http://localhost:3000"],
        TRUSTED_HOSTS=["app.example", "localhost"],
    )
    assert config.is_production


def test_cross_host_production_csrf_cookie_requires_shared_parent_domain() -> None:
    common = {
        "CORS_ORIGINS": ["https://app.example.com"],
        "TRUSTED_HOSTS": ["api.example.com"],
    }
    with pytest.raises(ValidationError, match="Cross-host production frontends"):
        _production_settings(**common)
    configured = _production_settings(**common, CSRF_COOKIE_DOMAIN=".example.com")
    assert configured.CSRF_COOKIE_DOMAIN == ".example.com"
    assert _production_settings(**common, AUTH_COOKIE_DOMAIN=".example.com", CSRF_COOKIE_DOMAIN=".example.com")


@pytest.mark.parametrize("domain", [".com", "api.example.com/path", "https://example.com", "127.0.0.1"])
def test_production_cookie_domain_rejects_public_suffix_or_non_domain_values(domain: str) -> None:
    with pytest.raises(ValidationError):
        _production_settings(CSRF_COOKIE_DOMAIN=domain)


def test_shared_artifact_mode_is_allowed_by_config_but_fails_readiness_without_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.artifacts import service as artifact_service

    monkeypatch.setattr(artifact_service, "_configured_store", None)
    settings = _production_settings(
        ARTIFACT_STORAGE_BACKEND="blob",
        ARTIFACT_DEPLOYMENT_MODE="shared",
        ARTIFACT_BLOB_CONTAINER="reports",
        REPORT_ARTIFACT_DIR=str(tmp_path / "staging"),
    )
    with pytest.raises(RuntimeError, match="ConditionalBlobClient adapter"):
        validate_production_artifact_storage(settings)
    from app.artifacts.store import LocalArtifactStore

    monkeypatch.setattr(artifact_service, "_configured_store", LocalArtifactStore(tmp_path / "wrong-local-store"))
    with pytest.raises(RuntimeError, match="conditional production blob adapter"):
        validate_production_artifact_storage(settings)


def test_production_validation_error_does_not_echo_database_credentials() -> None:
    secret_url = "sqlite:///user:very-private-password@host/database"
    with pytest.raises(ValidationError) as raised:
        _production_settings(DATABASE_URL=secret_url)
    assert secret_url not in str(raised.value)
    assert "very-private-password" not in str(raised.value)


def test_artifact_storage_preflight_checks_writable_paths_and_cleans_probe(tmp_path, monkeypatch) -> None:
    from app.core import production_readiness

    settings = _production_settings(
        REPORT_ARTIFACT_DIR=str(tmp_path / "reports"),
        ARTIFACT_ROOT_DIR=str(tmp_path / "canonical"),
        ARTIFACT_STORAGE_BACKEND="local",
    )
    validate_production_artifact_storage(settings)
    assert list((tmp_path / "reports").iterdir()) == []
    assert list((tmp_path / "canonical").iterdir()) == []

    def fail_probe(*_args, **_kwargs):
        raise OSError("secret mount path")

    monkeypatch.setattr(production_readiness.tempfile, "mkstemp", fail_probe)
    with pytest.raises(RuntimeError, match="not writable") as raised:
        validate_production_artifact_storage(settings)
    assert "secret mount path" not in str(raised.value)


def test_production_database_preflight_rejects_non_postgresql_without_leaking() -> None:
    class FakeBind:
        dialect = SimpleNamespace(name="sqlite")

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_bind(self):
            return FakeBind()

    with pytest.raises(RuntimeError, match="readiness validation failed") as raised:
        validate_production_database_schema(FakeSession)  # type: ignore[arg-type]
    assert "sqlite" not in str(raised.value).lower()


def test_production_database_preflight_sanitizes_connection_failures() -> None:
    secret_url = "postgresql://private-user:private-password@private-host/private-db"

    class FakeBind:
        dialect = SimpleNamespace(name="postgresql")

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_bind(self):
            return FakeBind()

        def execute(self, *_args, **_kwargs):
            raise RuntimeError(f"connection failed for {secret_url}")

    with pytest.raises(RuntimeError, match="readiness validation failed") as raised:
        validate_production_database_schema(FakeSession)  # type: ignore[arg-type]
    assert secret_url not in str(raised.value)
    assert "private-password" not in str(raised.value)


def test_lifespan_rejects_invalid_production_authority_before_starting_workers(monkeypatch) -> None:
    import app.core.production_readiness as readiness
    import app.main as main
    from app.agents import checkpointer
    from app.core import schema_readiness
    from app.execution.dispatcher import DurableWorkDispatcher

    started: list[str] = []
    monkeypatch.setattr(main, "settings", SimpleNamespace(is_production=True, DATABASE_POOL_TIMEOUT_SECONDS=1))
    monkeypatch.setattr(main, "require_production_dependencies", lambda _settings: None)
    monkeypatch.setattr(main, "_validate_production_configuration", lambda _settings: None)
    monkeypatch.setattr(
        readiness,
        "validate_production_database_schema",
        lambda _factory: (_ for _ in ()).throw(RuntimeError("schema invalid")),
    )
    monkeypatch.setattr(checkpointer, "validate_analysis_checkpointer_ready", lambda: _unexpected_async())
    monkeypatch.setattr(schema_readiness, "required_application_tables", lambda: {"execution_work_items"})
    monkeypatch.setattr(DurableWorkDispatcher, "start", lambda: started.append("dispatcher"))

    with pytest.raises(RuntimeError, match="startup authority validation failed"):
        asyncio.run(_enter_lifespan(main.lifespan, main.app))
    assert started == []


def test_lifespan_rejects_missing_dependencies_before_database_or_workers(monkeypatch) -> None:
    import app.core.production_readiness as readiness
    import app.main as main
    from app.core import schema_readiness
    from app.execution.dispatcher import DurableWorkDispatcher

    started: list[str] = []
    monkeypatch.setattr(main, "settings", SimpleNamespace(is_production=True, DATABASE_POOL_TIMEOUT_SECONDS=1))
    monkeypatch.setattr(
        main,
        "require_production_dependencies",
        lambda _settings: (_ for _ in ()).throw(ProductionDependencyError(1)),
    )
    monkeypatch.setattr(main, "_validate_production_configuration", lambda _settings: None)
    monkeypatch.setattr(
        readiness,
        "validate_production_database_schema",
        lambda _factory: (_ for _ in ()).throw(AssertionError("DB must not be touched")),
    )
    monkeypatch.setattr(schema_readiness, "required_application_tables", lambda: {"execution_work_items"})
    monkeypatch.setattr(DurableWorkDispatcher, "start", lambda: started.append("dispatcher"))

    with pytest.raises(RuntimeError, match="startup authority validation failed"):
        asyncio.run(_enter_lifespan(main.lifespan, main.app))
    assert started == []


def test_lifespan_rejects_unavailable_checkpointer_before_artifacts_or_workers(monkeypatch) -> None:
    import app.core.production_readiness as readiness
    import app.main as main
    import app.observability as observability
    from app.agents import checkpointer
    from app.core import schema_readiness
    from app.execution.dispatcher import DurableWorkDispatcher

    reached: list[str] = []
    monkeypatch.setattr(main, "settings", SimpleNamespace(is_production=True, DATABASE_POOL_TIMEOUT_SECONDS=1))
    monkeypatch.setattr(main, "require_production_dependencies", lambda _settings: None)
    monkeypatch.setattr(main, "_validate_production_configuration", lambda _settings: None)
    monkeypatch.setattr(readiness, "validate_production_database_schema", lambda _factory: reached.append("database"))
    monkeypatch.setattr(readiness, "validate_production_artifact_storage", lambda _settings: reached.append("storage"))

    async def unavailable_checkpointer():
        reached.append("checkpointer")
        raise RuntimeError("private checkpoint URL")

    monkeypatch.setattr(checkpointer, "validate_analysis_checkpointer_ready", unavailable_checkpointer)
    monkeypatch.setattr(schema_readiness, "required_application_tables", lambda: {"execution_work_items"})
    monkeypatch.setattr(observability, "configure_tracing", lambda _settings: None)
    monkeypatch.setattr(observability, "configure_metrics", lambda _settings: None)
    monkeypatch.setattr(DurableWorkDispatcher, "start", lambda *_args: reached.append("worker"))

    with pytest.raises(RuntimeError, match="startup authority validation failed") as raised:
        asyncio.run(_enter_lifespan(main.lifespan, main.app))
    assert "private checkpoint URL" not in str(raised.value)
    assert reached == ["database", "checkpointer"]


def test_optional_redis_and_telemetry_failures_do_not_block_production_lifespan(monkeypatch) -> None:
    import app.core.production_readiness as readiness
    import app.main as main
    import app.observability as observability
    from app.agents import checkpointer
    from app.core import schema_readiness
    from app.core import redis as redis_module

    events: list[str] = []

    class Redis:
        async def initialize(self):
            events.append("redis_attempt")
            raise RuntimeError("private redis endpoint")

        async def close(self):
            events.append("redis_close")

    monkeypatch.setattr(main, "settings", SimpleNamespace(
        is_production=True,
        is_sqlite=False,
        DATABASE_POOL_TIMEOUT_SECONDS=1,
    ))
    monkeypatch.setattr(main, "require_production_dependencies", lambda _settings: None)
    monkeypatch.setattr(main, "_validate_production_configuration", lambda _settings: None)
    monkeypatch.setattr(readiness, "validate_production_database_schema", lambda _factory: None)
    monkeypatch.setattr(readiness, "validate_production_artifact_storage", lambda _settings: None)
    monkeypatch.setattr(checkpointer, "validate_analysis_checkpointer_ready", lambda: _resolved_async())
    monkeypatch.setattr(schema_readiness, "required_application_tables", lambda: set())
    monkeypatch.setattr(observability, "configure_tracing", lambda _settings: (_ for _ in ()).throw(RuntimeError("OTLP secret")))
    monkeypatch.setattr(observability, "configure_metrics", lambda _settings: (_ for _ in ()).throw(RuntimeError("OTLP secret")))
    monkeypatch.setattr(observability, "shutdown_tracing", lambda: events.append("tracing_close"))
    monkeypatch.setattr(observability, "shutdown_metrics", lambda: events.append("metrics_close"))
    monkeypatch.setattr(redis_module, "get_redis_manager", lambda: Redis())

    assert asyncio.run(_yield_lifespan(main.lifespan, main.app))
    assert "redis_attempt" in events
    assert "redis_close" in events
    assert "tracing_close" in events
    assert "metrics_close" in events


def test_lifespan_cleans_up_started_workers_after_later_worker_failure(monkeypatch) -> None:
    import app.core.production_readiness as readiness
    import app.main as main
    import app.observability as observability
    from app.agents import checkpointer
    from app.core import schema_readiness
    from app.core import redis as redis_module
    from app.execution.dispatcher import DurableWorkDispatcher
    from app.governance.outbox import RelationalOutboxRelay

    events: list[str] = []

    class Redis:
        async def initialize(self):
            events.append("redis_initialize")

        async def close(self):
            events.append("redis_close")

    monkeypatch.setattr(main, "settings", SimpleNamespace(
        is_production=True,
        is_sqlite=False,
        DATABASE_POOL_TIMEOUT_SECONDS=1,
    ))
    monkeypatch.setattr(main, "require_production_dependencies", lambda _settings: None)
    monkeypatch.setattr(main, "_validate_production_configuration", lambda _settings: None)
    monkeypatch.setattr(readiness, "validate_production_database_schema", lambda _factory: None)
    monkeypatch.setattr(readiness, "validate_production_artifact_storage", lambda _settings: None)
    monkeypatch.setattr(checkpointer, "validate_analysis_checkpointer_ready", lambda: _resolved_async())
    monkeypatch.setattr(schema_readiness, "required_application_tables", lambda: {
        "execution_work_items", "outbox_events",
    })
    monkeypatch.setattr(observability, "configure_tracing", lambda _settings: None)
    monkeypatch.setattr(observability, "configure_metrics", lambda _settings: None)
    monkeypatch.setattr(observability, "shutdown_tracing", lambda: events.append("tracing_stop"))
    monkeypatch.setattr(observability, "shutdown_metrics", lambda: events.append("metrics_stop"))
    monkeypatch.setattr(redis_module, "get_redis_manager", lambda: Redis())
    monkeypatch.setattr(DurableWorkDispatcher, "reconcile_orphaned_domain_work", lambda *_args: 0)
    monkeypatch.setattr(DurableWorkDispatcher, "start", lambda *_args: events.append("dispatcher_start"))
    monkeypatch.setattr(DurableWorkDispatcher, "stop", lambda *_args: events.append("dispatcher_stop"))

    def fail_outbox_start() -> None:
        events.append("outbox_start")
        raise RuntimeError("private worker diagnostic")

    monkeypatch.setattr(RelationalOutboxRelay, "start", lambda *_args: fail_outbox_start())
    monkeypatch.setattr(RelationalOutboxRelay, "stop", lambda *_args: events.append("outbox_stop"))

    with pytest.raises(RuntimeError, match="runtime initialization failed") as raised:
        asyncio.run(_enter_lifespan(main.lifespan, main.app))
    assert "private worker diagnostic" not in str(raised.value)
    assert events.index("dispatcher_start") < events.index("outbox_start")
    assert events.index("outbox_start") < events.index("dispatcher_stop")
    assert events.index("outbox_stop") < events.index("dispatcher_stop")
    assert "redis_close" in events


async def _resolved_async() -> None:
    return None




async def _unexpected_async() -> None:
    raise AssertionError("checkpointer must not be reached after schema failure")


async def _enter_lifespan(lifespan, app) -> None:
    async with lifespan(app):
        raise AssertionError("invalid production authority must prevent lifespan yield")


async def _yield_lifespan(lifespan, app) -> bool:
    async with lifespan(app):
        return True
