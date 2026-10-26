"""Tests for the backend health check endpoints."""

from fastapi.testclient import TestClient
from unittest.mock import patch


def test_root_endpoint(client: TestClient):
    """Verify GET / returns basic service info and status."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "RepoLens"
    assert data["version"] == "1.0.1"
    assert "health_url" in data


def test_health_endpoint_root(client: TestClient):
    """Verify GET /health returns healthy status and DB connection."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "RepoLens"
    assert data["database"] == "connected"
    assert data["version"] == "1.0.1"


def test_health_endpoint_api_v1(client: TestClient):
    """Verify GET /api/v1/health returns matching healthy status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "RepoLens"
    assert data["database"] == "connected"


def test_health_reports_connected_but_unmigrated_database_as_degraded(client: TestClient):
    with patch(
        "app.api.routes.health.missing_scan_storage_tables",
        return_value=frozenset({"index_snapshots"}),
    ):
        response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert data["database"] == "migration_required"


def test_public_health_does_not_log_database_connection_secret(caplog):
    """Production logs must not echo secret-bearing driver diagnostics."""
    from app.api.routes.health import check_health

    canary = "postgresql://private-user:private-password@private.internal/database"

    class BrokenDatabase:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError(canary)

    with caplog.at_level("ERROR"):
        response = check_health(BrokenDatabase())  # type: ignore[arg-type]
    assert response["status"] == "degraded"
    assert canary not in caplog.text
    assert "private-password" not in caplog.text


def test_telemetry_uses_configured_sqlite_checkpoint_directory(client, monkeypatch, tmp_path):
    """Do not report writable checkpoints by checking a nonexistent default path."""
    from app.api.routes import health

    missing_dir = tmp_path / "missing-checkpoint-volume"
    monkeypatch.setattr(health.settings, "CHECKPOINT_DB_FILE", str(missing_dir / "checkpoints.db"))

    response = client.get("/health/telemetry")
    assert response.status_code == 200
    assert response.json()["storage"]["checkpointer_storage_accessible"] is False


def test_completed_scan_sse_emits_state_based_terminal_signal_if_event_missing(
    client, db_session,
):
    from uuid import uuid4
    from app.models.scan import ScanModel
    from app.schemas.enums import ScanStatus

    scan_id = str(uuid4())
    db_session.add(ScanModel(
        id=scan_id,
        repository_url="https://github.com/example/repo",
        status=ScanStatus.COMPLETED.value,
    ))
    db_session.commit()

    response = client.get(f"/api/v1/scans/{scan_id}/events")
    assert response.status_code == 200
    assert "event: SCAN_COMPLETED" in response.text
    assert '"status_source": "persisted_resource_state"' in response.text



def test_detailed_telemetry_reports_degraded_when_metric_queries_fail(monkeypatch):
    """Incomplete metrics must not be represented as accurate healthy totals."""
    from app.api.routes import health

    class BrokenMetricsDB:
        def execute(self, *_args, **_kwargs):
            return None

        def query(self, *_args, **_kwargs):
            raise RuntimeError("diagnostic-secret-canary")

    monkeypatch.setattr(health, "missing_scan_storage_tables", lambda _db: frozenset())
    result = health._build_telemetry_report(BrokenMetricsDB())
    assert result.status == "degraded"
    assert result.metrics.total_scans == 0
    assert "diagnostic-secret-canary" not in result.model_dump_json()


def test_detailed_telemetry_reports_unapplied_migrations(monkeypatch):
    from app.api.routes import health

    class HealthyDatabase:
        def execute(self, *_args, **_kwargs):
            return None

        def query(self, *_args, **_kwargs):
            raise RuntimeError("unapplied tables")

    monkeypatch.setattr(
        health, "missing_scan_storage_tables",
        lambda _db: frozenset({"findings"}),
    )
    result = health._build_telemetry_report(HealthyDatabase())
    assert result.database == "migration_required"
    assert result.status == "degraded"
