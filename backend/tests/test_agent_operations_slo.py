"""SQL-authoritative SLO and optional low-cardinality metric contracts."""

from datetime import datetime, timedelta, timezone
import hashlib
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.execution.types import DomainOutcome, WorkKind
from app.models.ai_execution import AIExecutionModel
from app.models.execution import FailureRecordModel, WorkItemModel
from app.llm.execution import measured_provider_token_observations
from app.observability.metrics import METRIC_CATALOG, emit_sql_metric, record_metric
from app.observability import metrics
from app.observability.slo import (
    SLIStatus,
    SLOMode,
    SLOPolicy,
    SLOReport,
    build_slo_report,
)


def _work(
    db,
    *,
    tenant_id: str,
    state: str,
    kind: str,
    now: datetime,
    outcome: str | None = None,
    user_failure: bool = False,
) -> None:
    identity = str(uuid4())
    item = WorkItemModel(
        tenant_id=tenant_id,
        request_id=f"request-{identity}",
        requested_by=tenant_id,
        policy_snapshot_id="policy-test",
        work_kind=kind,
        resource_type="TEST",
        resource_id=f"resource-{identity}",
        state=state,
        domain_outcome=outcome,
        idempotency_key=f"idempotency-{identity}",
        request_digest=hashlib.sha256(f"{state}-{kind}-{identity}".encode()).hexdigest(),
        request_payload={},
        side_effect_class="SAFE_RECOMPUTATION",
        resource_profile="SMALL_REPO_SCAN",
        deadline_at=now + timedelta(hours=1),
        created_at=now - timedelta(seconds=20),
        started_at=now - timedelta(seconds=10),
        terminal_at=now - timedelta(seconds=1),
    )
    db.add(item)
    if user_failure:
        db.flush()
        db.add(FailureRecordModel(
            work_item_id=item.id,
            attempt_id=None,
            code="USER_INPUT_ERROR",
            category="USER",
            stage="admission",
            retryable=False,
            infrastructure_state="FAILED",
            public_message="Invalid task input.",
            failure_metadata={},
        ))


def _provider(db, *, success: bool, created_at: datetime, sequence: int) -> None:
    db.add(AIExecutionModel(
        tenant_id=None,
        request_id=f"provider-request-{sequence}",
        sequence=1,
        provider="gemini",
        model="test-model",
        capability="REPOSITORY_ANALYSIS",
        prompt_template_version="test/1",
        prompt_digest="a" * 64,
        generation_settings={},
        request_budget={},
        estimated_input_tokens=20,
        input_tokens=None,
        output_tokens=None,
        total_tokens=None,
        latency_ms=10.0,
        validation_result="NOT_REQUESTED",
        success=success,
        routing_policy_version="test/1",
        model_registry_version="b" * 64,
        record_digest=hashlib.sha256(f"record-{sequence}".encode()).hexdigest(),
        created_at=created_at,
    ))


def test_slo_classifies_sql_work_fallback_and_provider_failure_separately(db_session) -> None:
    from app.cli.create_operator import create_or_elevate_operator

    tenant = create_or_elevate_operator(
        db_session,
        email="slo_test_operator@example.com",
        password="SloTestPass12345!",
    )
    now = datetime.now(timezone.utc)
    _work(db_session, tenant_id=tenant.id, state="SUCCEEDED", kind=WorkKind.SCAN.value, now=now, outcome=DomainOutcome.DEGRADED.value)
    _work(db_session, tenant_id=tenant.id, state="SUCCEEDED", kind=WorkKind.GITHUB_DELIVERY.value, now=now, outcome=DomainOutcome.COMPLETE.value)
    _work(db_session, tenant_id=tenant.id, state="FAILED", kind=WorkKind.SCAN.value, now=now)
    _work(db_session, tenant_id=tenant.id, state="CANCELLED", kind=WorkKind.SCAN.value, now=now)
    _provider(db_session, success=True, created_at=now - timedelta(seconds=2), sequence=1)
    _provider(db_session, success=False, created_at=now - timedelta(seconds=1), sequence=2)
    db_session.flush()

    policy = SLOPolicy(
        mode=SLOMode.ENFORCED,
        objectives={"work_reliability": 0.6, "provider_reliability": 0.9},
        minimum_samples=1,
    )
    report = build_slo_report(db_session, policy=policy, now=now)
    primary = report.windows["24h"]
    assert primary["work_reliability"].eligible_events == 3
    assert primary["work_reliability"].good_events == 2  # DEGRADED successful fallback is reliable work.
    assert primary["work_reliability"].bad_events == 1
    assert primary["work_reliability"].excluded_events == 1  # user cancellation excluded
    assert primary["provider_reliability"].good_events == 1
    assert primary["provider_reliability"].bad_events == 1  # fallback provider failure remains visible
    assert primary["work_reliability"].status == SLIStatus.OBJECTIVE_MET
    assert report.report_digest
    assert len(report.burn_rate_pairs) == 4


def test_no_samples_are_unknown_and_not_reported_as_success() -> None:
    from app.observability.slo import _sli_result

    result = _sli_result(name="work_reliability", good=0, bad=0, excluded=0, policy=SLOPolicy())
    assert result.status == SLIStatus.NO_DATA
    assert result.reliability is None
    assert result.eligible_events == 0


def test_user_input_failure_is_excluded_from_work_reliability(db_session) -> None:
    from app.cli.create_operator import create_or_elevate_operator

    tenant = create_or_elevate_operator(
        db_session,
        email="slo_user_failure@example.com",
        password="SloTestPass12345!",
    )
    now = datetime.now(timezone.utc)
    _work(
        db_session,
        tenant_id=tenant.id,
        state="FAILED",
        kind=WorkKind.SCAN.value,
        now=now,
        user_failure=True,
    )
    db_session.flush()
    result = build_slo_report(db_session, policy=SLOPolicy(), now=now).windows["24h"]["work_reliability"]
    assert result.eligible_events == 0
    assert result.excluded_events == 1
    assert result.reliability is None


def test_slo_policy_has_no_invented_default_targets_and_enforced_needs_explicit_target() -> None:
    policy = SLOPolicy.from_settings(type(
        "Settings", (), {
            "AGENT_SLO_MODE": "OBSERVE",
            "AGENT_SLO_OBJECTIVES": {},
            "AGENT_SLO_MIN_SAMPLES": 20,
            "AGENT_SLO_BURN_RATE_THRESHOLD": None,
        }
    )())
    assert policy.objectives == {}
    assert policy.mode == SLOMode.OBSERVE
    with pytest.raises(ValidationError):
        SLOPolicy(mode=SLOMode.ENFORCED)
    with pytest.raises(ValidationError):
        SLOPolicy(objectives={"work_reliability": 1.0})


def test_slo_report_rejects_tampered_digest(db_session) -> None:
    policy = SLOPolicy()
    report = build_slo_report(db_session, policy=policy)
    data = report.model_dump(mode="json")
    data["invariant_observations"]["failed_outbox_events"] += 1
    with pytest.raises(ValidationError, match="digest"):
        SLOReport.model_validate(data)


def test_metric_catalog_is_closed_and_otel_attributes_are_low_cardinality(monkeypatch) -> None:
    class Histogram:
        def __init__(self):
            self.observations = []

        def record(self, value, attributes):
            self.observations.append((value, attributes))

    class Meter:
        def __init__(self):
            self.histograms = {}

        def create_histogram(self, name, unit):
            self.histograms[name] = Histogram()
            return self.histograms[name]

        def create_counter(self, name, unit):
            self.histograms[name] = Histogram()
            return self.histograms[name]

    class Provider:
        def __init__(self):
            self.meter = Meter()

        def get_meter(self, *_):
            return self.meter

    provider = Provider()
    monkeypatch.setattr(metrics, "_configured", False)
    monkeypatch.setattr(metrics, "_enabled", False)
    monkeypatch.setattr(metrics, "_provider", None)
    monkeypatch.setattr(metrics, "_meter", None)
    monkeypatch.setattr(metrics, "_instruments", {})
    assert metrics.configure_metrics(meter_provider=provider)
    assert emit_sql_metric("provider.latency", 1500, "milliseconds", {"provider": "gemini", "model": "private/custom"})
    histogram = provider.meter.histograms["gen_ai.client.operation.duration"]
    assert histogram.observations == [(1.5, {"gen_ai.provider.name": "gemini"})]
    assert record_metric("gen_ai.client.token.usage", 30, {
        "gen_ai.provider.name": "gemini",
        "gen_ai.token.type": "input",
        "prompt": "must-not-be-an-attribute",
    })
    token_attrs = provider.meter.histograms["gen_ai.client.token.usage"].observations[0][1]
    assert token_attrs == {"gen_ai.provider.name": "gemini", "gen_ai.token.type": "input"}
    assert not record_metric("unregistered.metric", 1, {"name": "dynamic"})
    assert "gen_ai.client.operation.duration" in METRIC_CATALOG
    metrics.shutdown_metrics()


def test_metric_exporter_missing_is_non_fatal(monkeypatch) -> None:
    monkeypatch.setattr(metrics, "_configured", False)
    monkeypatch.setattr(metrics, "_enabled", False)
    monkeypatch.setattr(metrics, "_provider", None)
    monkeypatch.setattr(metrics, "_meter", None)
    settings = type("Settings", (), {
        "OTEL_ENABLED": True,
        "OTEL_METRICS_ENABLED": True,
        "OTEL_EXPORTER_OTLP_ENDPOINT": "",
    })()
    assert metrics.configure_metrics(settings) is False
    assert not metrics.record_metric("gen_ai.client.operation.duration", 1.0, {})


def test_unknown_provider_token_usage_is_not_recorded_as_zero() -> None:
    from types import SimpleNamespace

    unknown = SimpleNamespace(total_tokens=None, input_tokens=None, output_tokens=None)
    measured_zero = SimpleNamespace(total_tokens=0, input_tokens=0, output_tokens=None)
    assert measured_provider_token_observations(unknown) == ()
    assert measured_provider_token_observations(measured_zero) == (
        ("provider.tokens", 0),
        ("provider.input_tokens", 0),
    )


def test_sql_snapshot_gauges_replace_old_bounded_series(monkeypatch) -> None:
    class Meter:
        def create_observable_gauge(self, name, callbacks, unit):
            self.name = name
            self.callback = callbacks[0]
            return self

    class Provider:
        def __init__(self):
            self.meter = Meter()

        def get_meter(self, *_):
            return self.meter

    provider = Provider()
    monkeypatch.setattr(metrics, "_configured", False)
    monkeypatch.setattr(metrics, "_enabled", False)
    monkeypatch.setattr(metrics, "_provider", None)
    monkeypatch.setattr(metrics, "_meter", None)
    monkeypatch.setattr(metrics, "_instruments", {})
    monkeypatch.setattr(metrics, "_gauge_values", {})
    assert metrics.configure_metrics(meter_provider=provider)
    assert metrics.replace_metric_gauges(
        "repolens.work.items.sql_snapshot",
        [(4, {"repolens.work.kind": "SCAN", "repolens.work.state": "RUNNING"})],
    )
    first = provider.meter.callback(None)
    assert [(item.value, item.attributes) for item in first] == [(
        4,
        {"repolens.work.kind": "SCAN", "repolens.work.state": "RUNNING"},
    )]
    assert metrics.replace_metric_gauges("repolens.work.items.sql_snapshot", [])
    assert provider.meter.callback(None) == []
    assert metrics.replace_metric_gauges(
        "repolens.work.items.sql_snapshot",
        [(4, {"repolens.work.kind": "UNKNOWN", "repolens.work.state": "RUNNING"})],
    )
    assert provider.meter.callback(None) == []
    metrics.shutdown_metrics()


def test_operator_operations_endpoints_are_bounded_and_public_probes_are_minimal(client, monkeypatch) -> None:
    from app.observability import operations

    async def ready_check(_settings):
        return {"ready": True, "backend": "TEST", "state": "CONNECTED"}

    monkeypatch.setattr(operations, "check_checkpointer_readiness", ready_check)
    assert client.get("/health/live").json() == {"status": "alive"}
    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}
    overview = client.get("/api/v1/operations/overview")
    assert overview.status_code == 200
    data = overview.json()
    assert data["tools"]["authority"] == "AgentToolRegistry"
    assert data["tools"]["registered_count"] >= 1
    assert data["tools"]["runtime_health"] == "NOT_PROBED_READ_ONLY_INVENTORY_ONLY"
    assert data["providers"]["recently_used_model_limit"] == 25
    assert "tenant_id" not in overview.text
    slo = client.get("/api/v1/operations/slo?window=24h")
    assert slo.status_code == 200
    report = slo.json()
    assert report["policy"]["mode"] == "OBSERVE"
    assert report["policy"]["objectives"] == {}
    assert report["windows"]["24h"]["work_reliability"]["status"] == "NO_DATA"
    assert client.get("/api/v1/operations/slo?window=30d").status_code == 422


@pytest.mark.asyncio
async def test_missing_sqlite_checkpointer_probe_does_not_create_database(tmp_path) -> None:
    from app.observability.operations import check_checkpointer_readiness

    checkpoint_file = tmp_path / "missing-checkpoints.db"
    settings = SimpleNamespace(
        CHECKPOINT_BACKEND="SQLITE",
        CHECKPOINT_DB_FILE=str(checkpoint_file),
        is_production=False,
    )
    result = await check_checkpointer_readiness(settings)
    assert result == {"ready": False, "backend": "SQLITE", "state": "MISSING"}
    assert not checkpoint_file.exists()


def test_detailed_telemetry_and_slo_are_operator_only(client) -> None:
    client.cookies.clear()
    assert client.get("/api/v1/health/detailed").status_code == 401
    assert client.get("/api/v1/health/telemetry").status_code == 401
    assert client.get("/api/v1/operations/overview").status_code == 401
    assert client.get("/api/v1/operations/slo").status_code == 401
    assert client.get("/health/live").status_code == 200
