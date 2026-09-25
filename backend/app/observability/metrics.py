"""Optional low-cardinality OpenTelemetry metrics.

SQL/domain records remain the authority for SLO evaluation. This module only
projects explicitly catalogued observations to an optional OTLP exporter.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import math
import os
from types import MappingProxyType
from typing import Any, Mapping

from app.llm.types import LLMProvider
from app.execution.types import DomainOutcome, WorkKind

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class MetricDefinition:
    name: str
    unit: str
    kind: str
    allowed_attributes: Mapping[str, frozenset[object]]


_PROVIDERS = frozenset(provider.value for provider in LLMProvider)
_WORK_KINDS = frozenset(kind.value for kind in WorkKind)
_OUTCOMES = frozenset(outcome.value for outcome in DomainOutcome)
_EVENTS = frozenset({"queued", "started", "completed", "attempt_failed"})
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "UNKNOWN"})
_STATUS_CLASSES = frozenset({"1xx", "2xx", "3xx", "4xx", "5xx", "unknown"})
_WORK_STATES = frozenset({
    "QUEUED", "ADMITTED", "READY", "RETRY_WAIT", "LEASED", "RUNNING",
    "SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT",
})
_OUTBOX_STATES = frozenset({"PENDING", "PROCESSING", "PUBLISHED", "FAILED"})
_RECONCILIATION_STATES = frozenset({"PENDING", "RUNNING", "COMPLETED", "FAILED", "EXPIRED"})

METRIC_CATALOG_VERSION = "repolens-metric-catalog/1.0"
METRIC_CATALOG: Mapping[str, MetricDefinition] = MappingProxyType({
    "gen_ai.client.operation.duration": MetricDefinition(
        "gen_ai.client.operation.duration", "s", "histogram",
        MappingProxyType({"gen_ai.provider.name": _PROVIDERS}),
    ),
    "gen_ai.client.token.usage": MetricDefinition(
        "gen_ai.client.token.usage", "{token}", "histogram",
        MappingProxyType({
            "gen_ai.provider.name": _PROVIDERS,
            "gen_ai.token.type": frozenset({"input", "output"}),
        }),
    ),
    "http.server.request.duration": MetricDefinition(
        "http.server.request.duration", "s", "histogram",
        MappingProxyType({
            "http.request.method": _HTTP_METHODS,
            "http.response.status_class": _STATUS_CLASSES,
        }),
    ),
    "repolens.work.events": MetricDefinition(
        "repolens.work.events", "{event}", "counter",
        MappingProxyType({
            "repolens.work.kind": _WORK_KINDS,
            "repolens.work.event": _EVENTS,
        }),
    ),
    "repolens.work.queue_wait": MetricDefinition(
        "repolens.work.queue_wait", "s", "histogram",
        MappingProxyType({"repolens.work.kind": _WORK_KINDS}),
    ),
    "repolens.work.duration": MetricDefinition(
        "repolens.work.duration", "s", "histogram",
        MappingProxyType({
            "repolens.work.kind": _WORK_KINDS,
            "repolens.work.outcome": _OUTCOMES,
        }),
    ),
    "repolens.work.items.sql_snapshot": MetricDefinition(
        "repolens.work.items.sql_snapshot", "{item}", "gauge",
        MappingProxyType({
            "repolens.work.kind": _WORK_KINDS,
            "repolens.work.state": _WORK_STATES,
        }),
    ),
    "repolens.outbox.items.sql_snapshot": MetricDefinition(
        "repolens.outbox.items.sql_snapshot", "{item}", "gauge",
        MappingProxyType({"repolens.outbox.state": _OUTBOX_STATES}),
    ),
    "repolens.reconciliation.items.sql_snapshot": MetricDefinition(
        "repolens.reconciliation.items.sql_snapshot", "{item}", "gauge",
        MappingProxyType({"repolens.reconciliation.state": _RECONCILIATION_STATES}),
    ),
    "repolens.provider.attempts": MetricDefinition(
        "repolens.provider.attempts", "{attempt}", "counter",
        MappingProxyType({
            "gen_ai.provider.name": _PROVIDERS,
            "repolens.provider.success": frozenset({True, False}),
        }),
    ),
})


_SQL_BINDINGS: Mapping[str, tuple[str, str]] = MappingProxyType({
    "provider.latency": ("gen_ai.client.operation.duration", "provider_latency"),
    "provider.input_tokens": ("gen_ai.client.token.usage", "provider_input_tokens"),
    "provider.output_tokens": ("gen_ai.client.token.usage", "provider_output_tokens"),
    "provider.calls": ("repolens.provider.attempts", "provider_attempt"),
    "job.queued": ("repolens.work.events", "work_queued"),
    "job.started": ("repolens.work.events", "work_started"),
    "job.completed": ("repolens.work.events", "work_completed"),
    "job.attempt_failed": ("repolens.work.events", "work_attempt_failed"),
    "job.queue_wait": ("repolens.work.queue_wait", "queue_wait"),
    "job.stage_duration": ("repolens.work.duration", "work_duration"),
})

_configured = False
_enabled = False
_provider: Any = None
_meter: Any = None
_instruments: dict[str, Any] = {}
_gauge_values: dict[str, dict[tuple[tuple[str, object], ...], tuple[float, dict[str, object]]]] = {}


def configure_metrics(settings: Any | None = None, *, meter_provider: Any | None = None) -> bool:
    """Configure optional OTLP metric export without making startup depend on it."""
    global _configured, _enabled, _provider, _meter
    if _configured:
        return _enabled
    _configured = True
    if meter_provider is not None:
        try:
            _provider = meter_provider
            _meter = meter_provider.get_meter("repolens", "1")
            _enabled = True
        except Exception:
            _provider = None
            _meter = None
        return _enabled

    settings = settings or _safe_settings()
    if not bool(getattr(settings, "OTEL_ENABLED", False)) or not bool(
        getattr(settings, "OTEL_METRICS_ENABLED", False)
    ):
        return False
    endpoint = str(
        getattr(settings, "OTEL_EXPORTER_OTLP_ENDPOINT", "")
        or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    ).strip()
    if not endpoint:
        logger.info("OTLP metric export is enabled but no endpoint is configured; metrics remain local no-ops.")
        return False
    try:
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

        raw_headers = str(
            getattr(settings, "OTEL_EXPORTER_OTLP_HEADERS", "")
            or os.getenv("OTEL_EXPORTER_OTLP_HEADERS", "")
        )
        headers = {
            key.strip(): value.strip()
            for part in raw_headers.split(",")
            if "=" in part
            for key, value in [part.split("=", 1)]
            if key.strip()
        }
        exporter = OTLPMetricExporter(endpoint=endpoint, headers=headers)
        reader = PeriodicExportingMetricReader(exporter)
        provider = MeterProvider(
            metric_readers=[reader],
            resource=Resource.create({
                "service.name": str(getattr(settings, "OTEL_SERVICE_NAME", "repolens"))[:128],
            }),
        )
        _provider = provider
        _meter = provider.get_meter("repolens", "1")
        _enabled = True
    except Exception:
        # SDK/exporter errors cannot affect API startup or durable work.
        logger.warning("OTLP metric exporter unavailable; durable SQL telemetry remains active.")
        _provider = None
        _meter = None
        _enabled = False
    return _enabled


def _safe_settings() -> Any:
    try:
        from app.core.config import get_settings

        return get_settings()
    except Exception:
        return type("Settings", (), {"OTEL_ENABLED": False, "OTEL_METRICS_ENABLED": False})()


def _instrument(definition: MetricDefinition) -> Any:
    existing = _instruments.get(definition.name)
    if existing is not None:
        return existing
    if _meter is None:
        return None
    if definition.kind == "counter":
        instrument = _meter.create_counter(definition.name, unit=definition.unit)
    elif definition.kind == "gauge":
        from opentelemetry.metrics import Observation

        def observe(_options: object, metric_name: str = definition.name):
            return [
                Observation(value, attributes=attributes)
                for value, attributes in _gauge_values.get(metric_name, {}).values()
            ]

        instrument = _meter.create_observable_gauge(
            definition.name,
            callbacks=[observe],
            unit=definition.unit,
        )
    else:
        instrument = _meter.create_histogram(definition.name, unit=definition.unit)
    _instruments[definition.name] = instrument
    return instrument


def record_metric(name: str, value: float, attributes: Mapping[str, object] | None = None) -> bool:
    """Record one catalogued measurement with closed, low-cardinality dimensions."""
    definition = METRIC_CATALOG.get(name)
    if not _enabled or definition is None:
        return False
    try:
        numeric = float(value)
        if not math.isfinite(numeric) or numeric < 0:
            return False
        safe: dict[str, object] = {}
        for key, allowed_values in definition.allowed_attributes.items():
            candidate = (attributes or {}).get(key)
            if candidate in allowed_values:
                safe[key] = candidate
        instrument = _instrument(definition)
        if instrument is None:
            return False
        if definition.kind == "gauge":
            return False
        if definition.kind == "counter":
            instrument.add(numeric, attributes=safe)
        else:
            instrument.record(numeric, attributes=safe)
        return True
    except Exception:
        # A broken exporter/instrument is observability loss, never a work failure.
        return False


def replace_metric_gauges(
    name: str,
    values: list[tuple[float, Mapping[str, object]]],
) -> bool:
    """Replace a complete bounded SQL snapshot used by an observable gauge."""
    definition = METRIC_CATALOG.get(name)
    if not _enabled or definition is None or definition.kind != "gauge":
        return False
    try:
        current: dict[tuple[tuple[str, object], ...], tuple[float, dict[str, object]]] = {}
        for raw_value, raw_attributes in values:
            value = float(raw_value)
            if not math.isfinite(value) or value < 0:
                return False
            attributes: dict[str, object] = {}
            valid_dimensions = True
            for key, allowed_values in definition.allowed_attributes.items():
                candidate = raw_attributes.get(key)
                if candidate in allowed_values:
                    attributes[key] = candidate
                else:
                    valid_dimensions = False
            if not valid_dimensions:
                continue
            identity = tuple(sorted(attributes.items()))
            current[identity] = (value, attributes)
        # Catalog cardinality is fixed by enum dimensions; keep an additional
        # defensive ceiling in case a future schema accidentally widens it.
        if len(current) > 128:
            return False
        _gauge_values[name] = current
        _instrument(definition)
        return True
    except Exception:
        return False


def emit_sql_metric(
    source_name: str,
    value: float,
    unit: str,
    dimensions: Mapping[str, object] | None,
) -> bool:
    """Project a known SQL telemetry event to its registered OTEL instrument."""
    binding = _SQL_BINDINGS.get(source_name)
    if binding is None:
        return False
    metric_name, binding_kind = binding
    dims = dimensions or {}
    provider = dims.get("provider")
    work_kind = dims.get("work_kind")
    if binding_kind == "provider_latency" and unit == "milliseconds":
        return record_metric(
            metric_name, value / 1000.0,
            {"gen_ai.provider.name": provider},
        )
    if binding_kind in {"provider_input_tokens", "provider_output_tokens"} and unit == "tokens":
        return record_metric(
            metric_name, value,
            {
                "gen_ai.provider.name": provider,
                "gen_ai.token.type": "input" if binding_kind == "provider_input_tokens" else "output",
            },
        )
    if binding_kind == "provider_attempt":
        return record_metric(
            metric_name, value,
            {"gen_ai.provider.name": provider, "repolens.provider.success": dims.get("success")},
        )
    event = {
        "work_queued": "queued",
        "work_started": "started",
        "work_completed": "completed",
        "work_attempt_failed": "attempt_failed",
    }.get(binding_kind)
    if event is not None:
        return record_metric(
            metric_name, value,
            {"repolens.work.kind": work_kind, "repolens.work.event": event},
        )
    if binding_kind == "queue_wait" and unit == "seconds":
        return record_metric(metric_name, value, {"repolens.work.kind": work_kind})
    if binding_kind == "work_duration" and unit == "seconds":
        return record_metric(
            metric_name, value,
            {"repolens.work.kind": work_kind, "repolens.work.outcome": dims.get("outcome")},
        )
    return False


def shutdown_metrics() -> None:
    global _configured, _enabled, _provider, _meter
    provider, _provider = _provider, None
    _meter = None
    _instruments.clear()
    _gauge_values.clear()
    _configured = False
    _enabled = False
    if provider is not None:
        try:
            provider.shutdown()
        except Exception:
            logger.warning("OpenTelemetry metric shutdown failed; ignoring exporter error.")


def metrics_enabled() -> bool:
    """Whether this process has an optional OTel meter provider configured."""
    return _enabled


__all__ = [
    "METRIC_CATALOG",
    "METRIC_CATALOG_VERSION",
    "MetricDefinition",
    "configure_metrics",
    "emit_sql_metric",
    "metrics_enabled",
    "record_metric",
    "replace_metric_gauges",
    "shutdown_metrics",
]
