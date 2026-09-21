"""Optional OpenTelemetry tracing with a strict content-free policy.

The application remains fully functional when the optional OTel packages are not
installed or tracing is disabled. Trace failures are deliberately swallowed at
this boundary and never become domain failures.
"""

from __future__ import annotations

from contextlib import contextmanager
import logging
import os
import re
import sys
from typing import Any, Iterator, Mapping

from .semantic import safe_attributes

logger = logging.getLogger(__name__)

_TRACEPARENT = re.compile(r"^00-[0-9a-fA-F]{32}-[0-9a-fA-F]{16}-[0-9a-fA-F]{2}$")
_TRACESTATE_MAX = 512
_configured = False
_enabled = False
_tracer = None
_provider = None


class _NoopSpan:
    def __enter__(self) -> "_NoopSpan":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def set_attribute(self, *_: object, **__: object) -> None:
        return None

    def add_event(self, *_: object, **__: object) -> None:
        return None

    def record_exception(self, *_: object, **__: object) -> None:
        return None

    def set_status(self, *_: object, **__: object) -> None:
        return None


def configure_tracing(settings: Any | None = None) -> bool:
    """Initialize the optional SDK once. Returns whether tracing is active."""
    global _configured, _enabled, _tracer, _provider
    if _configured:
        return _enabled
    _configured = True
    settings = settings or _safe_settings()
    if not bool(getattr(settings, "OTEL_ENABLED", False)):
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

        provider = TracerProvider(
            resource=Resource.create({"service.name": str(getattr(settings, "OTEL_SERVICE_NAME", "repolens"))[:128]}),
            sampler=TraceIdRatioBased(float(getattr(settings, "OTEL_SAMPLE_RATIO", 1.0))),
        )
        endpoint = str(getattr(settings, "OTEL_EXPORTER_OTLP_ENDPOINT", "") or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", ""))
        if endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

                # Headers are passed to the exporter only and are never logged,
                # persisted, or attached as span attributes.
                raw_headers = str(getattr(settings, "OTEL_EXPORTER_OTLP_HEADERS", "") or os.getenv("OTEL_EXPORTER_OTLP_HEADERS", ""))
                headers = {
                    part.split("=", 1)[0].strip(): part.split("=", 1)[1].strip()
                    for part in raw_headers.split(",")
                    if "=" in part and part.split("=", 1)[0].strip()
                }
                provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, headers=headers)))
            except Exception:
                logger.warning("OTLP exporter unavailable; tracing remains active without an exporter.")
        trace.set_tracer_provider(provider)
        _provider = provider
        _tracer = trace.get_tracer("repolens", "1")
        _enabled = True
    except Exception:
        # Missing optional SDK or exporter must never stop RepoLens startup.
        logger.info("OpenTelemetry SDK unavailable; using no-op tracing.")
        _enabled = False
    return _enabled


def _safe_settings() -> Any:
    try:
        from app.core.config import get_settings

        return get_settings()
    except Exception:
        return type("Settings", (), {"OTEL_ENABLED": False})()


def _valid_traceparent(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _TRACEPARENT.fullmatch(value) else None


def extract_trace_context(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Extract only valid W3C headers; malformed values fail closed."""
    headers = headers or {}
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    traceparent = _valid_traceparent(lowered.get("traceparent"))
    if traceparent is None:
        return {}
    tracestate = lowered.get("tracestate", "").strip()[:_TRACESTATE_MAX]
    return {"traceparent": traceparent, **({"tracestate": tracestate} if tracestate else {})}


def inject_trace_context() -> dict[str, str]:
    """Inject the current context into bounded durable work metadata."""
    if not _enabled:
        return {}
    try:
        from opentelemetry.propagate import inject

        carrier: dict[str, str] = {}
        inject(carrier)
        return extract_trace_context(carrier)
    except Exception:
        return {}


def current_trace_headers() -> dict[str, str]:
    return inject_trace_context()


@contextmanager
def span(name: str, *, attributes: Mapping[str, Any] | None = None, parent_headers: Mapping[str, str] | None = None) -> Iterator[Any]:
    """Start a safe span; tracing exceptions are non-domain failures."""
    if not _enabled or _tracer is None:
        yield _NoopSpan()
        return
    token = None
    span_context_manager = None
    try:
        from opentelemetry import context, propagate, trace

        if parent_headers:
            ctx = propagate.extract(dict(extract_trace_context(parent_headers)))
            token = context.attach(ctx)
        span_context_manager = _tracer.start_as_current_span(name)
        active = span_context_manager.__enter__()
        for key, value in safe_attributes(attributes).items():
            active.set_attribute(key, value)
    except Exception:
        # Do not let an exporter/provider issue alter application behavior.
        if span_context_manager is not None:
            try:
                span_context_manager.__exit__(*sys.exc_info())
            except Exception:
                pass
        yield _NoopSpan()
        if token is not None:
            try:
                context.detach(token)
            except Exception:
                pass
        return
    try:
        yield active
    except BaseException:
        span_context_manager.__exit__(*sys.exc_info())
        raise
    else:
        span_context_manager.__exit__(None, None, None)
    finally:
        if token is not None:
            try:
                from opentelemetry import context

                context.detach(token)
            except Exception:
                pass


def span_event(name: str, attributes: Mapping[str, Any] | None = None) -> None:
    if not _enabled:
        return
    try:
        from opentelemetry import trace

        active = trace.get_current_span()
        if active is not None:
            active.add_event(name, attributes=safe_attributes(attributes))
    except Exception:
        return


def shutdown_tracing() -> None:
    global _configured, _enabled, _tracer, _provider
    provider, _provider = _provider, None
    _tracer = None
    _enabled = False
    _configured = False
    if provider is not None:
        try:
            provider.shutdown()
        except Exception:
            logger.warning("OpenTelemetry shutdown failed; ignoring exporter error.")


__all__ = [
    "configure_tracing", "current_trace_headers", "extract_trace_context",
    "inject_trace_context", "shutdown_tracing", "span", "span_event",
]
