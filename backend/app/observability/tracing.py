"""Optional OpenTelemetry tracing with a strict content-free policy.

The application remains fully functional when the optional OTel packages are not
installed or tracing is disabled. Trace failures are deliberately swallowed at
this boundary and never become domain failures.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import logging
import os
import re
from typing import Any, Iterator, Mapping

from .semantic import safe_attributes

logger = logging.getLogger(__name__)

_TRACEPARENT = re.compile(r"^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-([0-9a-fA-F]{2})$")
_TRACESTATE_KEY = re.compile(r"^[a-z0-9][a-z0-9_*/-]{0,255}(?:@[a-z0-9][a-z0-9_*/-]{0,255})?$")
_TRACESTATE_VALUE = re.compile(r"^[\x21-\x2b\x2d-\x3c\x3e-\x7e]{0,256}$")
_TRACESTATE_MAX = 512
_configured = False
_enabled = False
_tracer = None
_provider = None

# The MCP SDK creates the authoritative server-side execute-tool span.  An
# in-process protocol bridge sets this flag while it delegates to the
# canonical AgentToolRegistry so the registry does not emit a duplicate
# semantic execute_tool span for the same operation.
_mcp_server_tool_span_active: ContextVar[bool] = ContextVar(
    "repolens_mcp_server_tool_span_active", default=False
)


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


class _SafeSpan:
    """Small facade that applies the content-free policy to post-start updates."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def set_attribute(self, key: str, value: Any) -> None:
        for safe_key, safe_value in safe_attributes({key: value}).items():
            self._inner.set_attribute(safe_key, safe_value)

    def add_event(self, name: str, attributes: Mapping[str, Any] | None = None, **kwargs: Any) -> None:
        self._inner.add_event(name, attributes=safe_attributes(attributes), **kwargs)

    def record_exception(self, exception: BaseException, **kwargs: Any) -> None:
        # Exception messages and tracebacks may contain source or secrets.  The
        # span exception policy is represented by a bounded type attribute.
        self.set_attribute("error.type", type(exception).__name__)

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        self._inner.set_status(*args, **kwargs)


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
        # The OTel API permits installing the process-wide provider only once.
        # Test clients and worker lifecycles may call this function again after
        # shutdown, so use a fresh provider directly without attempting to
        # overwrite an already-installed global provider.
        current_provider = trace.get_tracer_provider()
        if current_provider.__class__.__name__ == "ProxyTracerProvider":
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
    match = _TRACEPARENT.fullmatch(value)
    if match is None:
        return None
    trace_id, parent_id, _flags = match.groups()
    if trace_id.lower() == "0" * 32 or parent_id.lower() == "0" * 16:
        return None
    return value.lower()


def _valid_tracestate(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        if len(value.encode("ascii")) > _TRACESTATE_MAX:
            return None
    except UnicodeEncodeError:
        return None
    members = [member.strip() for member in value.split(",")]
    if not members or len(members) > 32 or any(not member for member in members):
        return None
    seen: set[str] = set()
    for member in members:
        if member.count("=") != 1:
            return None
        key, member_value = member.split("=", 1)
        if key != key.strip() or member_value != member_value.strip():
            return None
        if len(key) > 256 or not _TRACESTATE_KEY.fullmatch(key) or not _TRACESTATE_VALUE.fullmatch(member_value):
            return None
        key = key.lower()
        if key in seen:
            return None
        seen.add(key)
    return ",".join(members)


def extract_trace_context(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Extract only valid W3C headers; malformed values fail closed."""
    headers = headers or {}
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    traceparent = _valid_traceparent(lowered.get("traceparent"))
    if traceparent is None:
        return {}
    tracestate = _valid_tracestate(lowered.get("tracestate"))
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
def mcp_server_tool_span_active() -> Iterator[None]:
    """Suppress duplicate AgentToolRegistry execute spans for MCP calls."""
    token = _mcp_server_tool_span_active.set(True)
    try:
        yield
    finally:
        _mcp_server_tool_span_active.reset(token)


def is_mcp_server_tool_span_active() -> bool:
    return _mcp_server_tool_span_active.get()


@contextmanager
def span(
    name: str,
    *,
    attributes: Mapping[str, Any] | None = None,
    parent_headers: Mapping[str, str] | None = None,
    kind: Any | None = None,
) -> Iterator[Any]:
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
        if kind is None:
            span_context_manager = _tracer.start_as_current_span(name)
        else:
            span_context_manager = _tracer.start_as_current_span(name, kind=kind)
        active = span_context_manager.__enter__()
        for key, value in safe_attributes(attributes).items():
            active.set_attribute(key, value)
    except Exception:
        # Do not let an exporter/provider issue alter application behavior.
        if span_context_manager is not None:
            try:
                span_context_manager.__exit__(None, None, None)
            except Exception:
                pass
        yield _NoopSpan()
        if token is not None:
            try:
                context.detach(token)
            except Exception:
                pass
        return
    safe_active = _SafeSpan(active)
    try:
        yield safe_active
    except BaseException as exc:
        # Keep exception telemetry content-free; the domain exception is still
        # re-raised to the caller unchanged.
        safe_active.set_attribute("error.type", type(exc).__name__)
        span_context_manager.__exit__(None, None, None)
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
    "mcp_server_tool_span_active", "is_mcp_server_tool_span_active",
]
