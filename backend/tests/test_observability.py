"""Content-free tracing and durable propagation contract tests."""

from __future__ import annotations

from app.observability.semantic import safe_attributes
from app.observability.tracing import (
    configure_tracing,
    extract_trace_context,
    shutdown_tracing,
    span,
)


def test_malformed_w3c_context_fails_closed() -> None:
    assert extract_trace_context({"traceparent": "not-a-trace"}) == {}
    assert extract_trace_context({"traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01", "tracestate": "x" * 800})[
        "tracestate"
    ] == "x" * 512


def test_attributes_drop_content_and_redact_secrets() -> None:
    attrs = safe_attributes({
        "prompt": "private source",
        "raw_result": {"secret": "value"},
        "input_tokens": 12,
        "error_type": "Bearer abcdefghijklmnop",
        "provider": "gemini",
        "unexpected": "repository source must not be attached",
    })
    assert "prompt" not in attrs
    assert "raw_result" not in attrs
    assert attrs["input_tokens"] == 12
    assert "Bearer" not in attrs["error_type"] or "[REDACTED]" in attrs["error_type"]
    assert attrs["provider"] == "gemini"
    assert "unexpected" not in attrs


def test_disabled_tracing_is_idempotent_and_non_failing() -> None:
    shutdown_tracing()
    settings = type("Settings", (), {"OTEL_ENABLED": False})()
    assert configure_tracing(settings) is False
    assert configure_tracing(settings) is False
    with span("test", attributes={"prompt": "must not be recorded"}):
        pass
    shutdown_tracing()
