"""Content-free tracing and durable propagation contract tests."""

from __future__ import annotations

import pytest

from app.observability.semantic import safe_attributes
from app.observability import tracing
from app.observability.tracing import (
    configure_tracing,
    extract_trace_context,
    shutdown_tracing,
    span,
)


def test_malformed_w3c_context_fails_closed() -> None:
    assert extract_trace_context({"traceparent": "not-a-trace"}) == {}
    valid = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
    assert extract_trace_context({"traceparent": valid, "tracestate": "x" * 800}) == {"traceparent": valid}
    assert extract_trace_context({"traceparent": "00-" + "0" * 32 + "-" + "b" * 16 + "-01"}) == {}
    assert extract_trace_context({"traceparent": valid, "tracestate": "vendor=value"}) == {
        "traceparent": valid,
        "tracestate": "vendor=value",
    }
    assert extract_trace_context({"traceparent": valid, "tracestate": "vendor=value, other=ok"}) == {
        "traceparent": valid,
        "tracestate": "vendor=value,other=ok",
    }


def test_attributes_drop_content_and_redact_secrets() -> None:
    attrs = safe_attributes({
        "prompt": "private source",
        "raw_result": {"secret": "value"},
        "gen_ai.usage.input_tokens": 12,
        "error.type": "Bearer abcdefghijklmnop",
        "gen_ai.provider.name": "gemini",
        "unexpected": "repository source must not be attached",
    })
    assert "prompt" not in attrs
    assert "raw_result" not in attrs
    assert attrs["gen_ai.usage.input_tokens"] == 12
    assert "Bearer" not in attrs["error.type"] or "[REDACTED]" in attrs["error.type"]
    assert attrs["gen_ai.provider.name"] == "gemini"
    assert "unexpected" not in attrs


@pytest.fixture
def sdk_exporter(monkeypatch: pytest.MonkeyPatch):
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(tracing, "_configured", True)
    monkeypatch.setattr(tracing, "_enabled", True)
    monkeypatch.setattr(tracing, "_provider", provider)
    monkeypatch.setattr(tracing, "_tracer", provider.get_tracer("repolens-test", "1"))
    yield exporter
    provider.shutdown()


def test_real_sdk_exports_content_free_standard_spans(sdk_exporter) -> None:
    from opentelemetry.trace import SpanKind

    with span(
        "chat",
        kind=SpanKind.CLIENT,
        attributes={
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": "test-provider",
            "gen_ai.request.model": "test-model",
            "repolens.prompt.version": "observability-test/1",
            "gen_ai.usage.input_tokens": 10,
            "repolens.test.digest": "abc",
            "repolens.test.prompt": "must not export",
        },
    ) as current:
        current.set_attribute("repolens.test.output_tokens", 4)
        current.set_attribute("repolens.test.source", "must not export")
    spans = sdk_exporter.get_finished_spans()
    assert len(spans) == 1
    exported = spans[0]
    assert exported.kind is SpanKind.CLIENT
    assert exported.attributes["gen_ai.operation.name"] == "chat"
    assert exported.attributes["gen_ai.provider.name"] == "test-provider"
    assert exported.attributes["repolens.prompt.version"] == "observability-test/1"
    assert exported.attributes["gen_ai.usage.input_tokens"] == 10
    assert exported.attributes["repolens.test.output_tokens"] == 4
    assert "repolens.test.prompt" not in exported.attributes
    assert "repolens.test.source" not in exported.attributes


def test_real_sdk_parent_context_round_trip(sdk_exporter) -> None:
    with span("parent"):
        parent_headers = tracing.current_trace_headers()
    assert parent_headers["traceparent"].startswith("00-")
    with span("child", parent_headers=parent_headers):
        pass
    spans = {item.name: item for item in sdk_exporter.get_finished_spans()}
    assert spans["child"].context.trace_id == spans["parent"].context.trace_id
    assert spans["child"].parent.span_id == int(parent_headers["traceparent"].split("-")[2], 16)


def test_rejected_tool_request_does_not_emit_execution_span(sdk_exporter) -> None:
    from app.agent_tools.registry import AgentToolRegistry

    registry = AgentToolRegistry.__new__(AgentToolRegistry)
    registry._specs = {}
    result = registry.invoke("run_shell", {})
    assert result.errors[0].code == "UNKNOWN_TOOL"
    assert sdk_exporter.get_finished_spans() == ()


def test_configure_shutdown_reconfigure_has_no_provider_override(caplog) -> None:
    shutdown_tracing()
    settings = type("Settings", (), {"OTEL_ENABLED": True, "OTEL_SERVICE_NAME": "test", "OTEL_SAMPLE_RATIO": 1.0, "OTEL_EXPORTER_OTLP_ENDPOINT": ""})()
    assert configure_tracing(settings) is True
    shutdown_tracing()
    assert "Overriding of current TracerProvider is not allowed" not in caplog.text
    assert configure_tracing(type("Settings", (), {"OTEL_ENABLED": False})()) is False


def test_disabled_tracing_is_idempotent_and_non_failing() -> None:
    shutdown_tracing()
    settings = type("Settings", (), {"OTEL_ENABLED": False})()
    assert configure_tracing(settings) is False
    assert configure_tracing(settings) is False
    with span("test", attributes={"prompt": "must not be recorded"}):
        pass
    shutdown_tracing()
