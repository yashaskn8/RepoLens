# RepoLens Agent Observability

RepoLens tracing is an optional, vendor-neutral distributed-causality layer. It
does not replace durable workflow events, SQL telemetry metrics, LangGraph
checkpoints, or model execution metadata:

* **Events** are the audit/operational record and remain the source of truth for
  business transitions.
* **Metrics** are aggregate measurements persisted through the existing
  telemetry recorder.
* **Traces** connect an HTTP request, durable work attempt, workflow, model
  route, retrieval, and deterministic tool invocation across process boundaries.

Tracing is disabled by default. Enable it with `OTEL_ENABLED=true`, set a
bounded `OTEL_SAMPLE_RATIO`, and optionally configure
`OTEL_EXPORTER_OTLP_ENDPOINT` and exporter-only `OTEL_EXPORTER_OTLP_HEADERS`.
The optional `observability` dependency installs the OpenTelemetry SDK and OTLP
HTTP exporter. Any OTLP-compatible collector can be used, including Tempo,
Jaeger, or an operator-managed Langfuse OTLP endpoint. RepoLens does not add a
Langfuse SDK or make a hosted observability service a runtime dependency.

## Propagation and durability

The HTTP boundary extracts a valid W3C `traceparent`/`tracestate` pair and starts
one controlled HTTP SERVER span while preserving the existing request ID,
security headers, timing, and durable request metric behavior. New durable work
items persist only bounded nullable propagation fields in
`execution_work_items`; these fields are not part of `request_payload`, request
digests, or idempotency identity. A reused idempotent work item retains its
original parent. Each leased attempt starts its own span and restores the
persisted parent, so retries and crash recovery remain distinguishable.
Malformed or oversized propagation is rejected rather than truncated; all-zero
W3C IDs are rejected. The SDK provider is installed at most once per process,
and shutdown is best-effort so exporter failures cannot affect domain work.

## Privacy contract

Trace attributes are passed through one central scalar/bounded helper. Prompts,
messages, model responses, source text, raw tool arguments/results, retrieval
queries/chunks/vectors, cookies, authorization values, API keys, secrets,
stack traces, and absolute host paths are never attached to spans. Safe
metadata is limited to versions, digests, provider/model IDs, operation names,
bounded statuses, durations, token counts, evidence counts, and budget state.
GenAI attributes use the OpenTelemetry `gen_ai.*` namespace; RepoLens-specific
metadata uses `repolens.*`.
Exporter headers are used only by the exporter and are never logged or
persisted. Trace/exporter failures are non-domain failures and do not trigger a
workflow retry.

## Instrumented boundaries

The current implementation covers the HTTP request, durable work attempt,
LangGraph workflow and node transitions, Evidence Investigator plan steps,
canonical `AgentToolRegistry.invoke`, `LLMRouter.generate` (including safe
provider attempt/failure events), and `RetrievalService.retrieve`. Context
packing remains content-free and reports bounded byte/token/evidence/tool
counts. Existing workflow events and model execution metadata remain intact.

## Limitations

Tracing is intentionally diagnostic rather than an authorization boundary.
The existing allowlists, Pydantic validation, path confinement, budgets,
redaction, verifier, HITL boundary, and checkpoint authority remain canonical.
If the optional SDK is absent, tracing is a no-op. Live collector delivery is
not required for zero-key CI and is not part of deterministic analysis
correctness.
