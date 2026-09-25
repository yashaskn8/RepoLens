# RepoLens Agent Operations and SLOs

RepoLens exposes an operator control plane over its existing durable work,
provider, tool, GitHub App, outbox, reconciliation, and checkpoint authorities.
It is a read-only view: the SLO evaluator does not change routing, circuit
breakers, queue state, GitHub authorization, or execution policy.

## Probes and access

- `GET /health/live` is process-only and does not query databases or providers.
- `GET /health/ready` checks application SQL/schema and the configured graph
  checkpointer. It does not call an LLM. Public output is only `ready` or
  `not_ready`.
- `GET /api/v1/operations/overview` and `GET /api/v1/operations/slo` require an
  authenticated operator session. Existing detailed `/health/detailed` and
  `/health/telemetry` routes are operator-only as well.

The operations overview is bounded and content-minimized. It reports counts,
ages, bounded configured/recent model inventories, canonical tool inventory,
and state groups; it does not expose tenant/resource IDs, prompts, source,
credentials, or host paths. Tool health intentionally says
`NOT_PROBED_READ_ONLY_INVENTORY_ONLY`: there is no durable per-tool health
authority today, and this view does not create one.

## SQL-authoritative SLO view

The SLO endpoint accepts only fixed windows (`5m`, `1h`, `6h`, `24h`, `7d`). It
derives these service indicators from durable records:

- `work_reliability`: succeeded durable work over succeeded + failed + timed
  out work. User-cancelled work is excluded; invalid/policy-blocked requests
  that never became work rows are outside the denominator. Persisted terminal
  failures classified as `USER` are also excluded.
- `github_automation_reliability`: the same classification for GitHub delivery
  and approved review-publication work kinds.
- `provider_reliability`: successful provider attempts over immutable
  `AIExecutionModel` attempts. A failed provider attempt remains a dependency
  failure even when a later fallback makes the overall work successful.

`SUCCEEDED` work is reliable even with a `DEGRADED` domain outcome, because
bounded fallback can still complete the requested work truthfully. SLO
classification is versioned separately from the domain states. Zero eligible
events produce `NO_DATA`, never 100% success. Low-traffic failures are reported
as their own signals instead of being hidden by a large denominator.

No production objectives are assumed. Defaults are `OBSERVE` mode, no
objectives, and therefore measurements without an implicit pass/fail target.
An operator may explicitly configure `AGENT_SLO_OBJECTIVES` (JSON object keyed
by `work_reliability`, `github_automation_reliability`, and/or
`provider_reliability`). Values must be in `[0, 1)`; an objective of 1 is not
valid for error-budget burn math. `AGENT_SLO_MODE=ENFORCED` is rejected unless
at least one explicit objective is configured. “Enforced” means objective
comparisons are active in the report; it does not mutate admission, routing,
provider health, or send pages. A burn-rate threshold is independently
configured with `AGENT_SLO_BURN_RATE_THRESHOLD`; absent threshold/sample
coverage yields an unknown multi-window trigger, not a false clear.

The report includes common `5m/1h` and `1h/6h` burn-rate pairs, bounded recent
latency samples (maximum 2,000 values per distribution), and truncation
indicators. Percentiles are descriptive nearest-rank estimates over the most
recent bounded sample. SQL aggregates and domain rows—not trace spans or OTLP
metrics—are the source of SLO truth. The query windows are closed and work
lifecycle timestamps are indexed by the accompanying migration.

## Metrics and failure handling

`TelemetryRecorder` remains the central SQL telemetry writer. Its optional
OpenTelemetry projection uses a closed catalog (`repolens-metric-catalog/1.0`)
and strict low-cardinality dimensions. SQL-snapshot observable gauges are
refreshed when the operator overview is read; they are not a separate durable
queue authority. Unknown metric names and unregistered
dimension values are not exported. It never exports tenant, request, work,
attempt, repository, path, prompt, or source identifiers.

OTLP metrics are opt-in with `OTEL_ENABLED=true`,
`OTEL_METRICS_ENABLED=true`, and an `OTEL_EXPORTER_OTLP_ENDPOINT`. The SDK and
HTTP exporter remain optional extras. Missing SDK/exporter or export failure
must not fail application startup or work. OTEL metrics are diagnostic only;
they are not used to calculate SLOs. Provider duration uses
`gen_ai.client.operation.duration` in seconds. Provider token usage uses
`gen_ai.client.token.usage` only for adapter-reported values. Missing token
usage is omitted (`NOT_MEASURED`), never recorded as zero.

The overview's 24-hour input/output token totals include only attempts with
provider-reported values and expose a separate measurement count; a missing
count is not interpreted as zero usage. Monetary cost is currently
`NOT_MEASURED` because no canonical provider-pricing ledger exists.

## Operator runbook

1. Check `/health/live` to distinguish a process failure from dependency
   readiness. A live process may correctly be unready.
2. Check `/health/ready`; investigate database/schema or checkpointer setup
   through deployment tooling if it is `not_ready`. This probe intentionally
   does not contact model providers.
3. Review `/api/v1/operations/overview` for queue state, expired leases,
   provider circuits, GitHub webhook state, outbox/reconciliation leases, and
   checkpoint status. Resolve expired durable state through the existing
   worker/reconciliation authorities; do not edit rows manually.
4. Review `/api/v1/operations/slo?window=24h` and compare configured objective
   status, sample count, low-traffic signals, burn windows, latency truncation,
   and invariant observations. `NO_DATA` and `INSUFFICIENT_SAMPLE` are not
   healthy SLO decisions.
5. Provider circuit state remains owned by `ProviderHealthRegistry`; never
   change it based on a derived SLO report. Review failure records and provider
   provenance, then use existing operational policy controls if an operator
   action is needed.

There is no pager transport in this feature. Integrations should consume
operator-authorized reports only after targets and alert thresholds have been
reviewed for the deployment.
