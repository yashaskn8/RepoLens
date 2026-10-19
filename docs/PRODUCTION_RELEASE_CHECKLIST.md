# RepoLens production release checklist

**Current decision: BLOCKED for production repository scanning.** This is a
capability assessment, not a statement about CI quality. CI checks can pass
while real deployment requirements remain unmet.

For the concrete **no-local-Docker** security implementation and acceptance
tests required to unblock acquisition, consult
[Secure Production Sandbox](SECURE_PRODUCTION_SANDBOX.md).

## What is verified in repository code

- Required CI tests Python, frontend TypeScript/lint/build, Windows reparse
  protection, and PostgreSQL/pgvector/Redis integration under ephemeral CI
  services, using locked dependencies.
- Manual production validation is a separate GitHub Actions workflow and uses
  explicitly supplied staging secrets for live runs; it does not deploy.
- Production settings require PostgreSQL, secure cookies, explicit CORS and
  trusted hosts, PostgreSQL checkpointer, and an explicitly selected artifact
  deployment mode.
- New acquisition requests in production are rejected until there is a hard
  filesystem-quota + egress enforcement boundary. External scanner execution
  in production is likewise disabled until independently isolated.
- The service readiness endpoint now returns HTTP 503 for those unsupported
  production capabilities, even when database connectivity is healthy.
- The staging smoke refuses to submit work unless /health/ready returns HTTP
  200 with status=ready. Smoke does not publish externally without an
  explicit two-control opt-in.

## Mandatory blockers to close BEFORE exposure to untrusted traffic

1. **Enforced acquisition workspace quota.** Provision a trusted host-level
   volume/filesystem or worker sandbox with OS-enforced per-job writable-byte,
   inode, process, CPU, memory and wall-clock limits. Limits must take effect
   before Git is launched, not by polling after clone writes. The enforcement
   provider must return verifiable admission evidence and fail closed when
   unavailable. Keep this separate from Git object-count and reactive
   monitoring, which are useful but not hard quotas.
2. **Network egress policy.** Ensure Git fetch can contact only the approved
   public GitHub transport endpoint, without arbitrary redirects, alternative
   protocols, user-configured proxies, internal IP/DNS resolution or access to
   cloud metadata services. Enforce this at a network/firewall/worker boundary
   rather than trusting URL validation alone.
3. **External scanners isolated from secrets and internal networks.**
   Semgrep, Trivy and OSV-Scanner must operate in an independently bounded,
   no-internal-egress worker context with read-only input and strict
   CPU/memory/process/output caps. If isolation is missing, results must remain
   UNAVAILABLE rather than reporting a clean pass.
4. **Connect capabilities to the canonical gates.** Implement and test the
   actual trusted quota/egress admission in
   `backend/app/ingestion/acquisition_boundary.py` and the independent
   scanner isolation contract in `backend/app/analysis/base.py`. Add tests for
   quota exhaustion, redirects, DNS changes, cross-job isolation, interrupted
   workers, resource cleanup and unavailable enforcement. Do **not** introduce
   a flag that simply returns true.
5. **Deployment target.** Select and provision a specific TLS-terminated host
   or supported platform, DNS, runtime OS isolation primitives, PostgreSQL,
   optional Redis, persistent artifact storage, secret manager and worker
   lifecycle. Deployment access and secrets are not stored in the repository.
6. **Live integration.** Test GitHub App callback/session behavior, webhook
   signature/replay handling, exact-head-change publication, provider outages,
   read-only operation and staged operator-approved COMMENT-only review
   publication against a sacrificial repository. Confirm branch protections and
   API permissions independently.
7. **Operational recovery.** Exercise backup/restore, migrations, rollbacks,
   secret rotation, expired-work recovery, artifact cleanup, observability
   alerts and canary rollback criteria. Run load and resource-exhaustion tests
   against a production-equivalent staging environment.

## Release procedure — no Docker installation on a developer laptop

1. Review a pinned commit on `main`, its complete CI jobs and any unresolved
   findings. The GitHub workflow is a build/test gate, **not CD deployment**.
2. Configure production secrets on a controlled host. Do not use demo/staging
   values or commit `.env` files. Install backend dependencies from
   `backend/uv.lock`, including the `production` extra.
3. Use `python -m app.cli.production_preflight` for an **imports-only**
   check. Use `python -m app.cli.production_preflight --release-gate` for
   offline mandatory-isolation checks. The latter must return zero before
   claiming release eligibility; it currently returns nonzero.
4. Apply Alembic migrations as a separately controlled deployment step.
   Verify PostgreSQL schema, checkpointer and canonical artifact-store health.
5. Deploy an immutable build through the selected platform and obtain an
   HTTP 200 `/health/ready` response. A 503 means **do not route traffic**.
6. Execute the `Manual Production Validation` GitHub workflow on `main`.
   Provide a disposable PostgreSQL test database (never live) if opting into
   schema-reset checks; supply staging secrets for optional live-provider and
   staging smoke runs. Staging smoke validates readiness first.
7. Permit a human-approved canary and monitor errors, resource saturation,
   queue latency, job completion, false-clean/partial coverage and database
   performance before broader release. Roll back on failure.

**Deployment status:** No deployment workflow, production host, externally
validated isolation provider or live GitHub authorization evidence is
configured by this repository change. Do not label this checklist or a green
CI run a production certification.
