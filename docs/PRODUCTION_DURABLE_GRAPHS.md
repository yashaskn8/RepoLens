# Production Durable Graph Execution

RepoLens uses LangGraph's official async saver implementations. Local development and tests remain Docker-free and default to SQLite. Production execution requires PostgreSQL so checkpoint state is shared across workers and survives process restarts.

## Configuration and bootstrap

`CHECKPOINT_BACKEND=AUTO` selects SQLite for local SQLite deployments and PostgreSQL when `CHECKPOINT_DATABASE_URL` or `DATABASE_URL` is PostgreSQL. Set `CHECKPOINT_BACKEND=POSTGRES` to make that choice explicit. A dedicated checkpoint database is optional; when omitted, the application database URL is used. The PostgreSQL URL is parsed and normalized for psycopg while preserving its credentials, host, port, database, and query parameters; it is never logged.

Install the production dependencies from `backend` (this is the single production installation contract):

```powershell
python -m pip install -e ".[production]"
```

Apply application migrations, initialize the checkpointer schema once as an explicit deployment/bootstrap operation, and run the dependency preflight before starting the server:

```powershell
python -m alembic upgrade head
python -m app.agents.checkpointer_cli setup
python -m app.cli.production_preflight
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Application startup and `/health/ready` perform read-only checks for the exact Alembic head, every mapped ORM table, PostgreSQL connectivity, and initialized checkpoint schema. They never apply migrations or create checkpoint tables. SQLite's idempotent saver setup remains local/test behavior. `/health/live` checks process state only.

## Canonical report artifacts and deployment topology

Reports are staged locally only while being assembled or rendered. The durable report document and generated PDF are published through the canonical artifact store, and the report row stores tenant-bound artifact IDs; status checks, retries, and downloads resolve those IDs through `ArtifactRegistry` and verify the declared digest. A READY report is never served from a local report path.

Production must explicitly set `ARTIFACT_DEPLOYMENT_MODE`. `single_persistent_local` is supported only for one application host with an operator-provided persistent mount at `ARTIFACT_ROOT_DIR`; startup probes atomic publication, digest verification, read-back, and deletion but cannot prove that the mount survives host replacement. `shared` requires a configured production `ConditionalBlobClient` adapter and fails readiness when none is installed. Do not use container-local ephemeral storage for either mode. `REPORT_ARTIFACT_DIR` is temporary staging, not a serving authority.

For a separate frontend and API host, build the frontend with an absolute credential-free HTTPS `NEXT_PUBLIC_API_BASE_URL`. CORS origins and headers/methods are explicit. The session cookie remains HttpOnly and can be host-only; if the browser frontend must read the CSRF cookie across hosts, configure `CSRF_COOKIE_DOMAIN` as a valid shared parent domain covering both frontend origins and backend trusted hosts. `AUTH_COOKIE_DOMAIN` is optional and, when set, must cover backend trusted hosts. Browsers reject public-suffix cookie domains; operators should configure only their registrable application domain. CSRF validation requires the double-submit pair to bind to a currently valid, active server-side session.

## Recovery and authority

The SQL `DurableWorkDispatcher` remains the only recovery scheduler and lease authority. In production, a scan graph requires its active `SCAN` claim and rechecks that claim at graph-node boundaries. Scan persistence commits hold a short lease-row fence in the same SQL transaction. No lease token or database credential enters LangGraph state.

Graph invocations use `durability="sync"`. Resume is allowed only when the checkpoint matches the current scan, tenant, repository URL, commit/index authority, and full-analysis graph contract identity. A checkpoint read error is treated as an error, not as an empty thread. A mismatched checkpoint fails closed instead of applying findings from another generation.

Checkpoint serialization disables pickle fallback and uses an exact per-workflow Pydantic model allowlist. Runtime clients, registries, database sessions, and repository service objects remain outside checkpoint state. Change-analysis workspaces are rebound from freshly materialized snapshots for each invocation rather than relying on temporary paths from an older process.

Recovery is at-least-once around an interrupted in-flight node. A provider call that completed immediately before a process crash may be repeated on resume; RepoLens does not claim exactly-once provider execution. Durable workflow budgets and idempotent finding persistence remain authoritative.

## Guarantees and limitations

- Production SQLite and in-memory checkpointing are rejected.
- Normal tests use SQLite or an in-memory saver and require no provider credentials, PostgreSQL, or Docker.
- Optional PostgreSQL integration coverage runs only when `TEST_POSTGRES_URL` is explicitly configured.
- This mechanism checkpoints graph progress; it does not replace durable work leases, SQL usage accounting, or domain-level idempotency.
