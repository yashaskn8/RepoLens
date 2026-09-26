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
