# RepoLens Backend

RepoLens is an AI-powered repository intelligence and automated remediation engine.

## Core Capabilities

- **Phase 1 (Deep Intake & Context Engine)**: AST parsing with Tree-sitter (Python, JavaScript, TypeScript), dependency graph modeling via NetworkX, hybrid BM25 + dense retrieval, and deterministic scanner adapters (Semgrep, Trivy, OSV).
- **Phase 2 (Multi-Agent Analysis)**: Collaborative specialist reasoning (Architecture, Integration, Bug, Security) with LangGraph durable checkpoint execution.
- **Phase 3 (Remediation & Human Review)**: Evidence-grounded research, deterministic FixPlan validation, minimal unified diff generation, isolated sandbox syntax verification, patch critic evaluation, and HITL approval workflow.
- **Persistent Repository Intelligence**: Immutable Git-tree inventory, reusable file projections, semantic components, source-attested JS/TS workspace resolution, bounded graph queries, snapshot pins, retention, and resumable impact frontiers.
- **Production Validation**: Optional PostgreSQL/pgvector integration tests, a passive 1K/10K/100K scale harness, and a safe deployment smoke path. These are separate from normal zero-infrastructure CI.

## Canonical Package Metadata

`pyproject.toml` is the authoritative source for all package dependencies and configuration.
`requirements.txt` is a local-development compatibility wrapper around the `dev` extra. Do not use it for production.

## Installation & Setup

```bash
# Local development and tests
python -m pip install -e ".[dev]"
```

## Production install and startup

Production requires PostgreSQL for both the SQL execution authority and LangGraph durable checkpoints. From `backend`, install the production extra, configure the environment, migrate before startup, then run the zero-network import preflight:

```bash
python -m pip install -e ".[production]"
# Set DATABASE_URL, AUTH_COOKIE_SECURE=true, deployed CORS_ORIGINS,
# and TRUSTED_HOSTS in the deployment environment.
python -m alembic upgrade head
python -m app.cli.production_preflight
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Application startup fails closed before background workers if PostgreSQL, the exact repository Alembic head, the complete ORM schema, the PostgreSQL checkpointer, or required local artifact storage is unavailable. Startup never applies migrations. `/health/live` is process-only; `/health/ready` checks database connectivity, migration revision, complete application schema, and checkpointer readiness, and returns only `ready` or `not_ready`.

For local development, SQLite remains supported:

```bash
python -m pip install -e ".[dev]"
python -m alembic upgrade head

uvicorn app.main:app --reload --port 8000
```

## Running Tests

```bash
pytest
```

External-service tests skip cleanly unless explicitly configured.

## Manual Validation

```bash
# Deterministic sandbox smoke (no external writes)
python -m app.cli.deployment_smoke sandbox

# Passive generated scale fixture; 10k and 100k are also supported
python -m app.benchmarks.scale --preset 1k --output scale-report.json

# Optional disposable PostgreSQL/pgvector environment
python -m pytest tests/test_postgres_integration.py tests/test_pgvector_index.py -m integration
```

The harness reports actual deterministic measurements. Model calls, token use, and verifier attempts are recorded as `NOT_EXECUTED` when no live model path runs. Million-file behavior remains a benchmark target, not a claimed result.
