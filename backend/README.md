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
`requirements.txt` is aligned with `pyproject.toml` for standard pip workflows.

## Installation & Setup

```bash
# Install package with all runtime dependencies
pip install .

# Install with development and test dependencies
pip install -e ".[dev]"

# Optional PostgreSQL/pgvector runtime support
pip install -e ".[postgres]"
```

## Running Migrations & Server

```bash
# Apply latest schema migrations
alembic upgrade head

# Start FastAPI development server
uvicorn app.main:app --reload --port 8000
```

## Running Tests

```bash
pytest
```

The suite currently collects 953 tests; external-service tests skip cleanly unless explicitly configured.

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
