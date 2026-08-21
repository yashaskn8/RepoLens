# RepoLens Backend

RepoLens is an AI-powered repository intelligence and automated remediation engine.

## Core Capabilities

- **Phase 1 (Deep Intake & Context Engine)**: AST parsing with Tree-sitter (Python, JavaScript, TypeScript), dependency graph modeling via NetworkX, hybrid BM25 + dense retrieval, and deterministic scanner adapters (Semgrep, Trivy, OSV).
- **Phase 2 (Multi-Agent Analysis)**: Collaborative specialist reasoning (Architecture, Integration, Bug, Security) with LangGraph durable checkpoint execution.
- **Phase 3 (Remediation & Human Review)**: Evidence-grounded research, deterministic FixPlan validation, minimal unified diff generation, isolated sandbox syntax verification, patch critic evaluation, and HITL approval workflow.

## Canonical Package Metadata

`pyproject.toml` is the authoritative source for all package dependencies and configuration.
`requirements.txt` is aligned with `pyproject.toml` for standard pip workflows.

## Installation & Setup

```bash
# Install package with all runtime dependencies
pip install .

# Install with development and test dependencies
pip install -e ".[dev]"
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
