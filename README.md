# RepoLens

[![CI](https://github.com/yashaskn8/RepoLens/actions/workflows/ci.yml/badge.svg)](https://github.com/yashaskn8/RepoLens/actions/workflows/ci.yml)

**RepoLens** is an evidence-first repository and pull-request intelligence platform. It combines deterministic structural static analysis, cross-layer dependency graph traversal, and evidence-grounded agentic reasoning to inspect multi-language codebases, verify candidate security remediations, and analyze the blast radius of pull requests.

RepoLens treats all submitted codebases as untrusted passive data, enforcing hostile repository confinement, tenant isolation, human-in-the-loop remediation authority, and guarded GitHub API writes.

---

## What RepoLens Does

- **Passive Repository Security & Quality Scanning**: Ingests public repositories via ephemeral shallow clones, parses syntax trees with Tree-sitter, runs deterministic static analyzers (Semgrep, Trivy, OSV-Scanner), and maps relationships across backend and frontend code.
- **Cross-Layer Contract Intelligence**: Statically reconstructs the full dependency and route graph between frontend client endpoints (`fetch`/`axios`) and backend route handlers (FastAPI), identifying breaking contract mismatches and orphaned schemas.
- **Pull Request & Change Intelligence**: Analyzes dual-revision AST diffs across commit ranges or public GitHub PRs, deterministically computing upstream caller blast radius with NetworkX graph traversal.
- **Evidence-Grounded AI Reasoning**: Specialist agents operate only on verified machine evidence (AST nodes, line citations, and scanner findings). Claims lacking direct source citations are discarded by the finding verifier.
- **Guarded Remediation & Safe Delivery**: Generates scoped candidate patches with 12-check AST verification. Remediation pauses at human approval boundaries; optional delivery to GitHub is restricted to isolated branch PRs by authenticated operators.

---

## Why It Is Different

1. **Deterministic Evidence Precedes AI Reasoning**: Rather than passing unindexed code to large language models, RepoLens extracts AST symbols, static findings, and graph topologies first. Models reason over structured evidence, while deterministic verification rejects or downgrades unsupported claims.
2. **Cross-Layer Contract Matching**: While traditional linters analyze single files in isolation, RepoLens connects client API calls in TypeScript to backend route decorators and Pydantic schemas in Python.
3. **Zero Untrusted Code Execution**: RepoLens never runs repository test suites, never executes arbitrary scripts or Makefiles, and never imports untrusted modules during analysis.
4. **Guarded GitHub Boundary**: Public repository and PR analyses are completely credential-free. Remote GitHub writes require server `GITHUB_TOKEN`, `OPERATOR` privileges, resource ownership, human approval, explicit feature flags, and remote branch drift checks.

---

## Core Workflows

### 1. Repository Security Scan & Remediation
`User` $\to$ `Clone & Ingest` $\to$ `Tree-sitter & Scanners` $\to$ `RepositoryGraph` $\to$ `Specialist Agents` $\to$ `Evidence Verifier` $\to$ `Candidate Patch Generation` $\to$ `12-Check AST Verifier` $\to$ `Human Approval Gate` $\to$ `(Optional Operator PR Delivery)`

### 2. Pull Request Change Intelligence & Review
`User` $\to$ `Credential-Free PR Resolution` $\to$ `Dual Snapshot Acquisition` $\to$ `AST Structural Diff` $\to$ `Cross-Layer Contract Match` $\to$ `Graph Blast Radius` $\to$ `AI Reviewer & Verifier` $\to$ `Report Generation` $\to$ `Operator Review` $\to$ `(Optional Operator COMMENT Publication)`

---

## Architecture Overview

```
RepoLens/
├── backend/                  # FastAPI / Python backend
│   ├── app/
│   │   ├── agents/          # Multi-agent LangGraph workflows & checkpointer
│   │   ├── analysis/        # Change intelligence, AST diff engine, blast radius & verifier
│   │   ├── api/             # FastAPI REST & SSE routers (scans, findings, patches, analyses)
│   │   ├── cli/             # Operator creation and administrative CLI utilities
│   │   ├── core/            # Pydantic Settings, database engine, security middlewares
│   │   ├── delivery/        # Safe GitHub Git Data API provider, PR body generator, drift checker
│   │   ├── graph/           # RepositoryGraph (NetworkX), node/edge builders, contract matcher
│   │   ├── ingestion/       # Tree-sitter parsers, dual snapshot acquisition, PR resolver
│   │   ├── llm/             # Resilient LLMRouter with provider fallbacks & telemetry
│   │   ├── models/          # SQLAlchemy ORM models (Users, Scans, Findings, Patches, Deliveries)
│   │   ├── patching/        # Unified diff applier, candidate patch generator, 12-check verifier
│   │   ├── schemas/         # Pydantic domain schemas, enums, change analysis & report models
│   │   ├── security/        # Argon2id password hashing, session tokens, secret redaction, CSRF
│   │   └── services/        # Auth, quotas, review publication, scan recovery & workflow events
│   ├── alembic/             # Database migrations (001 through 010)
│   └── tests/               # Pytest verification, security regression & migration lifecycle tests
└── frontend/                 # Next.js + React 19 + TypeScript frontend
    └── src/
        ├── app/             # App Router pages (Security Scan & Change Intelligence modes)
        ├── components/      # UI components (Diff view, Blast radius graph, Findings, Remediations)
        ├── context/         # AuthContext (Sessions, USER/OPERATOR role management)
        ├── lib/             # API client & SSE streaming hooks
        └── types/           # Domain TypeScript definitions mirroring backend schemas
```

For detailed architectural specifications and Mermaid sequence diagrams, see [Architecture Documentation](docs/architecture.md).

---

## Security & Safety Model

- **Multi-Tenant Isolation**: All database queries enforce strict user scoping (`user_id == current_user.id`). Attempting to access another tenant's artifacts returns `404 Not Found` (fail-closed IDOR defense).
- **Authentication & Sessions**: Password hashing via Argon2id. Opaque 256-bit entropy session tokens stored as SHA-256 digests in DB; transmitted via `HttpOnly`, `SameSite=Lax` cookies.
- **CSRF Defense**: Double-submit cookie verification (`repolens_csrf` cookie + `X-CSRF-Token` header) enforced on all state-mutating requests.
- **Fail-Closed Production Invariants**: Startup validation blocks execution if production mode lacks HTTPS secure cookies or contains wildcard CORS / trusted host settings.
- **Safe Review Publishing**: PR review publication is restricted strictly to `COMMENT` events; `APPROVE` and `REQUEST_CHANGES` are prohibited in code.

For complete threat evaluations and defense-in-depth matrices, see [Security & Threat Model](docs/threat-model.md).

---

## Tech Stack

- **Frontend**: Next.js 15, React 19, TypeScript, Vanilla CSS design system.
- **Backend**: FastAPI, Python 3.11+, Pydantic Settings & Schemas.
- **Persistence**: SQLAlchemy 2.0 ORM, Alembic migrations (revisions 001–010), SQLite default (portable to PostgreSQL / pgvector).
- **Static Analysis**: Tree-sitter AST parsers (Python, JS, TS, TSX, JSX), NetworkX graph engine, optional CLI adapters for Semgrep, Trivy, and OSV-Scanner.
- **Agent Orchestration**: LangGraph state machine with durable SQLite checkpointing.
- **LLM Abstraction**: Centralized `LLMRouter` with dynamic task-to-model mapping and fallback support across Gemini, Groq, NVIDIA, and HuggingFace.
- **Integrations**: GitHub Git Data API & REST API, Model Context Protocol (MCP) stdio adapters.

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ and `npm`
- Git

### 1. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies in editable mode
python -m pip install -e ".[dev]"

# Apply database migrations (001 through 010)
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --port 8000
```
Backend API will be available at `http://localhost:8000` (`/api/v1/docs` for Swagger UI, `/health` for health check).

### 2. Frontend Setup

```bash
cd frontend

# Install clean dependencies
npm ci

# Start Next.js development server
npm run dev
```
Frontend application will be available at `http://localhost:3000`.

---

## Configuration

Configuration is managed via environment variables. See [`.env.example`](.env.example) for a complete template.

Key configuration areas:
- `DATABASE_URL`: Relational database connection string (default: `sqlite:///./repolens.db`).
- `ENVIRONMENT`: Set to `development` or `production`.
- `AUTH_COOKIE_SECURE`: Must be `true` in production over HTTPS.
- `CORS_ORIGINS` & `TRUSTED_HOSTS`: Explicit comma-separated allowed origins/hosts.
- `GEMINI_API_KEY`, `GROQ_API_KEY`, `NVIDIA_API_KEY`, `HUGGINGFACE_API_KEY`: Optional provider keys for AI-assisted reasoning.
- `GITHUB_DELIVERY_ENABLED` & `GITHUB_PR_REVIEW_WRITE_ENABLED`: Guarded write flags (default: `false`).

---

## Authentication & Operator Setup

1. **User Registration**: Registering via the web UI creates a standard **`USER`** account with access to public repository scanning and PR change intelligence within daily quotas.
2. **Operator Elevation**: Privileged actions (e.g. delivering patches to GitHub) require the **`OPERATOR`** role. Create or elevate an operator account via the interactive CLI:
   ```bash
   cd backend
   python -m app.cli.create_operator --email operator@example.com
   ```
   *Note: Passwords are entered interactively via secure masked prompt (minimum 12 characters). Plaintext command-line password arguments are prohibited.*

---

## Running Tests

### Backend Test Suite
```bash
cd backend
python -m pytest
```
> **Latest Release Verification**: Collected 650 backend tests — **645 passed**, 5 PostgreSQL/pgvector integration tests skipped in the default SQLite environment (0 failed, 0 errors).

### Frontend Verification
```bash
cd frontend
npm ci
npm run type-check
npm run lint
npm run build
```

---

## GitHub Write Safety Invariants

RepoLens enforces strict controls around external GitHub writes:
1. **Public Analysis is Credential-Free**: Scanning repositories and resolving public pull requests does not require or use a GitHub token.
2. **Explicit Operator Authorization**: Remote writes require an active `OPERATOR` session and explicit server feature flags (`GITHUB_DELIVERY_ENABLED=True` or `GITHUB_PR_REVIEW_WRITE_ENABLED=True`).
3. **No Direct Commits or Merges**: Remediation delivery creates an isolated branch (`repolens/fix-...`) and opens a pull request via GitHub's Git Data API. RepoLens never writes to default branches and never merges PRs.
4. **Base Commit Drift Protection**: Before executing a remote write, the system verifies that the remote repository's branch HEAD SHA matches the exact scanned commit SHA. If upstream drift is detected, delivery is aborted immediately.
5. **COMMENT-Only Review Publication**: Published PR reviews are issued exclusively as standard `COMMENT` events, never `APPROVE` or `REQUEST_CHANGES`.

---

## Documentation Index

- [Architecture Specification](docs/architecture.md): System components, data flow, LangGraph workflows, and 3 Mermaid diagrams.
- [Security & Threat Model](docs/threat-model.md): Trust boundaries, threat actors, 20 evaluated vectors, and deployment checklist.
- [Demonstration Playbook](docs/demo.md): Step-by-step evaluator walkthrough, curated public repositories, and 5-minute demo script.
- [Product Capability Matrix](docs/phase9/product-capability-matrix.md): Complete module-by-module capability inventory.
- [Release Engineering Audit](docs/phase9/BATCH_2_RELEASE_ENGINEERING.md): Verified remote CI execution evidence and migration bootstrap proof.

---

## Current Limitations & Unsupported Features

- **Untrusted Code Execution**: RepoLens does not run arbitrary test suites, execute binaries, or provide dynamic sandbox execution.
- **Autonomous Auto-Merging**: Machine systems cannot merge pull requests or bypass human review.
- **Private Repository Multi-Tenancy**: Current public release candidate focuses on public GitHub repository analysis; organization-wide OAuth token delegations and private repository sync are out of scope for v1.

---

## Release Status

RepoLens release version: **v1.0.0** (Phase 9 verification complete, reproducible CI pipeline and migration lifecycle verified).
