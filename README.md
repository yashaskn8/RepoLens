# RepoLens

RepoLens is an AI-powered repository intelligence and autonomous remediation platform that ingests, indexes, verifies, plans, and patches complex multi-language codebases with strict mathematical determinism and human-in-the-loop safety boundaries.

> **Phase 3.6: Final Correctness Closure**  
> Complete intelligence pipeline featuring Tree-sitter AST symbol indexing, deterministic RepositoryGraph route & dependency contract evaluation, durable LangGraph multi-agent scan execution, exact-commit snapshot rehydration, and a 12-check isolated sandbox patch verification engine.

---

## Key Capabilities & Safety Invariants

1. **Untrusted Repository Confinement**: Submitted repositories are never executed, test suites are never run directly, and external scripts are never invoked.
2. **Deterministic 12-Check Verification**: Patches undergo unified diff validation, path traversal prevention, binary file guards, Tree-sitter AST syntax re-parsing, route contract verification, scanner re-evaluation, secret leak scanning, and critical finding regression checks.
3. **Exact Commit Rehydration**: The original repository is never mutated in-place. Remediation, planning, and verification operate strictly in ephemeral sandbox clones rehydrated to the exact persisted commit SHA.
4. **Human-in-the-Loop Authority**: Machine verification never marks patches as `APPROVED`. Patches pause at human approval boundaries (`VERIFIED` or `NEEDS_REVIEW`) and require explicit human review via `/approve`, `/reject`, or `/revise`.
5. **Single Revision Lineage**: Human revisions generate an immutable child patch linked via `parent_patch_id` and `revision_number = 1`, enforcing a hard cap of at most one human revision per patch lineage.
6. **Zero External Worker Requirement**: RepoLens supports pure local development on Windows, macOS, and Linux without requiring Docker, Redis, Celery, or Kafka.

---

## Architecture Overview

```
RepoLens/
├── backend/                  # FastAPI / Python backend
│   ├── app/
│   │   ├── agents/          # Multi-agent LangGraph workflows & checkpointer
│   │   ├── analysis/        # Intelligence service, scanners, evidence store
│   │   ├── api/             # FastAPI routers (scans, findings, patches, health)
│   │   ├── context/         # Hybrid retrieval, context engine, token budgeting
│   │   ├── core/            # Settings, database connection, database engine
│   │   ├── graph/           # RepositoryGraph, node/edge builders, route matcher
│   │   ├── ingestion/       # Tree-sitter parsers, manifest, snapshot rehydration
│   │   ├── llm/             # Resilient gateway with fallback & exponential backoff
│   │   ├── models/          # SQLAlchemy ORM models (Scan, Finding, Evidence, Patch)
│   │   ├── patching/        # Unified diff applier, validator, 12-check verifier, critic
│   │   ├── planning/        # Fix planner with strict scope boundary enforcement
│   │   ├── research/        # Evidence-grounded technical research & source tiering
│   │   ├── schemas/         # Canonical Pydantic schemas & enums
│   │   └── services/        # Durable scan recovery & in-process task dispatcher
│   ├── alembic/             # Database migrations (001, 002, 003)
│   └── tests/               # 280+ comprehensive Pytest verification tests
└── frontend/                 # Next.js + React 19 + TypeScript frontend
    └── src/
        ├── app/             # App Router pages (scans dashboard, finding remediation)
        ├── components/      # UI components (diff viewer, approval modal, graphs)
        ├── lib/             # API client & HTTP hooks
        └── types/           # Domain TypeScript definitions mirroring schemas
```

---

## Local Development (No Docker Required)

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Git

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run database migrations:
   ```bash
   alembic upgrade head
   ```

5. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   The backend will be available at `http://localhost:8000`.  
   - Interactive API Docs: `http://localhost:8000/docs`  
   - Health Check: `http://localhost:8000/health`

6. Run backend test suite:
   ```bash
   pytest tests/ -v
   ```

---

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Type-check and lint:
   ```bash
   npm run type-check
   npm run lint
   ```

4. Start the Next.js development server:
   ```bash
   npm run dev
   ```
   The frontend will be available at `http://localhost:3000`.

---

## Database Portability

By default, RepoLens uses SQLite for local zero-dependency development (`sqlite:///./repolens.db`). To switch to PostgreSQL, set the `DATABASE_URL` environment variable:
```bash
DATABASE_URL="postgresql://user:password@localhost:5432/repolens"
```
Alembic migrations (001, 002, 003) and SQLAlchemy models are designed to be fully compatible with both SQLite and PostgreSQL.
