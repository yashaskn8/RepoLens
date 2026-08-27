# RepoLens

RepoLens is an AI-powered repository intelligence and autonomous remediation platform that ingests, indexes, verifies, plans, and patches complex multi-language codebases with strict mathematical determinism and human-in-the-loop safety boundaries.

> **Phase 5: Safe GitHub Delivery & Pull Request Orchestration**  
> Complete intelligence, remediation, and safe delivery platform featuring automated Pull Request generation via GitHub's Git Data API, deterministic base-branch drift protection, isolated ephemeral sandbox verification, real-time Server-Sent Events (SSE) workflow streaming with monotonic replay, durable audit trail event persistence, structured GFM Markdown and JSON evidence reporting, operational telemetry monitoring, Tree-sitter AST symbol indexing, deterministic RepositoryGraph route & dependency contract evaluation, durable LangGraph multi-agent scan execution, exact-commit snapshot rehydration, and an isolated sandbox patch verification engine.

---

## Key Capabilities & Safety Invariants

1. **Untrusted Repository Confinement**: Submitted repositories are never executed, test suites are never run directly, and external scripts are never invoked.
2. **Safe GitHub PR Orchestration**: Approved patches can be delivered as pull requests back to the originating repository via GitHub's Git Data API (`blobs` $\to$ `tree` $\to$ `commit` $\to$ `ref`). RepoLens **never** writes directly to `main` or the default branch, never performs auto-merges, and never force-pushes.
3. **Deterministic Base Drift Protection**: Before creating a commit or branch, the delivery validator verifies the remote branch HEAD SHA matches the exact scanned commit SHA. If drift is detected, delivery is blocked and recorded in the audit trail without modifying remote repository state.
4. **Deterministic 15-Check Delivery Verification**: Patches undergo strict validation including explicit human approval checks, machine verdict checks, remote base SHA drift detection, branch name sanitization, path traversal confinement, binary file guards, Tree-sitter AST syntax re-parsing, scanner re-evaluation, secret leak scanning, and critical finding regression checks.
5. **Exact Commit Rehydration**: The original repository is never mutated in-place. Remediation, planning, and verification operate strictly in ephemeral sandbox clones rehydrated to the exact persisted commit SHA.
6. **Human-in-the-Loop Authority**: Machine verification never marks patches as `APPROVED`. Patches pause at human approval boundaries (`VERIFIED` or `NEEDS_REVIEW`) and require explicit human review via `/approve`, `/reject`, or `/revise`. Only already-approved patches can be delivered to GitHub.
7. **Machine Verdict vs Human Review Separation**: Machine verification results are persisted independently as `PASSED`, `NEEDS_REVIEW`, or `REJECTED`, while patch lifecycle status uses `DRAFT`, `VERIFIED`, `NEEDS_REVIEW`, `REJECTED`, and `APPROVED`. Only explicit human approval may set `APPROVED`.
8. **Single Revision Lineage**: Human revisions generate an immutable child patch linked via `parent_patch_id` and `revision_number = 1`, enforced by database constraints and atomic API validation.
9. **Real-Time SSE Streaming & Replay**: Low-latency Server-Sent Events stream live workflow stages, tool actions, delivery lifecycle events, and human decisions with `Last-Event-ID` offset recovery.
10. **Exportable Evidence Reports & Delivery Telemetry**: Complete GFM Markdown and structured JSON report generation with exact source evidence, unified diffs, chronological audit trails, and delivery metrics.
11. **Zero External Worker Requirement**: RepoLens supports pure local development on Windows, macOS, and Linux without requiring Docker, Redis, Celery, or Kafka.

---

## Architecture Overview

```
RepoLens/
├── backend/                  # FastAPI / Python backend
│   ├── app/
│   │   ├── agents/          # Multi-agent LangGraph workflows & checkpointer
│   │   ├── analysis/        # Intelligence service, scanners, evidence store
│   │   ├── api/             # FastAPI routers (scans, findings, patches, deliveries, health)
│   │   ├── context/         # Hybrid retrieval, context engine, token budgeting
│   │   ├── core/            # Settings, database connection, database engine
│   │   ├── delivery/        # GitHub provider, Git Data API, safety validator, PR body generator
│   │   ├── graph/           # RepositoryGraph, node/edge builders, route matcher
│   │   ├── ingestion/       # Tree-sitter parsers, manifest, snapshot rehydration
│   │   ├── llm/             # Resilient gateway with fallback, backoff & telemetry
│   │   ├── models/          # SQLAlchemy ORM models (Scan, Finding, Evidence, Patch, WorkflowEvent, Delivery)
│   │   ├── patching/        # Unified diff applier, validator, 12-check verifier, critic
│   │   ├── planning/        # Fix planner with strict scope boundary enforcement
│   │   ├── research/        # Evidence-grounded technical research & source tiering
│   │   ├── schemas/         # Canonical Pydantic schemas, enums, delivery, reports & telemetry
│   │   ├── security/        # Secret redaction, prompt injection and Markdown sanitization
│   │   └── services/        # Scan recovery, workflow events, report & delivery orchestrators
│   ├── alembic/             # Database migrations (001, 002, 003, 004, 005, 006, 007)
│   └── tests/               # 405+ comprehensive Pytest verification & security release tests
└── frontend/                 # Next.js + React 19 + TypeScript frontend
    └── src/
        ├── app/             # App Router pages (scans dashboard, finding remediation)
        ├── components/      # UI components (diff viewer, workflow timeline, approval modal, delivery card)
        ├── lib/             # API client, SSE streaming hooks & HTTP services
        └── types/           # Domain TypeScript definitions mirroring schemas
```

---

## Configuration & Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./repolens.db` | Main relational database (SQLite or PostgreSQL) |
| `CHECKPOINT_DB_FILE` | `checkpoints.db` | Durable LangGraph workflow execution checkpointer |
| `GITHUB_DELIVERY_ENABLED` | `False` | Feature toggle enabling safe GitHub Pull Request delivery |
| `GITHUB_TOKEN` | `""` | GitHub Personal Access Token (PAT) with repository content & PR write scope |
| `GEMINI_API_KEY` | `""` | LLM Provider — Gemini (architecture model: gemini-3.7-flash) |
| `GROQ_API_KEY` | `""` | LLM Provider — Groq (hosted open-weight models) |
| `NVIDIA_API_KEY` | `""` | LLM Provider — NVIDIA (NeMo / NeMoTron verification models) |
| `HUGGINGFACE_API_KEY` | `""` | LLM Provider — HuggingFace (hosted open-weight models) |


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
   pip install -e ".[dev]"
   ```
   *(Or `pip install -r requirements.txt`)*

4. Run database migrations:
   ```bash
   alembic upgrade head
   ```

5. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   The backend will be available at `http://localhost:8000`.  
   - Interactive Swagger API Docs: `http://localhost:8000/api/v1/docs`  
   - Interactive ReDoc API Docs: `http://localhost:8000/api/v1/redoc`  
   - Health Check: `http://localhost:8000/health`

6. Run backend test suite:
   ```bash
   pytest tests/ -v
   ```

---

## Frontend Setup

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
Alembic migrations (001, 002, 003, 004, 005, 006, 007) and SQLAlchemy models are designed to be fully compatible with both SQLite and PostgreSQL.
