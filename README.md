# RepoLens

RepoLens is an AI-powered repository intelligence and autonomous remediation platform that ingests, indexes, verifies, plans, patches, and analyzes complex multi-language codebases with strict mathematical determinism and human-in-the-loop safety boundaries.

> **Phase 6: Evidence-Grounded Change Intelligence & Pull Request Review**  
> Analyze the semantic blast radius of a pull request or exact commit range using deterministic structural/contract analysis, repository graph traversal and evidence-grounded AI review. Features exact dual-revision snapshot acquisition, Tree-sitter AST symbol & contract diffing, cross-layer API & schema mismatch detection, deterministic graph-aware blast radius computation, zero-execution security isolation, evidence-grounded AI review verification, structured GFM Markdown and JSON reporting with epistemic limitations disclosure, operational telemetry, and an integrated Change Analysis / PR Review product experience.

---

## Key Capabilities & Safety Invariants

1. **Untrusted Repository Confinement**: Submitted repositories are never executed, test suites are never run directly, dynamic reflection is not imported, and external scripts are never invoked.
2. **Dual-Revision Snapshot Acquisition**: Reconstructs exact base and head repository workspaces pinned to immutable 40-character commit SHAs, enforcing zero submodule recursion, zero git hooks, zero Git LFS filters, and strict symlink confinement.
3. **Deterministic Structural & Contract Diffing**: Statically extracts file deltas, symbol-level modifications (signature changes, deletions, additions), FastAPI route contract changes (paths, HTTP methods), Pydantic schema field changes, package dependency manifest changes, and environment variable config deltas.
4. **Cross-Layer Frontend/Backend Contract Matching**: Traces relationship graph edges between frontend client HTTP calls and backend API route definitions to deterministically detect breaking contract changes.
5. **Deterministic Graph-Aware Blast Radius**: NetworkX-backed dependency traversal traces upstream direct and transitive callers across changed symbols with depth limits, impact thresholds, and cycle detection.
6. **Evidence-Grounded AI Review Verifier**: AI review findings are strictly verified against deterministic AST facts, diff records, relationship graph edges, and source line ranges. 100% of unsupported or hallucinated AI claims are rejected.
7. **Explicit Epistemic Disclosures**: Reports transparently disclose available static analysis tools vs runtime execution (e.g. explicitly stating that repository test suites and dynamic sandboxes were NOT executed).
8. **Safe GitHub PR Orchestration**: Approved patches can be delivered as pull requests back to the originating repository via GitHub's Git Data API (`blobs` $\to$ `tree` $\to$ `commit` $\to$ `ref`). RepoLens **never** writes directly to `main` or the default branch, never performs auto-merges, and never force-pushes.
9. **Deterministic Base Drift Protection**: Before creating a commit or branch, the delivery validator verifies the remote branch HEAD SHA matches the exact scanned commit SHA. If drift is detected, delivery is blocked and recorded in the audit trail.
10. **Human-in-the-Loop Authority**: Machine verification never marks patches as `APPROVED`. Patches pause at human approval boundaries (`VERIFIED` or `NEEDS_REVIEW`) and require explicit human review. Only already-approved patches can be delivered.
11. **Real-Time SSE Streaming & Replay**: Low-latency Server-Sent Events stream live workflow stages, tool actions, delivery lifecycle events, and human decisions with `Last-Event-ID` offset recovery.
12. **Zero External Worker Requirement**: RepoLens supports pure local development on Windows, macOS, and Linux without requiring Docker, Redis, Celery, or Kafka.

---

## Architecture Overview

```
RepoLens/
├── backend/                  # FastAPI / Python backend
│   ├── app/
│   │   ├── agents/          # Multi-agent LangGraph workflows & checkpointer
│   │   ├── analysis/        # Change intelligence, diff engine, blast radius, AI reviewer & verifier
│   │   ├── api/             # FastAPI routers (scans, findings, patches, deliveries, change analyses)
│   │   ├── context/         # Hybrid retrieval, context engine, token budgeting
│   │   ├── core/            # Settings, database connection, database engine
│   │   ├── delivery/        # GitHub provider, Git Data API, safety validator, PR body generator
│   │   ├── graph/           # RepositoryGraph, node/edge builders, route matcher
│   │   ├── ingestion/       # Tree-sitter parsers, dual snapshot acquisition, PR resolver
│   │   ├── llm/             # Resilient gateway with fallback, backoff & telemetry
│   │   ├── models/          # SQLAlchemy ORM models (Scan, Finding, Patch, WorkflowEvent, ChangeAnalysis)
│   │   ├── patching/        # Unified diff applier, validator, 12-check verifier, critic
│   │   ├── planning/        # Fix planner with strict scope boundary enforcement
│   │   ├── research/        # Evidence-grounded technical research & source tiering
│   │   ├── schemas/         # Pydantic schemas, enums, change analysis, reports & telemetry
│   │   ├── security/        # Secret redaction, prompt injection and Markdown sanitization
│   │   └── services/        # Workflow events, report & delivery orchestrators
│   ├── alembic/             # Database migrations (001 through 008)
│   └── tests/               # 523+ comprehensive Pytest verification, security & release tests
└── frontend/                 # Next.js + React 19 + TypeScript frontend
    └── src/
        ├── app/             # App Router pages (security scan & change analysis modes)
        ├── components/      # UI components (change overview, blast radius, contract diff, evidence card)
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
Alembic migrations (001 through 008) and SQLAlchemy models are designed to be fully compatible with both SQLite and PostgreSQL.
