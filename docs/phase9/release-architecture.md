# RepoLens v1 Release Architecture Specification

**Authoritative Baseline SHA**: `e62e895bd9da7837d3fa92edcbf493d988f6fba8`  
**Phase**: Phase 9 — Batch 1 of 4 (Release Architecture Decision Record)

---

## 1. Executive Summary & Product Scope

**RepoLens** is an evidence-first, agentic repository intelligence and autonomous remediation platform designed for public GitHub repositories and pull requests. It reconstructs cross-layer software contracts, computes deterministic blast radiuses, extracts source-grounded findings, produces verified candidate patches, and supports explicitly authorized GitHub Pull Request delivery and COMMENT-only review publication.

### Core Philosophy
1. **Evidence-First**: Deterministic static analysis, Tree-sitter AST parsing, and relationship graphs precede all LLM reasoning. Unverified LLM assertions are rejected.
2. **Zero-Execution Confinement**: Submitted repositories are treated as hostile data. Code is never executed, dependencies are never installed, and dynamic sandboxes are never run on the host.
3. **Human-in-the-Loop Authority**: The platform never autonomously delivers patches or publishes reviews. All mutating actions require explicit authenticated human confirmation.

---

## 2. Release Personas

### Persona A: Normal Authenticated User (`USER`)
- **Capabilities**:
  - Register account / Login via secure Argon2id session.
  - Submit public GitHub repository URLs for scanning (up to 20/day).
  - Inspect repository findings, evidence snippets, and AST call graphs.
  - Generate candidate remediation patches and request iterative revisions (up to 50/day).
  - Submit public GitHub Pull Request URLs or dual commit SHAs for Change Analysis (up to 50/day).
  - Inspect contract impact, API mismatches, and markdown review reports.
- **Restrictions**:
  - Cannot perform GitHub write operations (cannot deliver PRs or publish reviews).
  - Cannot access other users' scans, findings, patches, or change analyses (isolated in SQL queries).

### Persona B: Authenticated Operator (`OPERATOR`)
- **Capabilities**:
  - All capabilities of a Normal User.
  - Deliver approved patches to GitHub as new Pull Requests via Git Data API (when `GITHUB_DELIVERY_ENABLED=True`).
  - Publish verified PR change reviews to GitHub as `COMMENT` reviews (when `GITHUB_PR_REVIEW_WRITE_ENABLED=True`).
- **Restrictions**:
  - Subject to identical tenant isolation: cannot access or mutate resources owned by another user.
  - Privileged GitHub writes strictly require explicit server-side feature flags and base commit drift checks.

### Persona C: Recruiter / Evaluator / Demo Viewer
- **Presentation Focus**:
  - Rapid zero-dependency setup (SQLite default, local Next.js + FastAPI dev servers).
  - Understandable architecture without microservice bloat or opaque background queues.
  - Transparent evidence trail and epistemic limitation disclosures.

---

## 3. System Architecture & Component Diagram

```
+-----------------------------------------------------------------------------------+
|                                Browser Client                                    |
|              Next.js 15 (React 19, TypeScript, Tailwind CSS, SSE Hooks)           |
+-----------------------------------------------------------------------------------+
                                         │  HTTP / HTTPS / SSE
                                         │  Cookies: repolens_session, repolens_csrf
                                         ▼
+-----------------------------------------------------------------------------------+
|                                FastAPI Backend                                    |
|  ┌─────────────────────────┐ ┌──────────────────────────┐ ┌─────────────────────┐ |
|  │ Security & Middlewares  │ │  Authentication & Quota  │ │  REST API Routers   │ |
|  │ - TrustedHostMiddleware │ │ - Argon2id Password Hash │ │ - /api/v1/auth      │ |
|  │ - CORSMiddleware        │ │ - 256-bit Session Store  │ │ - /api/v1/scans     │ |
|  │ - SecurityHeaders       │ │ - Double-Submit CSRF     │ │ - /api/v1/findings  │ |
|  │ - X-Request-ID Tracking │ │ - Daily Quotas (SQL Lock)│ │ - /api/v1/patches   │ |
|  └─────────────────────────┘ └──────────────────────────┘ │ - /api/v1/change... │ |
|                                                           │ - /api/v1/health    │ |
|                                                           └─────────────────────┘ |
+-----------------------------------------------------------------------------------+
               │                                      │
               ▼                                      ▼
+-------------------------------+      +--------------------------------------------+
|     Orchestration Engine      |      |           Analysis & Verification          |
| ┌───────────────────────────┐ |      | ┌────────────────────────────────────────┐ |
| │ LangGraph Workflow Engine │ |      | │ Deterministic Analyzers & Scanners     │ |
| │ - Typed Graph State       │ |      | │ - Tree-sitter AST (Py/JS/TS)           │ |
| │ - In-Memory / SQLite CP   │ |      | │ - Semgrep / Trivy / OSV Analyzers      │ |
| │ - Task Cancellation Safe  │ |      | │ - NetworkX RepositoryGraph (CALLS/APIs)│ |
| └───────────────────────────┘ |      | └────────────────────────────────────────┘ |
| ┌───────────────────────────┐ |      | ┌────────────────────────────────────────┐ |
| │ Resilient LLMRouter       │ |      | │ Grounding & Verification Gates         │ |
| │ - Role-based Model Routing│ |      | │ - EvidenceRegistry & Store             │ |
| │ - Exponential Backoff     │ |      | │ - 12-Check Strict Patch Verifier       │ |
| │ - Fallback Provider Chain │ |      | │ - AST-Grounded Review Verifier         │ |
| └───────────────────────────┘ |      | └────────────────────────────────────────┘ |
+-------------------------------+      +--------------------------------------------+
               │                                      │
               ▼                                      ▼
+-----------------------------------------------------------------------------------+
|                        Data Persistence & External Services                       |
| ┌──────────────────────────────────────────┐ ┌──────────────────────────────────┐ |
| │ Relational Database (SQLAlchemy 2.0)     │ │ Outbound External Integrations   │ |
| │ - Alembic Migrations (001 -> 010)        │ │ - Public GitHub Ingestion (GET)  │ |
| │ - SQLite (local) / PostgreSQL (prod)     │ │ - GitHub Git Data API (PR Write) │ |
| │ - Scans, Findings, Patches, Deliveries   │ │ - Multi-Provider LLMs (TLS)      │ |
| │ - Users, Sessions, UsageCounters, Events │ │ - Model Context Protocol (MCP)   │ |
| └──────────────────────────────────────────┘ └──────────────────────────────────┘ |
+-----------------------------------------------------------------------------------+
```

---

## 4. Trust Boundaries & Security Invariants

1. **Untrusted Repository Boundary**:
   - Ingested files are strictly confined to OS temporary workspaces.
   - Symlinks pointing outside the repository root are ignored (`_validate_safe_path`).
   - Repository code is never executed, imported, compiled, or evaluated.
2. **Identity & Session Boundary**:
   - Authentication tokens are 256-bit cryptographically secure random bytes, stored in the DB exclusively as SHA-256 hashes (`token_hash`).
   - Session cookies use `HttpOnly=True`, `SameSite=lax` (or `strict`), and in production `Secure=True` is strictly required.
   - Mutating routes enforce double-submit CSRF tokens via constant-time HMAC validation.
3. **Authorization Boundary**:
   - `_extract_user_id(current_user: CurrentUser)` accepts `CurrentUser` instances ONLY. Raw strings, UUID objects, and model instances are rejected with HTTP 401.
   - All resource lookups (`ScanModel`, `FindingModel`, `PatchModel`, `DeliveryModel`, `ChangeAnalysisModel`, `PullRequestReviewPublicationModel`) join directly against `owner_user_id == current_user.id`.
   - Cross-tenant access returns HTTP 404 to prevent resource existence leakage.
4. **Outbound GitHub Delivery Boundary**:
   - Normal users cannot trigger GitHub PR deliveries or review publications.
   - Deliveries require `OPERATOR` role AND explicit environment variable flags (`GITHUB_DELIVERY_ENABLED=True`, `GITHUB_PR_REVIEW_WRITE_ENABLED=True`).
   - Public PR resolution strips inbound authorization headers to eliminate confused-deputy attack vectors.
   - Fork PRs are rejected with HTTP 422 to prevent cross-repository poisoning.
   - All GitHub reviews are strictly `COMMENT` events; `APPROVE`, `REQUEST_CHANGES`, and auto-merges are programmatically prohibited.
5. **Admission Control & Quota Boundary**:
   - Usage counters are atomically incremented in the database (`UPDATE ... WHERE count < limit`).
   - Quotas fail-closed on missing or invalid UUID user IDs.

---

## 5. Primary Workflows

### Flow 1: Security Scan & Remediation Lifecycle
```
User submits URL
  │
  ▼
Validate GitHub URL & check daily quota (SCAN_CREATE)
  │
  ▼
Ephemeral Git shallow clone (depth=1, timeout=120s, budget=50MB)
  │
  ▼
Tree-sitter AST parsing & Static Scanner execution (Semgrep / Trivy / OSV)
  │
  ▼
Construct NetworkX RepositoryGraph (CALLS, IMPORTS, EXPOSES_API)
  │
  ▼
LangGraph Agent Workflow (Context building -> Reasoning -> Finding generation)
  │
  ▼
Deterministic Verifier: validates evidence in source AST -> Discard ungrounded
  │
  ▼
Persist CONFIRMED findings in DB & stream SSE events to UI
  │
  ▼
User requests Patch -> FixPlanner generates FixPlan -> PatchGenerator creates Unified Diff
  │
  ▼
Strict 12-check Patch Verifier -> Computes machine verdict (PASSED / FAILED)
  │
  ▼
Human Review: User approves patch (or submits feedback for iterative revision)
  │
  ▼
(Optional) Operator delivers PR via Git Data API with base commit drift guard
```

### Flow 2: PR Change Intelligence & Review Publication
```
User submits Public PR URL (or dual commit SHAs)
  │
  ▼
Validate PR URL & check daily quota (CHANGE_ANALYSIS_CREATE)
  │
  ▼
Credential-free PR metadata resolution -> Reconstruct base & head commit SHAs
  │
  ▼
Acquire dual-revision snapshots (Base Snapshot & Head Snapshot)
  │
  ▼
AST Structural & Contract Diff Engine: extract symbol deltas, API changes, schema diffs
  │
  ▼
Graph-Aware Blast Radius Traversal: trace upstream direct/transitive affected callers
  │
  ▼
AI Change Reviewer + Review Verifier: ground findings against AST facts -> Generate report
  │
  ▼
Persist ChangeAnalysis & Impact findings in DB -> Stream SSE to UI
  │
  ▼
Operator reviews preview -> Approves review publication
  │
  ▼
(Optional) Safe PR Review Publication: post COMMENT review with base drift protection
```

---

## 6. Deployment Shape & Portability

- **Single Process / Container Compatibility**: Runs as a standard FastAPI ASGI application (`uvicorn app.main:app`) and static Next.js frontend.
- **Zero External Heavy Infrastructure**:
  - SQLite by default (`sqlite:///./repolens.db`) with zero external service dependencies.
  - PostgreSQL support enabled via `DATABASE_URL="postgresql://..."`.
  - In-memory / SQLite LangGraph checkpointing (`checkpoints.db`).
  - No background Redis/Celery/Kafka message brokers needed.
- **Fail-Closed Production Configuration**:
  - In `ENVIRONMENT=production`, the application refuses to start if `AUTH_COOKIE_SECURE=False`, if wildcard CORS `*` is specified, or if wildcard `TRUSTED_HOSTS` is configured.

---

## 7. Phase 9 Batch Plan

- **Batch 1 (CURRENT)**: Final product audit, capability mapping, release architecture specification, and baseline verification.
- **Batch 2**: CI pipeline hardening (`.github/workflows/ci.yml`), release engineering, fresh database bootstrap verification, and operational health checks.
- **Batch 3**: UX polish, demo walk-through scripts, recruiter-friendly documentation (`README.md`, `docs/architecture.md`), and canonical demo repository guide.
- **Batch 4**: Final release gate evaluation, full test evidence pack assembly, version tagging, and official v1.0.0 release.
