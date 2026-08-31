# RepoLens v1.0.0 Release Notes

**Release Date:** August 31, 2026  
**Version:** `1.0.0`  
**Target Tag:** `v1.0.0`  
**License Status:** `NO LICENSE FILE`

---

## Overview

RepoLens v1.0.0 is the initial production-grade release of the AI-powered repository intelligence, multi-agent security scanning, and pull request change analysis platform. 

RepoLens combines deterministic static analysis, Tree-sitter AST parsing, and LangGraph-orchestrated AI workflows to analyze code repositories, identify vulnerabilities, generate verifiable remediation patches, and evaluate the architectural blast radius of pull requests.

---

## Key Features & Capabilities

### 1. Multi-Agent Code & Security Scanning
- **Deterministic AST & Pattern Analysis**: Detects security vulnerabilities, code smells, and quality antipatterns across Python, JavaScript, and TypeScript.
- **Evidence-First Verification**: Every finding is backed by deterministic code evidence, AST node locations, and reproducible proofs.
- **LangGraph Multi-Agent Orchestration**: Specialized scanner, triage, and planner agents coordinate analysis workflows with persistent state checkpointing.

### 2. AST-Verified Patch Generation
- **12-Check AST Patch Verifier**: Generates automated code repairs and subjects every patch to 12 deterministic AST and syntax safety checks before approval.
- **Fail-Closed Machine Verdicts**: Patches that introduce syntax errors, modify unaffected code blocks, or introduce dangerous primitives are automatically rejected.
- **Patch Revision Lineage**: Durable tracking of patch iterations, review feedback, and verification snapshots.

### 3. Change Intelligence & Pull Request Review
- **Semantic Diff & Blast Radius Analysis**: Calculates dependency impact graphs, exported symbol modifications, and downstream breaking change risks.
- **Automated PR Reviews**: Generates structured, evidence-grounded review comments and summaries for GitHub pull requests.

### 4. Safe GitHub Delivery
- **Read-Only by Default**: Strict safety controls prevent accidental upstream mutations (`GITHUB_DELIVERY_ENABLED=false` by default).
- **Branch Creation & Delivery Guards**: Verified deliveries require explicit authorization, pre-flight safety checks, and full audit logging in the `deliveries` table.

### 5. Multi-User Security & Access Control
- **Role-Based Access Control (RBAC)**: Fine-grained permissions across `ANONYMOUS`, `USER`, `OPERATOR`, and `ADMIN` roles.
- **Timing-Safe Authentication**: Argon2id password hashing, constant-time session token verification, and fail-closed authentication middleware.
- **Modern Cookie & CSRF Security**: Session tokens stored exclusively in `HttpOnly`, `SameSite=Lax` cookies; double-submit cookie CSRF validation on all state-changing endpoints.
- **Tenant Isolation**: Scans and change analyses are partitioned by owner user ID.

### 6. Operational Telemetry & Model Context Protocol (MCP)
- **MCP Server Adapter**: Native support for Model Context Protocol tools and resources, allowing external AI assistants to interact with RepoLens capabilities.
- **Observability**: Structured JSON logging, Prometheus-compatible metrics registry, and immutable `workflow_events` audit logging.

---

## Quality & Verification Summary

- **Backend Pytest Suite**: 650 collected — 645 passed, 5 skipped (optional provider API keys), 0 failed.
- **Phase 5–8 Regression Suite**: 167 collected — 167 passed, 0 failed.
- **Frontend Quality Gates**: TypeScript `type-check` (0 errors), ESLint (0 errors), Next.js production build successful (4 static pages).
- **Database Migrations**: 10 linear Alembic migrations creating 12 application tables (+ `alembic_version`), fully reversible.
- **Browser & Runtime Verification**: Playwright E2E smoke tests verified user registration, session persistence, role badge rendering, navigation, and zero console errors.

---

## Quickstart

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Git

### Backend Setup
```bash
cd backend
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

pip install -e .
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Frontend Setup
```bash
cd frontend
npm ci
npm run build
npm start
```

### Accessing the Application
- Web Interface: `http://localhost:3000`
- API Health Probe: `http://127.0.0.1:8000/health`
- Interactive API Docs (when enabled): `http://127.0.0.1:8000/api/v1/docs`

---

## Roadmap & Support

Development on RepoLens v1.0.0 is complete and frozen. Phase 10 is out of scope. For detailed architecture and security threat models, consult [docs/architecture.md](../architecture.md) and [docs/threat-model.md](../threat-model.md).
