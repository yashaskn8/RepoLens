# RepoLens v1.0.1 Release Notes

**Release Date:** August 31, 2026
**Version:** `1.0.1`
**Target Tag:** `v1.0.1`
**Supersedes:** `v1.0.0`
**License Status:** `NO LICENSE FILE`

---

## Overview

RepoLens v1.0.1 is a corrective release that fixes factual inaccuracies in the v1.0.0 release documentation and evidence pack. There are **no functional code changes, no new features, no schema migrations, and no security fixes** in this release.

The `v1.0.0` Git tag is preserved immutably. This release supersedes v1.0.0 as the recommended reference version.

---

## Corrections

### 1. Role Taxonomy
- **Removed** incorrect `ADMIN` role from RBAC documentation.
- **Corrected** to reflect the actual `UserRole` enum: `USER` and `OPERATOR` only. `ANONYMOUS` is a runtime access level for unauthenticated requests, not a persisted role.

### 2. Skipped Test Identifiers
- **Removed** fabricated test names (`test_live_openai_provider`, `test_live_anthropic_provider`, `test_live_gemini_provider`, `test_live_github_api`, `test_pgvector_similarity_search`).
- **Corrected** to list the actual skipped tests: `test_live_gemini_smoke`, `test_live_groq_smoke`, `test_live_nvidia_smoke`, `test_live_huggingface_smoke`, and `test_pgvector_real_postgres_integration`.

### 3. Provider API Key References
- **Removed** references to non-existent `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `GITHUB_TOKEN` environment variable guards.
- **Corrected** to list the actual guard variables: `GEMINI_API_KEY`, `GROQ_API_KEY`, `NVIDIA_API_KEY`, `HUGGINGFACE_API_KEY`, and `PGVECTOR_TEST_URL`.

### 4. Observability Claims
- **Removed** "Prometheus-compatible metrics registry" claim (no `prometheus_client` library is installed).
- **Removed** "Structured JSON logging" claim (standard Python `logging` is used, not `structlog` or `python-json-logger`).
- **Corrected** to: "Standard Python logging and in-memory metrics registry."

---

## Version Synchronization

All version markers updated from `1.0.0` → `1.0.1`:

| File | Parameter |
| :--- | :--- |
| `backend/app/core/config.py` | `Settings.VERSION` |
| `backend/pyproject.toml` | `project.version` |
| `backend/app/__init__.py` | `__version__` |
| `backend/app/mcp/adapter.py` | MCP Server default version |
| `backend/app/ingestion/github_pr.py` | `user_agent` |
| `frontend/package.json` | `version` |
| `frontend/package-lock.json` | `version` |

---

## Quality Verification

- **Backend Pytest Suite**: 650 collected, 645 passed, 5 skipped (valid environment guards), 0 failed.
- **Frontend Quality Gates**: `npm ci`, `type-check`, `lint`, and `build` all pass with 0 errors.
- **No schema changes**: Migration count remains at 10 (001–010), 12 application tables unchanged.

---

## Detailed Correction Record

See [V1.0.0_CORRECTION_NOTICE.md](V1.0.0_CORRECTION_NOTICE.md) for the complete itemized correction record with exact before/after text.
