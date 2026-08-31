# RepoLens Phase 9 — Batch 2 Release Engineering Report

**Audit Date**: 2026-08-31  
**Authoritative Baseline SHA**: `02ab889aa890e8fcdc10f65d42fc341bb82d871c`  
**Phase**: Phase 9 — Batch 2 of 4 (CI + Release Engineering + Migration Proof + Operational Hardening)  
**Status**: VERIFIED LOCALLY — AWAITING REMOTE GITHUB ACTIONS OBSERVATION

---

## 1. CI Workflow Architecture & Hardening

The GitHub Actions release verification pipeline defined in `.github/workflows/ci.yml` has been hardened with minimal permissions, clean environment isolation, and strict build/migration/test gates.

### Pipeline Configuration
- **Workflow File**: `.github/workflows/ci.yml`
- **Triggers**:
  - `push`: `[main, master]`
  - `pull_request`: `[main, master]`
  - `workflow_dispatch:` (Allows manual execution before release tagging)
- **Top-Level Permissions**:
  ```yaml
  permissions:
    contents: read
  ```
  *(No `contents: write`, `pull-requests: write`, `issues: write`, or `actions: write` granted)*
- **Concurrency Control**:
  ```yaml
  concurrency:
    group: repolens-ci-${{ github.workflow }}-${{ github.ref }}
    cancel-in-progress: true
  ```
- **Job Structure & Timeouts**:
  1. `backend-test` (Python 3.12, `timeout-minutes: 15`):
     - Dependency install: `pip install --upgrade pip` && `pip install -e ".[dev]"`
     - Dependency & bytecode verification: `python -m pip check` && `python -m compileall -q app`
     - Module import smoke: `python -c "import app.main; import app.services.authorization_service; ..."`
     - Reversible migration lifecycle proof on isolated DB (`ci_migration.db` $\to$ upgrade head $\to$ current $\to$ downgrade base $\to$ upgrade head)
     - Test DB migration bootstrap (`ci_test.db` $\to$ `alembic upgrade head`)
     - Pytest execution (`python -m pytest tests -v`)
  2. `frontend-check` (Node.js 20, `timeout-minutes: 10`):
     - Dependency install: `npm ci`
     - TypeScript type-check: `npm run type-check` (`tsc --noEmit`)
     - ESLint: `npm run lint` (`eslint src/`)
     - Production bundle build: `npm run build` (`next build`)

---

## 2. Empty Database Migration Bootstrap & Lifecycle Proof

### Migration Chain Verification
- **Alembic Revisions**: `001_initial_schema`, `002_patches_table`, `003_phase36_durability_and_provenance`, `004_patch_machine_verdict`, `005_workflow_events_table`, `006_deliveries_table`, `007_patch_fix_plan_snapshot`, `008_change_analysis_domain`, `009_pr_review_publication`, `010_multi_user_security`
- **Canonical Head**: `010_multi_user_security` (Single, linear, deterministic head)
- **Empty DB Bootstrap**: `alembic upgrade head` creates all 11 tables (`scans`, `findings`, `evidences`, `patches`, `workflow_events`, `deliveries`, `change_analyses`, `change_impacts`, `pr_review_publications`, `users`, `user_sessions`, `usage_counters`) solely via migrations (no `Base.metadata.create_all()` used).
- **Downgrade Cycle**: `alembic downgrade base` cleanly drops all tables in reverse dependency order without residual locks or orphaned constraints.
- **Re-Upgrade Cycle**: `alembic upgrade head` re-applies the complete revision chain cleanly.
- **Result**: **PASS (100% REVERSIBLE)**.

---

## 3. Engineering Findings Closure

### Finding A: SQLAlchemy Cartesian Product Warning
- **Status**: **REPRODUCED & RESOLVED**
- **Investigation**:
  - When running `pytest tests/test_human_revision_workflow.py -W error::sqlalchemy.exc.SAWarning`, the test `test_revise_race_condition_returns_409` failed with `SAWarning: SELECT statement has a cartesian product between FROM element(s) "patches" and FROM element "scans"`.
  - **Root Cause**: The production query in `authorization_service.py` (`db.query(PatchModel).join(ScanModel, PatchModel.scan_id == ScanModel.id)...`) is 100% correct and explicitly joins on `PatchModel.scan_id == ScanModel.id`. However, `test_revise_race_condition_returns_409` monkey-patched `db_session.query(PatchModel).filter` on the initial unjoined query instance. When `Query._clone()` was invoked during `.join()`, the copied filter method referenced the unjoined instance, causing SQLAlchemy's from-linter to generate `FROM patches, scans` without a join condition.
  - **Fix**: Replaced the instance-level monkey patch with a clean `_RaceConditionPatchQuery(type(real_q))` subclass method override that properly delegates to `super().filter(*args)`.
  - **Result**: Production tenant isolation SQL was preserved unaltered; the warning was eliminated at the root without global warning suppression.

### Finding B: Pytest-Asyncio Loop Scope Configuration
- **Status**: **REPRODUCED & RESOLVED**
- **Investigation**:
  - Pytest reported `PytestDeprecationWarning: The configuration option "asyncio_default_fixture_loop_scope" is unset`.
  - Added `asyncio_default_fixture_loop_scope = "function"` to `[tool.pytest.ini_options]` in `backend/pyproject.toml` as per official `pytest-asyncio` documentation.
  - **Result**: Warning eliminated cleanly with zero event-loop regressions across all 650 tests.

---

## 4. Test Topology & Execution Metrics

### Backend Test Suite
- **Command**: `python -m pytest tests -q`
- **Total Collected**: `650`
- **Passed**: `645`
- **Skipped**: `5` (PGVector integration tests requiring local PostgreSQL)
- **Failed**: `0`
- **Warnings**: `80` (Non-fatal third-party warnings: starlette multipart deprecation, alembic path separator config, testclient cookie deprecation, engine savepoint)
- **Execution Duration**: `68.71s`

### Phase 5–8 Regression Verification
- **Command**: `python -m pytest tests/test_phase5* tests/test_phase6* tests/test_phase7* tests/test_phase8* -q`
- **Passed**: `166` / `166` (`100% PASS`)

### Frontend Verification
- **TypeScript Type Check**: `npm run type-check` $\to$ **PASS** (0 errors)
- **ESLint**: `npm run lint` $\to$ **PASS** (0 errors)
- **Next.js Production Build**: `npm run build` $\to$ **PASS** (Static pages generated, optimized bundle 125 kB first-load JS)

---

## 5. Security & Isolation Verification

1. **CI Permissions**: Read-only (`contents: read`).
2. **Secret Independence**: All default test suites run with mocked LLM providers and GitHub clients; zero live API keys or tokens are required.
3. **Hostile Code Confinement**: Test fixtures are analyzed strictly as passive text/AST data; zero fixture code is imported or executed.
4. **Database Isolation**: CI runs exclusively against runner-local SQLite databases (`ci_test.db`, `ci_migration.db`) that are not committed or uploaded.

---

## 6. Items Deferred to Batch 3

The following non-blocking documentation and presentation items are explicitly scheduled for Batch 3:
1. **`README.md` Refresh**: Update header, test counts (645 passed), and migration range (001–010).
2. **`.env.example` Synchronization**: Document Phase 7 & 8 configuration variables (`GITHUB_PR_REVIEW_WRITE_ENABLED`, `AUTH_COOKIE_SECURE`, etc.).
3. **Repository-Relative Links**: Remove all local machine `file:///c:/Users/...` links in Phase 9 documentation and replace with repository-relative paths.
4. **Canonical Demo & Architecture Suite**: Author `docs/architecture.md`, `docs/threat-model.md`, and `docs/demo.md`.
5. **Frontend Role Badge**: Visual UI indicator for `OPERATOR` vs `USER` sessions.
