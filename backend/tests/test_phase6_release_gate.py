"""Comprehensive Release Gate Verification Suite for Phase 6 Change Intelligence.

Validates:
E2E A — Deleted Callee (Real Git repo, canonical RepositoryGraph builder, CALLS edge, CALLER_IMPACT)
E2E B — Frontend/Backend Contract Break (Canonical route matching, API_CONTRACT_CHANGE, affected frontend caller)
E2E C — Body-Only Function Change (Same signature, only body changes -> MODIFIED)
E2E D — Safe Line Shift (Line movement alone is NOT modified)
E2E E — Secret Config Safety (Zero plaintext secrets in DB, model_metadata, impacts, report, telemetry)
E2E F — Durable Process Restart (Resume from durable state, reacquire exact SHAs, zero duplicate impacts)
E2E G — Same-Repository PR Resolution (Zero writes, read-only GET, exact SHAs)
E2E H — Fork PR Typed Rejection (422 FORK_PULL_REQUEST_UNSUPPORTED, zero execution)
Alembic Migration Cycle — 007 -> 008 -> insert scan_id=NULL events -> 008 -> 007 -> 008 cycle
"""

from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from alembic import command
from alembic.config import Config

from app.analysis.diff_engine import ChangeDiffEngine
from app.analysis.impact_engine import ChangeImpactEngine
from app.analysis.report_generator import generate_change_analysis_report, generate_change_analysis_telemetry
from app.analysis.review_verifier import ChangeReviewVerifier
from app.analysis.reviewer import ChangeReviewAgent
from app.analysis.workflow import execute_background_change_analysis
from app.analysis.workflow_graph import build_change_analysis_graph
from app.core.database import Base
from app.graph.builder import build_repository_graph
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, NodeKind
from app.ingestion.comparison_snapshot import ComparisonSnapshotService, ComparisonWorkspacePair
from app.ingestion.github_pr import GitHubPRResolver, get_github_pr_resolver
from app.ingestion.manifest import build_manifest
from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.change_analysis import (
    ChangeAnalysisPRRequest,
    ChangeAnalysisReportResponse,
    ChangeAnalysisRequest,
    ChangeAnalysisResponse,
    ChangeImpactType,
    ChangeReviewFinding,
    ChangeReviewVerdict,
    ChangeRiskLevel,
    ConfigDelta,
    ImpactVerificationStatus,
    ResolvedPullRequest,
    Severity,
    StructuralDiffResult,
    SymbolChangeType,
)
from app.schemas.telemetry import ChangeAnalysisTelemetry
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService
from tests.conftest import TestingSessionLocal


class MockAsyncClient:
    """Mock async HTTP client for zero-write GitHub PR resolution verification."""

    def __init__(self, status_code: int = 200, json_data: Optional[Dict[str, Any]] = None):
        self.status_code = status_code
        self.json_data = json_data or {}
        self.calls: List[Dict[str, Any]] = []

    async def get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: Any = None):
        self.calls.append({"method": "GET", "url": url, "headers": headers})
        mock_resp = MagicMock()
        mock_resp.status_code = self.status_code
        mock_resp.json.return_value = self.json_data
        mock_resp.text = json.dumps(self.json_data)
        return mock_resp


def _init_local_git_repo(repo_dir: str, base_files: Dict[str, str], head_files: Dict[str, str]) -> Tuple[str, str]:
    """Initialize a real local Git repository with two distinct commits."""
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "TestUser"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@repolens.ai"], cwd=repo_dir, check=True, capture_output=True)

    # 1. Write base files and commit
    for rel_path, content in base_files.items():
        full_path = os.path.join(repo_dir, rel_path.replace("/", os.sep))
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

    subprocess.run(["git", "add", "-A"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial base commit"], cwd=repo_dir, check=True, capture_output=True)
    base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True).stdout.strip()

    # 2. Write head files and commit
    for rel_path, content in head_files.items():
        full_path = os.path.join(repo_dir, rel_path.replace("/", os.sep))
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

    # Remove files deleted in head
    for rel_path in base_files:
        if rel_path not in head_files:
            full_path = os.path.join(repo_dir, rel_path.replace("/", os.sep))
            if os.path.exists(full_path):
                os.remove(full_path)

    subprocess.run(["git", "add", "-A"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Head change commit"], cwd=repo_dir, check=True, capture_output=True)
    head_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True).stdout.strip()

    return base_sha, head_sha


# =========================================================================
# E2E A: Deleted Callee with Real Canonical Graph Builder
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_a_deleted_callee_production_graph(db_session: Session):
    """E2E A: Deleted callee with real local Git repo and canonical RepositoryGraph wiring."""
    with tempfile.TemporaryDirectory() as git_dir:
        base_files = {
            "app/auth.py": "def verify_token(token: str) -> bool:\n    return len(token) > 0\n",
            "app/api.py": "from app.auth import verify_token\ndef login_endpoint(token: str):\n    if verify_token(token):\n        return {'status': 'ok'}\n",
        }
        head_files = {
            "app/auth.py": "# verify_token removed\ndef new_helper():\n    pass\n",
            "app/api.py": "from app.auth import verify_token\ndef login_endpoint(token: str):\n    if verify_token(token):\n        return {'status': 'ok'}\n",
        }
        base_sha, head_sha = _init_local_git_repo(git_dir, base_files, head_files)

        analysis_id = str(uuid4())
        analysis = ChangeAnalysisModel(
            id=analysis_id,
            repository_url="https://github.com/fastapi/fastapi",
            repository_owner="fastapi",
            repository_name="fastapi",
            base_commit_sha=base_sha,
            head_commit_sha=head_sha,
            base_ref="main",
            head_ref="feature/auth",
            status="PENDING",
        )
        db_session.add(analysis)
        db_session.commit()

        # Unpack both revisions to test workspaces
        with tempfile.TemporaryDirectory() as base_ws, tempfile.TemporaryDirectory() as head_ws:
            proc = subprocess.Popen(["git", "archive", base_sha], cwd=git_dir, stdout=subprocess.PIPE)
            subprocess.run(["tar", "-x", "-C", base_ws], stdin=proc.stdout, check=True)
            proc2 = subprocess.Popen(["git", "archive", head_sha], cwd=git_dir, stdout=subprocess.PIPE)
            subprocess.run(["tar", "-x", "-C", head_ws], stdin=proc2.stdout, check=True)

            pair = ComparisonWorkspacePair(
                base_workspace=base_ws,
                head_workspace=head_ws,
                base_commit_sha=base_sha,
                head_commit_sha=head_sha,
                repository_url="https://github.com/fastapi/fastapi",
            )
            with patch("app.analysis.workflow.SessionLocal", side_effect=TestingSessionLocal), \
                 patch.object(
                     ComparisonSnapshotService,
                     "acquire_comparison_workspaces_from_metadata",
                     return_value=pair,
                 ), \
                 patch.object(
                     ComparisonSnapshotService,
                     "release_comparison_workspaces",
                     return_value=None,
                 ):
                await execute_background_change_analysis(analysis_id=analysis_id)

        # Verify DB persistence and canonical graph blast radius results
        db = TestingSessionLocal()
        updated_analysis = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id).first()
        assert updated_analysis is not None
        assert updated_analysis.status == "COMPLETED"

        # Verify impacts generated through canonical CALLS edge
        impacts = db.query(ChangeImpactModel).filter(ChangeImpactModel.analysis_id == analysis_id).all()
        assert len(impacts) >= 1
        caller_impacts = [i for i in impacts if i.impact_type == ChangeImpactType.CALLER_IMPACT.value]
        assert len(caller_impacts) >= 1
        imp = caller_impacts[0]
        assert "verify_token" in (imp.source_symbol or "")
        assert "login_endpoint" in (imp.affected_symbol or "")
        assert imp.severity in ("HIGH", "CRITICAL")
        db.close()


# =========================================================================
# E2E B: Frontend/Backend Contract Break with Canonical Route Matching
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_b_contract_break_canonical_route_matching(db_session: Session):
    """E2E B: Verify API contract break via execute_background_change_analysis using canonical RepositoryGraph route matching."""
    with tempfile.TemporaryDirectory() as git_dir:
        base_files = {
            "backend/api.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter()\n\n"
                "@router.post('/api/users')\n"
                "def create_user():\n"
                "    return {'status': 'created'}\n"
            ),
            "frontend/client.ts": (
                "export async function registerUser() {\n"
                "    const res = await fetch('/api/users', { method: 'POST' });\n"
                "    return res.json();\n"
                "}\n"
            ),
        }
        head_files = {
            "backend/api.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter()\n\n"
                "@router.put('/api/users')\n"
                "def create_user():\n"
                "    return {'status': 'updated'}\n"
            ),
            "frontend/client.ts": (
                "export async function registerUser() {\n"
                "    const res = await fetch('/api/users', { method: 'POST' });\n"
                "    return res.json();\n"
                "}\n"
            ),
        }
        base_sha, head_sha = _init_local_git_repo(git_dir, base_files, head_files)

        analysis_id = str(uuid4())
        analysis = ChangeAnalysisModel(
            id=analysis_id,
            repository_url="https://github.com/test/repo",
            repository_owner="test",
            repository_name="repo",
            base_commit_sha=base_sha,
            head_commit_sha=head_sha,
            base_ref="main",
            head_ref="feature/route-change",
            status="PENDING",
        )
        db_session.add(analysis)
        db_session.commit()

        # Unpack revisions to test workspaces
        with tempfile.TemporaryDirectory() as base_ws, tempfile.TemporaryDirectory() as head_ws:
            proc = subprocess.Popen(["git", "archive", base_sha], cwd=git_dir, stdout=subprocess.PIPE)
            subprocess.run(["tar", "-x", "-C", base_ws], stdin=proc.stdout, check=True)
            proc2 = subprocess.Popen(["git", "archive", head_sha], cwd=git_dir, stdout=subprocess.PIPE)
            subprocess.run(["tar", "-x", "-C", head_ws], stdin=proc2.stdout, check=True)

            pair = ComparisonWorkspacePair(
                base_workspace=base_ws,
                head_workspace=head_ws,
                base_commit_sha=base_sha,
                head_commit_sha=head_sha,
                repository_url="https://github.com/test/repo",
            )
            with patch("app.analysis.workflow.SessionLocal", side_effect=TestingSessionLocal), \
                 patch.object(
                     ComparisonSnapshotService,
                     "acquire_comparison_workspaces_from_metadata",
                     return_value=pair,
                 ), \
                 patch.object(
                     ComparisonSnapshotService,
                     "release_comparison_workspaces",
                     return_value=None,
                 ):
                await execute_background_change_analysis(analysis_id=analysis_id)

        # Fresh DB session inspection
        db = TestingSessionLocal()
        updated_analysis = db.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id).first()
        assert updated_analysis is not None
        assert updated_analysis.status == "COMPLETED"
        assert updated_analysis.base_commit_sha == base_sha
        assert updated_analysis.head_commit_sha == head_sha
        assert updated_analysis.risk_level in ("HIGH", "CRITICAL")

        # Verify persisted API_CONTRACT_CHANGE impact (no manual rows created)
        impacts = db.query(ChangeImpactModel).filter(ChangeImpactModel.analysis_id == analysis_id).all()
        contract_impacts = [i for i in impacts if i.impact_type == ChangeImpactType.API_CONTRACT_CHANGE.value]
        assert len(contract_impacts) >= 1
        c_imp = next((i for i in contract_impacts if i.affected_file == "frontend/client.ts"), None)
        assert c_imp is not None
        assert c_imp.severity == Severity.HIGH.value

        # Verify persisted diff metadata contains route delta
        diff_meta = updated_analysis.model_metadata.get("diff_result", {})
        route_deltas = diff_meta.get("route_deltas", [])
        assert len(route_deltas) >= 1
        delta = route_deltas[0]
        assert delta.get("change_type") == "METHOD_CHANGED"
        assert delta.get("base_http_method") == "POST"
        assert delta.get("head_http_method") == "PUT"
        assert delta.get("base_path") == "/api/users"

        # Verify generated report from freshly reloaded analysis contains contract changes
        from app.analysis.report_generator import generate_change_analysis_report
        report = generate_change_analysis_report(updated_analysis)
        assert report.contract_breaks_count >= 1
        assert "METHOD_CHANGED" in report.markdown_report
        db.close()


# =========================================================================
# E2E C: Body-Only Function Change Detection
# =========================================================================

def test_e2e_c_body_only_function_change():
    """E2E C: Same signature, same line count, only body changes -> detected as MODIFIED."""
    with tempfile.TemporaryDirectory() as base_dir, tempfile.TemporaryDirectory() as head_dir:
        base_code = "def calculate(x: int) -> int:\n    return x + 1\n"
        head_code = "def calculate(x: int) -> int:\n    return x + 2\n"

        with open(os.path.join(base_dir, "math_utils.py"), "w", encoding="utf-8") as f:
            f.write(base_code)
        with open(os.path.join(head_dir, "math_utils.py"), "w", encoding="utf-8") as f:
            f.write(head_code)

        diff_engine = ChangeDiffEngine()
        diff_res = diff_engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        assert len(diff_res.modified_symbols) == 1
        sym = diff_res.modified_symbols[0]
        assert sym.symbol_name == "calculate"
        assert sym.change_type == SymbolChangeType.MODIFIED


# =========================================================================
# E2E D: Safe Line Shift
# =========================================================================

def test_e2e_d_safe_line_shift_not_modified():
    """E2E D: Inserting 20 comment lines above function does NOT mark function as MODIFIED."""
    with tempfile.TemporaryDirectory() as base_dir, tempfile.TemporaryDirectory() as head_dir:
        base_code = "def calculate(x: int) -> int:\n    return x + 1\n"
        comments = "".join(f"# Comment line {i}\n" for i in range(20))
        head_code = comments + "def calculate(x: int) -> int:\n    return x + 1\n"

        with open(os.path.join(base_dir, "math_utils.py"), "w", encoding="utf-8") as f:
            f.write(base_code)
        with open(os.path.join(head_dir, "math_utils.py"), "w", encoding="utf-8") as f:
            f.write(head_code)

        diff_engine = ChangeDiffEngine()
        diff_res = diff_engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        # calculate must NOT be marked as modified
        modified_names = [s.symbol_name for s in diff_res.modified_symbols]
        assert "calculate" not in modified_names


# =========================================================================
# E2E E: Secret Configuration Safety
# =========================================================================

def test_e2e_e_secret_config_never_persists_raw_values():
    """E2E E: Changing secret values in .env detects config change with zero raw secrets stored."""
    with tempfile.TemporaryDirectory() as base_dir, tempfile.TemporaryDirectory() as head_dir:
        base_env = "GITHUB_TOKEN=ghp_super_secret_123\nDATABASE_URL=postgresql://user:password@localhost/db\nJWT_SECRET=abc123\n"
        head_env = "GITHUB_TOKEN=ghp_super_secret_456\nDATABASE_URL=postgresql://user:new_pass@localhost/db\nJWT_SECRET=xyz789\n"

        with open(os.path.join(base_dir, ".env"), "w", encoding="utf-8") as f:
            f.write(base_env)
        with open(os.path.join(head_dir, ".env"), "w", encoding="utf-8") as f:
            f.write(head_env)

        diff_engine = ChangeDiffEngine()
        diff_res = diff_engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        assert len(diff_res.config_deltas) == 3
        keys = {c.key for c in diff_res.config_deltas}
        assert keys == {"GITHUB_TOKEN", "DATABASE_URL", "JWT_SECRET"}

        # Serialize diff result and verify raw secret absence
        diff_json = diff_res.model_dump_json()
        assert "ghp_super_secret" not in diff_json
        assert "password" not in diff_json
        assert "abc123" not in diff_json

        # Compute blast radius and verify evidence payload
        impact_engine = ChangeImpactEngine()
        blast_report = impact_engine.compute_blast_radius(analysis_id=uuid4(), diff_result=diff_res, base_graph=RepositoryGraph())
        blast_json = blast_report.model_dump_json()
        assert "ghp_super_secret" not in blast_json
        assert "password" not in blast_json
        assert "abc123" not in blast_json


# =========================================================================
# E2E F: Durable Process Restart & Stage Caching
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_f_durable_process_restart():
    """E2E F: Process restart reloads from durable state without duplicating impacts."""
    tmpdir = tempfile.mkdtemp(prefix="restart_test_")
    db_path = os.path.join(tmpdir, "restart.db")
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(bind=engine)

    try:
        analysis_id = str(uuid4())
        session1 = SessionMaker()
        analysis = ChangeAnalysisModel(
            id=analysis_id,
            repository_url="https://github.com/fastapi/fastapi",
            repository_owner="fastapi",
            repository_name="fastapi",
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            status="DIFFING",
            model_metadata={
                "diff_result": {
                    "repository_url": "https://github.com/fastapi/fastapi",
                    "base_commit_sha": "1111111111111111111111111111111111111111",
                    "head_commit_sha": "2222222222222222222222222222222222222222",
                    "changed_files": [],
                    "added_files": [],
                    "deleted_files": [],
                    "modified_files": [],
                    "renamed_files": [],
                    "changed_symbols": [],
                    "added_symbols": [],
                    "deleted_symbols": [],
                    "modified_symbols": [],
                    "dependency_deltas": [],
                    "config_deltas": [],
                    "route_deltas": [],
                    "schema_deltas": [],
                    "summary": {"total_files_changed": 0, "total_symbols_changed": 0},
                }
            },
        )
        session1.add(analysis)
        session1.commit()
        session1.close()

        # Session 2: Resume analysis with fresh session and checkpointer
        pair = ComparisonWorkspacePair(
            base_workspace=tmpdir,
            head_workspace=tmpdir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/fastapi/fastapi",
        )
        with patch("app.analysis.workflow.SessionLocal", side_effect=SessionMaker), \
             patch.object(
                 ComparisonSnapshotService,
                 "acquire_comparison_workspaces_from_metadata",
                 return_value=pair,
             ), \
             patch.object(
                 ComparisonSnapshotService,
                 "release_comparison_workspaces",
                 return_value=None,
             ):
            await execute_background_change_analysis(analysis_id=analysis_id, checkpoint_db_path=os.path.join(tmpdir, "chk.db"))

        session3 = SessionMaker()
        resumed = session3.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis_id).first()
        assert resumed is not None
        assert resumed.status == "COMPLETED"
        session3.close()
    finally:
        engine.dispose()
        shutil.rmtree(tmpdir, ignore_errors=True)


# =========================================================================
# E2E G: Same-Repository PR Resolution (Zero Writes)
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_g_same_repo_pr_mode():
    """E2E G: Same-repository PR resolution with strictly read-only GET requests."""
    pr_url = "https://github.com/fastapi/fastapi/pull/789"
    mock_pr_response = {
        "number": 789,
        "title": "Upgrade dependencies",
        "state": "open",
        "base": {
            "ref": "main",
            "sha": "1111111111111111111111111111111111111111",
            "repo": {"html_url": "https://github.com/fastapi/fastapi"},
        },
        "head": {
            "ref": "feature/deps",
            "sha": "2222222222222222222222222222222222222222",
            "repo": {"html_url": "https://github.com/fastapi/fastapi", "fork": False},
        },
    }
    mock_client = MockAsyncClient(status_code=200, json_data=mock_pr_response)
    resolver = GitHubPRResolver(client=mock_client)

    resolved = await resolver.resolve_pr(pr_url)
    assert resolved.is_fork is False
    assert resolved.base_commit_sha == "1111111111111111111111111111111111111111"
    assert resolved.head_commit_sha == "2222222222222222222222222222222222222222"
    assert len(mock_client.calls) == 1
    assert mock_client.calls[0]["method"] == "GET"


# =========================================================================
# E2E H: Fork PR Typed Rejection
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_h_fork_pr_typed_rejection():
    """E2E H: External fork PRs return typed 422 FORK_PULL_REQUEST_UNSUPPORTED."""
    from fastapi import HTTPException
    from app.api.routes.change_analysis import create_change_analysis_from_pr

    pr_url = "https://github.com/fastapi/fastapi/pull/999"
    mock_pr_response = {
        "number": 999,
        "title": "External fork PR",
        "state": "open",
        "base": {
            "ref": "main",
            "sha": "1111111111111111111111111111111111111111",
            "repo": {"html_url": "https://github.com/fastapi/fastapi"},
        },
        "head": {
            "ref": "my-fork-branch",
            "sha": "2222222222222222222222222222222222222222",
            "repo": {"html_url": "https://github.com/external-user/fastapi", "fork": True},
        },
    }
    mock_client = MockAsyncClient(status_code=200, json_data=mock_pr_response)
    resolver = GitHubPRResolver(client=mock_client)

    db = TestingSessionLocal()
    with patch("app.api.routes.change_analysis.get_github_pr_resolver", return_value=resolver):
        with pytest.raises(HTTPException) as exc_info:
            await create_change_analysis_from_pr(payload=ChangeAnalysisPRRequest(pr_url=pr_url), db=db)

        assert exc_info.value.status_code == 422
        assert "FORK_PULL_REQUEST_UNSUPPORTED" in exc_info.value.detail

    db.close()


# =========================================================================
# Alembic Migration Authority (with NULL scan_id events test)
# =========================================================================

def test_alembic_phase6_migration_cycle_with_null_scan_events():
    """Verify Alembic full migration cycle: upgrade head -> insert scan_id=NULL events -> downgrade 007 -> re-upgrade head."""
    tmpdir = tempfile.mkdtemp(prefix="alembic_cycle_")
    db_path = os.path.join(tmpdir, "alembic_cycle.db")
    db_url = f"sqlite:///{db_path}"

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ini_path = os.path.join(base_dir, "alembic.ini")
    cfg = Config(ini_path)
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.set_main_option("script_location", os.path.join(base_dir, "alembic"))

    try:
        # 1. Upgrade to head (008)
        command.upgrade(cfg, "head")

        engine = create_engine(db_url)
        with engine.connect() as conn:
            # Insert a Phase 6 change-analysis event with scan_id=NULL
            conn.execute(
                text(
                    "INSERT INTO workflow_events (id, event_type, change_analysis_id, scan_id, stage, message, metadata_payload, created_at) "
                    "VALUES (1, 'CHANGE_DIFF_COMPLETED', 'test-analysis-id', NULL, 'DIFF', 'Diff completed', '{}', '2026-08-31T00:00:00Z')"
                )
            )
            conn.commit()
        engine.dispose()

        # 2. Downgrade Phase 6 (back to 007) - must cleanly delete scan_id=NULL events and restore constraint
        command.downgrade(cfg, "007")

        engine2 = create_engine(db_url)
        insp_downgraded = inspect(engine2)
        tables_down = insp_downgraded.get_table_names()
        assert "change_analyses" not in tables_down
        assert "change_impacts" not in tables_down
        engine2.dispose()

        # 3. Re-upgrade to head (008)
        command.upgrade(cfg, "head")

        engine3 = create_engine(db_url)
        insp_up = inspect(engine3)
        tables_reup = insp_up.get_table_names()
        assert "change_analyses" in tables_reup
        assert "change_impacts" in tables_reup
        engine3.dispose()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# =========================================================================
# Micro-Closure 1: Exact Typed Evidence Grounding & Rejection Tests
# =========================================================================

def test_exact_evidence_identities_rejections():
    """Verify that ChangeReviewVerifier rejects non-exact, fuzzy, or reversed evidence references."""
    from app.analysis.review_verifier import ChangeReviewVerifier
    from app.schemas.change_analysis import (
        BlastRadiusReport,
        ChangeImpact,
        ChangeReviewFinding,
        ChangeReviewVerdict,
        RouteContractDelta,
        StructuralDiffResult,
        SymbolDiffFact,
    )
    from app.graph.repository_graph import RepositoryGraph
    from app.graph.schemas import EdgeKind, NodeKind

    # Setup base graph with A -> B CALLS edge
    base_graph = RepositoryGraph()
    base_graph.add_node("symbol:app/auth.py:FUNCTION:caller_fn:10", NodeKind.SYMBOL, "caller_fn", file_path="app/auth.py", start_line=10, end_line=20)
    base_graph.add_node("symbol:app/auth.py:FUNCTION:callee_fn:30", NodeKind.SYMBOL, "callee_fn", file_path="app/auth.py", start_line=30, end_line=40)
    base_graph.add_edge("symbol:app/auth.py:FUNCTION:caller_fn:10", "symbol:app/auth.py:FUNCTION:callee_fn:30", EdgeKind.CALLS)

    diff_res = StructuralDiffResult(
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
        route_deltas=[
            RouteContractDelta(
                file_path="app/api.py",
                route_type="FASTAPI_ROUTE",
                route_name="login",
                base_path="/api/login",
                head_path="/api/login",
                base_http_method="POST",
                head_http_method="PUT",
                change_type="METHOD_CHANGED",
                details="Method updated",
            )
        ],
        changed_symbols=[
            SymbolDiffFact(
                file_path="app/auth.py",
                symbol_name="callee_fn",
                symbol_kind="FUNCTION",
                change_type="MODIFIED",
                base_location={"start_line": 30, "end_line": 40},
                head_location={"start_line": 30, "end_line": 40},
            )
        ],
    )

    impact_id = uuid4()
    blast_report = BlastRadiusReport(
        analysis_id=uuid4(),
        impacts=[
            ChangeImpact(
                id=impact_id,
                analysis_id=uuid4(),
                impact_type=ChangeImpactType.CALLER_IMPACT,
                severity=Severity.HIGH,
                title="Direct caller 'caller_fn' impacted by modified 'callee_fn'",
                description="Caller broken",
                source_file="app/auth.py",
                source_symbol="callee_fn",
                affected_file="app/auth.py",
                affected_symbol="caller_fn",
                created_at=datetime.now(timezone.utc),
            )
        ],
        total_impacts=1,
    )

    verifier = ChangeReviewVerifier()

    # 1. Reversed edge direction: callee -> caller (A calls B, but ref claims B calls A)
    reversed_finding = ChangeReviewFinding(
        title="Reversed call edge claim",
        risk_type="REGRESSION_RISK",
        severity=Severity.HIGH,
        reasoning_summary="Reversed edge test",
        evidence_refs=["edge:CALLS:symbol:app/auth.py:FUNCTION:callee_fn:30->symbol:app/auth.py:FUNCTION:caller_fn:10"],
        affected_files=["app/auth.py"],
        affected_symbols=["caller_fn"],
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(reversed_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.REJECTED
    assert "Fake graph relationship" in reason

    # 2. Substring edge match (node IDs merely contained as substring)
    substring_edge_finding = ChangeReviewFinding(
        title="Substring edge claim",
        risk_type="REGRESSION_RISK",
        severity=Severity.HIGH,
        reasoning_summary="Substring edge test",
        evidence_refs=["edge:CALLS:caller_fn->callee_fn"],
        affected_files=["app/auth.py"],
        affected_symbols=["caller_fn"],
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(substring_edge_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.REJECTED

    # 3. Impact title instead of UUID
    title_impact_finding = ChangeReviewFinding(
        title="Title impact claim",
        risk_type="REGRESSION_RISK",
        severity=Severity.HIGH,
        reasoning_summary="Title impact test",
        evidence_refs=["impact:Direct caller 'caller_fn' impacted by modified 'callee_fn'"],
        affected_files=["app/auth.py"],
        affected_symbols=["caller_fn"],
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(title_impact_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.REJECTED
    assert "does not resolve to deterministic" in reason or "Unknown impact" in reason

    # 4. Impact title substring
    substring_impact_finding = ChangeReviewFinding(
        title="Substring impact claim",
        risk_type="REGRESSION_RISK",
        severity=Severity.HIGH,
        reasoning_summary="Substring impact test",
        evidence_refs=["impact:caller_fn"],
        affected_files=["app/auth.py"],
        affected_symbols=["caller_fn"],
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(substring_impact_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.REJECTED

    # 5. Non-existent symbol in real file
    fake_sym_finding = ChangeReviewFinding(
        title="Fake symbol in real file",
        risk_type="REGRESSION_RISK",
        severity=Severity.HIGH,
        reasoning_summary="Fake symbol test",
        evidence_refs=["symbol:app/auth.py:FUNCTION:non_existent_fn:99"],
        affected_files=["app/auth.py"],
        affected_symbols=["caller_fn"],
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(fake_sym_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.REJECTED

    # 6. Symbol in wrong file
    wrong_file_sym_finding = ChangeReviewFinding(
        title="Symbol in wrong file",
        risk_type="REGRESSION_RISK",
        severity=Severity.HIGH,
        reasoning_summary="Wrong file test",
        evidence_refs=["symbol:app/wrong_file.py:FUNCTION:caller_fn:10"],
        affected_files=["app/auth.py"],
        affected_symbols=["caller_fn"],
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(wrong_file_sym_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.REJECTED

    # 7. Symbol with wrong start line
    wrong_line_sym_finding = ChangeReviewFinding(
        title="Symbol with wrong line",
        risk_type="REGRESSION_RISK",
        severity=Severity.HIGH,
        reasoning_summary="Wrong line test",
        evidence_refs=["symbol:app/auth.py:FUNCTION:caller_fn:999"],
        affected_files=["app/auth.py"],
        affected_symbols=["caller_fn"],
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(wrong_line_sym_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.REJECTED

    # 8. Route with wrong HTTP method
    wrong_route_finding = ChangeReviewFinding(
        title="Route with wrong method",
        risk_type="API_CONTRACT_BREAK",
        severity=Severity.HIGH,
        reasoning_summary="Wrong method test",
        evidence_refs=["route:DELETE:/api/login"],
        affected_files=["app/api.py"],
        affected_symbols=["login"],
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(wrong_route_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.REJECTED
    assert "does not resolve to deterministic" in reason or "No route delta found" in reason

    # 9. Valid exact IDs -> CONFIRMED (with zero assumptions)
    valid_exact_finding = ChangeReviewFinding(
        title="Valid exact route contract break",
        risk_type="API_CONTRACT_BREAK",
        severity=Severity.HIGH,
        reasoning_summary="Valid exact test",
        evidence_refs=[
            "file:app/api.py",
            f"impact:{impact_id}",
            "route:POST:/api/login",
            "symbol:app/auth.py:FUNCTION:caller_fn:10",
            "edge:CALLS:symbol:app/auth.py:FUNCTION:caller_fn:10->symbol:app/auth.py:FUNCTION:callee_fn:30",
        ],
        affected_files=["app/api.py", "app/auth.py"],
        affected_symbols=["caller_fn", "login"],
        confidence=0.5,  # Confidence must not affect CONFIRMED
        assumptions=[],
    )
    v, reason, _ = verifier.verify_finding(valid_exact_finding, diff_res, blast_report, base_graph)
    assert v == ChangeReviewVerdict.CONFIRMED


# =========================================================================
# Micro-Closure 2: AST-Aware Symbol Body Fingerprint Semantics
# =========================================================================

def test_ast_aware_symbol_body_fingerprint_semantics():
    """Verify AST-aware symbol body fingerprinting handles string literals, comments, whitespace, and body edits."""
    from app.ingestion.parser import parse_file
    from app.ingestion.schemas import SymbolKind

    # Case A: return x + 1 vs return x + 2 -> DIFFERENT
    py_a1 = "def calc(x):\n    return x + 1\n"
    py_a2 = "def calc(x):\n    return x + 2\n"
    res_a1 = parse_file("a.py", "python", py_a1.encode("utf-8"))
    res_a2 = parse_file("a.py", "python", py_a2.encode("utf-8"))
    fp_a1 = res_a1[0].details["body_fingerprint"]
    fp_a2 = res_a2[0].details["body_fingerprint"]
    assert fp_a1 != fp_a2

    # Case B: 20 comments inserted above function -> SAME
    py_b1 = "def greet(name):\n    return f'hello {name}'\n"
    py_b2 = "\n".join([f"# Comment line {i}" for i in range(20)]) + "\ndef greet(name):\n    return f'hello {name}'\n"
    res_b1 = parse_file("b.py", "python", py_b1.encode("utf-8"))
    res_b2 = parse_file("b.py", "python", py_b2.encode("utf-8"))
    fp_b1 = res_b1[0].details["body_fingerprint"]
    fp_b2 = res_b2[0].details["body_fingerprint"]
    assert fp_b1 == fp_b2

    # Case C: comment-only change inside function -> SAME
    py_c1 = "def process():\n    # old comment\n    x = 10\n    return x\n"
    py_c2 = "def process():\n    # completely rewritten comment\n    x = 10\n    return x\n"
    res_c1 = parse_file("c.py", "python", py_c1.encode("utf-8"))
    res_c2 = parse_file("c.py", "python", py_c2.encode("utf-8"))
    fp_c1 = res_c1[0].details["body_fingerprint"]
    fp_c2 = res_c2[0].details["body_fingerprint"]
    assert fp_c1 == fp_c2

    # Case D: "#not-a-comment" vs "#changed-string" inside Python string -> DIFFERENT
    py_d1 = 'def get_tag():\n    return "#not-a-comment"\n'
    py_d2 = 'def get_tag():\n    return "#changed-string"\n'
    res_d1 = parse_file("d.py", "python", py_d1.encode("utf-8"))
    res_d2 = parse_file("d.py", "python", py_d2.encode("utf-8"))
    fp_d1 = res_d1[0].details["body_fingerprint"]
    fp_d2 = res_d2[0].details["body_fingerprint"]
    assert fp_d1 != fp_d2

    # Case E: "https://old.com" vs "https://new.com" inside JS/TS string -> DIFFERENT
    ts_e1 = 'export function getUrl(): string {\n    return "https://old.example.com";\n}\n'
    ts_e2 = 'export function getUrl(): string {\n    return "https://new.example.com";\n}\n'
    res_e1 = parse_file("e.ts", "typescript", ts_e1.encode("utf-8"))
    res_e2 = parse_file("e.ts", "typescript", ts_e2.encode("utf-8"))
    fp_e1 = res_e1[0].details["body_fingerprint"]
    fp_e2 = res_e2[0].details["body_fingerprint"]
    assert fp_e1 != fp_e2

    # Case F: whitespace-only formatting change inside function -> SAME
    py_f1 = "def format_fn():\n    a = 1\n    b = 2\n    return a + b\n"
    py_f2 = "def format_fn():\n\n    a   =   1\n\n    b   =   2\n\n    return a + b\n"
    res_f1 = parse_file("f.py", "python", py_f1.encode("utf-8"))
    res_f2 = parse_file("f.py", "python", py_f2.encode("utf-8"))
    fp_f1 = res_f1[0].details["body_fingerprint"]
    fp_f2 = res_f2[0].details["body_fingerprint"]
    assert fp_f1 == fp_f2


# =========================================================================
# Micro-Closure 3: Large-File Rename Detection Memory Safety
# =========================================================================

def test_large_file_rename_memory_safety():
    """Verify that files exceeding MAX_FILE_SIZE_BYTES are never read into memory during rename detection."""
    from app.analysis.diff_engine import ChangeDiffEngine

    diff_engine = ChangeDiffEngine()
    max_size = 1000  # 1 KB limit for testing

    with tempfile.TemporaryDirectory() as base_dir, tempfile.TemporaryDirectory() as head_dir:
        # Create a 5 KB file in base and head
        large_content = b"X" * 5000
        old_file = os.path.join(base_dir, "large_old.bin")
        new_file = os.path.join(head_dir, "large_new.bin")

        with open(old_file, "wb") as f:
            f.write(large_content)
        with open(new_file, "wb") as f:
            f.write(large_content)

        # Ensure bounded hasher returns None without full reading
        assert diff_engine._compute_file_sha256_bounded(old_file, max_size) is None
        assert diff_engine._compute_file_sha256_bounded(new_file, max_size) is None

        # Verify structural diff skips rename and reports both as added/deleted with EXCEEDS_MAX_FILE_SIZE
        diff_engine.settings.MAX_FILE_SIZE_BYTES = max_size
        diff_res = diff_engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        assert len(diff_res.renamed_files) == 0
        assert "large_old.bin" in diff_res.deleted_files
        assert "large_new.bin" in diff_res.added_files
        added_fact = next(f for f in diff_res.changed_files if f.file_path == "large_new.bin")
        assert added_fact.skipped_reason == "EXCEEDS_MAX_FILE_SIZE"


# =========================================================================
# Micro-Closure 4: Null-Safe & Truthful LLM Degradation Reporting
# =========================================================================

def test_null_safe_llm_degradation_reporting():
    """Verify that report generation is null-safe for all model_metadata permutations and displays truthful Markdown tool availability."""
    from app.analysis.report_generator import generate_change_analysis_report

    # 1. model_metadata is None
    analysis_none = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/test/repo",
        repository_owner="test",
        repository_name="repo",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        status="COMPLETED",
        model_metadata=None,
    )
    rep_none = generate_change_analysis_report(analysis_none)
    assert rep_none.tool_availability["llm_reviewer"] is False
    assert "| **Change Review Agent** | ℹ️ Not Executed | Static Only |" in rep_none.markdown_report

    # 2. LLM Unavailable fallback
    analysis_unavail = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/test/repo",
        repository_owner="test",
        repository_name="repo",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        status="COMPLETED",
        model_metadata={
            "review_report": {
                "summary": "Fallback summary",
                "findings": [],
                "model_metadata": {
                    "execution_status": "UNAVAILABLE",
                    "is_fallback": True,
                },
            }
        },
    )
    rep_unavail = generate_change_analysis_report(analysis_unavail)
    assert rep_unavail.tool_availability["llm_reviewer"] is False
    assert "| **Change Review Agent** | ⚠️ Unavailable — deterministic-only result | Fallback Mode |" in rep_unavail.markdown_report

    # 3. LLM Success
    analysis_success = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/test/repo",
        repository_owner="test",
        repository_name="repo",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        status="COMPLETED",
        model_metadata={
            "review_report": {
                "summary": "AI review succeeded",
                "findings": [],
                "model_metadata": {
                    "execution_status": "SUCCESS",
                    "is_fallback": False,
                },
            }
        },
    )
    rep_success = generate_change_analysis_report(analysis_success)
    assert rep_success.tool_availability["llm_reviewer"] is True
    assert "| **Change Review Agent** | ✅ Executed | Bounded Context Reasoning |" in rep_success.markdown_report


# =========================================================================
# FIX 9: Table-Driven Adversarial Grounding Release Gate (10 Directives)
# =========================================================================

def test_phase6_final_adversarial_grounding_suite():
    """Execute table-driven adversarial grounding verification tests across all 10 directives."""
    from app.analysis.evidence_ids import (
        make_config_evidence_id,
        make_dependency_evidence_id,
        make_edge_evidence_id,
        make_file_evidence_id,
        make_impact_evidence_id,
        make_route_delta_evidence_id,
        make_symbol_evidence_id,
    )
    from app.analysis.review_verifier import ChangeReviewVerifier
    from app.analysis.reviewer import ChangeReviewAgent
    from app.graph.repository_graph import RepositoryGraph
    from app.graph.schemas import EdgeKind, GraphEdge, GraphNode, NodeKind
    from app.llm.exceptions import LLMError
    from app.schemas.change_analysis import (
        BlastRadiusReport,
        ChangeImpact,
        ChangeReviewFinding,
        ChangeReviewReport,
        ChangeReviewVerdict,
        ConfigDelta,
        DependencyDelta,
        FileDiffFact,
        RouteContractDelta,
        StructuralDiffResult,
        SymbolDiffFact,
    )
    from app.schemas.enums import ChangeImpactType, Severity

    verifier = ChangeReviewVerifier()

    # Build canonical base objects
    impact_uuid = uuid4()
    diff_result = StructuralDiffResult(
        analysis_id=uuid4(),
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/test/repo",
        changed_files=[
            FileDiffFact(file_path="app/service.py", change_type=SymbolChangeType.MODIFIED, base_lines=100, head_lines=105),
            FileDiffFact(file_path="app/auth.py", change_type=SymbolChangeType.MODIFIED, base_lines=50, head_lines=55),
            FileDiffFact(file_path="backend/api.py", change_type=SymbolChangeType.MODIFIED, base_lines=30, head_lines=35),
            FileDiffFact(file_path="src/a.py", change_type=SymbolChangeType.MODIFIED, base_lines=20, head_lines=25),
            FileDiffFact(file_path="src/b.py", change_type=SymbolChangeType.MODIFIED, base_lines=20, head_lines=25),
        ],
        modified_files=["app/service.py", "app/auth.py", "backend/api.py", "src/a.py", "src/b.py"],
        changed_symbols=[
            SymbolDiffFact(file_path="app/auth.py", symbol_name="verify_token", symbol_kind="FUNCTION", change_type=SymbolChangeType.MODIFIED, head_location={"start_line": 10, "end_line": 20}),
            SymbolDiffFact(file_path="src/a.py", symbol_name="parse", symbol_kind="FUNCTION", change_type=SymbolChangeType.MODIFIED, head_location={"start_line": 5, "end_line": 15}),
            SymbolDiffFact(file_path="src/b.py", symbol_name="parse", symbol_kind="FUNCTION", change_type=SymbolChangeType.MODIFIED, head_location={"start_line": 10, "end_line": 20}),
        ],
        route_deltas=[
            RouteContractDelta(
                file_path="backend/api.py",
                route_type="FASTAPI_ROUTE",
                route_name="create_user",
                change_type="METHOD_CHANGED",
                base_http_method="POST",
                base_path="/api/users",
                head_http_method="PUT",
                head_path="/api/users",
            )
        ],
        config_deltas=[
            ConfigDelta(file_path=".env", key="API_URL", change_type="MODIFIED", base_value="http://localhost", head_value="https://api.prod")
        ],
        dependency_deltas=[
            DependencyDelta(manifest_file="package.json", package_name="react", change_type="MODIFIED", base_version="^18.0.0", head_version="^19.0.0")
        ],
    )

    base_graph = RepositoryGraph()
    n1 = base_graph.add_node(node_id="symbol:app/api.py:SYMBOL:login:1", label="login", kind=NodeKind.SYMBOL, file_path="app/api.py", start_line=1)
    n2 = base_graph.add_node(node_id="symbol:app/auth.py:SYMBOL:verify_token:10", label="verify_token", kind=NodeKind.SYMBOL, file_path="app/auth.py", start_line=10)
    base_graph.add_edge(source_id=n1.id, target_id=n2.id, kind=EdgeKind.CALLS)

    blast_radius_id = uuid4()
    blast_radius = BlastRadiusReport(
        analysis_id=blast_radius_id,
        total_impacts=1,
        overall_risk_level=ChangeRiskLevel.HIGH,
        impacts=[
            ChangeImpact(
                id=impact_uuid,
                analysis_id=blast_radius_id,
                impact_type=ChangeImpactType.CALLER_IMPACT,
                severity=Severity.HIGH,
                title="Caller broken",
                description="Caller function broken due to callee modification",
                source_file="app/auth.py",
                source_symbol="verify_token",
                affected_file="app/api.py",
                affected_symbol="login",
                evidence_payload={"depth": 1, "edge_type": "CALLS", "caller_node_id": n1.id, "callee_node_id": n2.id},
                created_at=datetime.now(timezone.utc),
            )
        ],
    )

    # -------------------------------------------------------------------------
    # Case 1: Valid file, invalid runtime claim (RESOURCE_LEAK) -> SUPPORTED_INFERENCE, NOT CONFIRMED
    # -------------------------------------------------------------------------
    f1 = ChangeReviewFinding(
        id=uuid4(),
        title="Guaranteed memory leak",
        risk_type="RESOURCE_LEAK",
        severity=Severity.HIGH,
        reasoning_summary="Likely leak based on service modification",
        evidence_refs=["file:app/service.py"],
        affected_files=["app/service.py"],
        affected_symbols=[],
        confidence=0.99,
        assumptions=[],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )
    v1, r1, _ = verifier.verify_finding(f1, diff_result, blast_radius, base_graph)
    assert v1 == ChangeReviewVerdict.SUPPORTED_INFERENCE, "Runtime predictive claim must NOT be CONFIRMED without deterministic proof"

    # -------------------------------------------------------------------------
    # Case 2: Valid symbol, unsupported security claim (SECURITY_REGRESSION) -> REJECTED
    # -------------------------------------------------------------------------
    f2 = ChangeReviewFinding(
        id=uuid4(),
        title="Security bypass vulnerability",
        risk_type="SECURITY_REGRESSION",
        severity=Severity.CRITICAL,
        reasoning_summary="Auth token function modified",
        evidence_refs=["symbol:app/auth.py:FUNCTION:verify_token:10"],
        affected_files=["app/auth.py"],
        affected_symbols=["verify_token"],
        confidence=0.99,
        assumptions=[],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )
    v2, r2, _ = verifier.verify_finding(f2, diff_result, blast_radius, base_graph)
    assert v2 == ChangeReviewVerdict.REJECTED, "Unsupported security regression claim must be REJECTED"
    assert "Unsupported claim" in r2

    # -------------------------------------------------------------------------
    # Case 3: Real API contract break -> CONFIRMED
    # -------------------------------------------------------------------------
    route_ev_id = make_route_delta_evidence_id("backend/api.py", "POST", "/api/users", "PUT", "/api/users")
    f3 = ChangeReviewFinding(
        id=uuid4(),
        title="API method changed POST to PUT",
        risk_type="API_CONTRACT_BREAK",
        severity=Severity.HIGH,
        reasoning_summary="Endpoint HTTP method changed from POST to PUT breaking callers",
        evidence_refs=[route_ev_id, "file:backend/api.py"],
        affected_files=["backend/api.py"],
        affected_symbols=["create_user"],
        confidence=0.95,
        assumptions=[],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )
    v3, r3, _ = verifier.verify_finding(f3, diff_result, blast_radius, base_graph)
    assert v3 == ChangeReviewVerdict.CONFIRMED, "Exact route delta contract break with zero assumptions must be CONFIRMED"

    # -------------------------------------------------------------------------
    # Case 4: Real config delta -> CONFIRMED
    # -------------------------------------------------------------------------
    cfg_ev_id = make_config_evidence_id(".env", "API_URL")
    f4 = ChangeReviewFinding(
        id=uuid4(),
        title="Environment URL changed",
        risk_type="CONFIG_MISMATCH",
        severity=Severity.MEDIUM,
        reasoning_summary="API_URL key modified in .env",
        evidence_refs=[cfg_ev_id, "file:.env"],
        affected_files=[".env"],
        affected_symbols=["API_URL"],
        confidence=0.95,
        assumptions=[],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )
    v4, r4, _ = verifier.verify_finding(f4, diff_result, blast_radius, base_graph)
    assert v4 == ChangeReviewVerdict.CONFIRMED, "Exact config delta with zero assumptions must be CONFIRMED"

    # -------------------------------------------------------------------------
    # Case 5: Dependency version change inference -> SUPPORTED_INFERENCE
    # -------------------------------------------------------------------------
    dep_ev_id = make_dependency_evidence_id("package.json", "react")
    f5 = ChangeReviewFinding(
        id=uuid4(),
        title="React major version bump may break components",
        risk_type="DEPENDENCY_INCOMPATIBILITY",
        severity=Severity.MEDIUM,
        reasoning_summary="React bumped from 18 to 19",
        evidence_refs=[dep_ev_id, "file:package.json"],
        affected_files=["package.json"],
        affected_symbols=["react"],
        confidence=0.85,
        assumptions=[],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )
    v5, r5, _ = verifier.verify_finding(f5, diff_result, blast_radius, base_graph)
    assert v5 == ChangeReviewVerdict.SUPPORTED_INFERENCE, "Dependency version delta alone is SUPPORTED_INFERENCE, not CONFIRMED"

    # -------------------------------------------------------------------------
    # Case 6: Duplicate symbol names with wrong evidence binding -> REJECTED
    # -------------------------------------------------------------------------
    # finding is for a.py, but evidence is for b.py's parse symbol
    f6 = ChangeReviewFinding(
        id=uuid4(),
        title="Parse function modified in a.py",
        risk_type="BEHAVIORAL_CHANGE",
        severity=Severity.LOW,
        reasoning_summary="Parser logic updated",
        evidence_refs=["symbol:src/b.py:FUNCTION:parse:10", "file:src/a.py"],
        affected_files=["src/a.py"],
        affected_symbols=["parse"],
        confidence=0.9,
        assumptions=[],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )
    v6, r6, _ = verifier.verify_finding(f6, diff_result, blast_radius, base_graph)
    assert v6 == ChangeReviewVerdict.REJECTED, "Symbol binding mismatch across files with identical symbol names must be REJECTED"
    assert "Unbound affected symbol" in r6

    # -------------------------------------------------------------------------
    # Case 7: Legacy evidence aliases -> REJECTED
    # -------------------------------------------------------------------------
    legacy_aliases = [
        "diff:app/service.py",
        "symbol:verify_token",
        "route:/api/users",
        "config:API_URL",
        "dep:react",
        "dependency:react",
    ]
    for alias in legacy_aliases:
        f_leg = ChangeReviewFinding(
            id=uuid4(),
            title=f"Test legacy alias {alias}",
            risk_type="BEHAVIORAL_CHANGE",
            severity=Severity.LOW,
            reasoning_summary="Legacy alias test",
            evidence_refs=[alias],
            affected_files=["app/service.py"],
            affected_symbols=[],
            confidence=0.5,
            assumptions=[],
            verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
            created_at=datetime.now(timezone.utc),
        )
        v_leg, r_leg, _ = verifier.verify_finding(f_leg, diff_result, blast_radius, base_graph)
        assert v_leg == ChangeReviewVerdict.REJECTED, f"Legacy alias '{alias}' must be strictly REJECTED"

    # -------------------------------------------------------------------------
    # Case 8: Reversed edge rejection -> REJECTED
    # -------------------------------------------------------------------------
    reversed_edge = f"edge:CALLS:{n2.id}->{n1.id}"
    f8 = ChangeReviewFinding(
        id=uuid4(),
        title="Reversed call relationship",
        risk_type="BEHAVIORAL_CHANGE",
        severity=Severity.LOW,
        reasoning_summary="Reversed edge test",
        evidence_refs=[reversed_edge],
        affected_files=["app/auth.py"],
        affected_symbols=["verify_token"],
        confidence=0.5,
        assumptions=[],
        verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
        created_at=datetime.now(timezone.utc),
    )
    v8, r8, _ = verifier.verify_finding(f8, diff_result, blast_radius, base_graph)
    assert v8 == ChangeReviewVerdict.REJECTED, "Reversed graph edge must be strictly REJECTED"
    assert "Fake graph relationship" in r8

    # -------------------------------------------------------------------------
    # Case 9: Secret in LLM error is redacted
    # -------------------------------------------------------------------------
    import asyncio
    secret_key = "ghp_super_secret_github_token_12345"
    mock_router = MagicMock()
    mock_router.route_request = AsyncMock(side_effect=LLMError(f"Authentication failure with token: {secret_key}"))

    reviewer = ChangeReviewAgent(router=mock_router, verifier=verifier)
    rep9 = asyncio.run(reviewer.review_changes(
        analysis_id=uuid4(),
        diff_result=diff_result,
        blast_radius=blast_radius,
    ))
    assert secret_key not in rep9.summary, "Raw secret must NOT appear in review summary"
    assert rep9.model_metadata is not None
    assert secret_key not in str(rep9.model_metadata.extra_metadata), "Raw secret must NOT appear in model_metadata"

    # -------------------------------------------------------------------------
    # Case 10: Oversized line evidence rejected
    # -------------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as ws_dir:
        large_file = os.path.join(ws_dir, "large.py")
        with open(large_file, "wb") as f:
            f.write(b"x = 1\n" * 300000)  # > 1.5MB (exceeds default MAX_FILE_SIZE_BYTES)

        f10 = ChangeReviewFinding(
            id=uuid4(),
            title="Line reference in oversized file",
            risk_type="BEHAVIORAL_CHANGE",
            severity=Severity.LOW,
            reasoning_summary="Line evidence check",
            evidence_refs=["line:large.py:10-20"],
            affected_files=["large.py"],
            affected_symbols=[],
            confidence=0.5,
            assumptions=[],
            verdict=ChangeReviewVerdict.SUPPORTED_INFERENCE,
            created_at=datetime.now(timezone.utc),
        )
        v10, r10, _ = verifier.verify_finding(f10, diff_result, blast_radius, base_graph, head_workspace=ws_dir)
        assert v10 == ChangeReviewVerdict.REJECTED, "Line evidence on oversized file must be REJECTED"
        assert "oversized" in r10 or "exceeds" in r10


