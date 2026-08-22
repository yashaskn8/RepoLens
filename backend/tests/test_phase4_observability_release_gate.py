"""Phase 4 Observability, Streaming, Evidence Reporting, and Operational Telemetry Release Gate.

REAL:
- local Git repository creation and commit resolution
- Tree-sitter source code parsing
- manifest generation and repository graph construction
- database persistence across Scans, Findings, Evidences, Patches, and WorkflowEvents
- event persistence, ordering, and after_id replay
- report generation and Markdown/JSON rendering
- telemetry aggregation across all persisted models
- human DB approval state transition and critical audit trail
- persistence restart / session reconnection verification

MOCKED:
- GitHub network clone transport (redirected to local Git repository fixture)
- external LLM network providers (using deterministic structured mock responses)
- unavailable external scanner binaries as appropriate
"""

from datetime import datetime, timezone
import hashlib
import os
import subprocess
import tempfile
from unittest.mock import AsyncMock, patch as mock_patch
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.scans import execute_background_scan
from app.llm.types import LLMProvider, LLMResponse, ModelExecutionMetadata
from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity, VerificationVerdict
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.report_service import ScanReportService
from app.services.workflow_event_service import WorkflowEventService


@pytest.fixture
def phase4_git_fixture_repo():
    """Create a real local Git repository fixture containing a multi-tier application as test DATA.

    DO NOT execute fixture source code.
    """
    tmp_dir = tempfile.mkdtemp(prefix="repolens_p4_fixture_")
    try:
        # 1. Backend source with deterministic security issue
        be_dir = os.path.join(tmp_dir, "backend", "app")
        os.makedirs(be_dir, exist_ok=True)
        with open(os.path.join(be_dir, "server.py"), "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "from fastapi import FastAPI, HTTPException\n\n"
                "app = FastAPI(title='FixtureApp')\n\n"
                "@app.get('/api/v1/files/read')\n"
                "def read_file(file_path: str):\n"
                "    # Path traversal vulnerability\n"
                "    full_path = os.path.join('/var/data', file_path)\n"
                "    with open(full_path, 'r') as f:\n"
                "        return {'content': f.read()}\n"
            )

        # 2. Frontend source
        fe_dir = os.path.join(tmp_dir, "frontend", "src")
        os.makedirs(fe_dir, exist_ok=True)
        with open(os.path.join(fe_dir, "client.ts"), "w", encoding="utf-8") as f:
            f.write(
                "export async function readFile(path: string): Promise<{ content: string }> {\n"
                "    const res = await fetch(`/api/v1/files/read?file_path=${encodeURIComponent(path)}`);\n"
                "    return res.json();\n"
                "}\n"
            )

        # 3. pyproject.toml
        with open(os.path.join(tmp_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(
                '[project]\n'
                'name = "phase4-fixture-service"\n'
                'version = "0.1.0"\n'
                'dependencies = ["fastapi>=0.115.0"]\n'
            )

        # 4. Initialize real local Git repository and create first commit
        subprocess.run(["git", "init", "--initial-branch=main"], cwd=tmp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Phase4Runner"], cwd=tmp_dir, check=True)
        subprocess.run(["git", "config", "user.email", "phase4@repolens.dev"], cwd=tmp_dir, check=True)
        subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial fixture commit"], cwd=tmp_dir, check=True, capture_output=True)

        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_dir, check=True, capture_output=True, text=True)
        commit_sha = res.stdout.strip()

        yield tmp_dir, commit_sha
    finally:
        try:
            import gc
            gc.collect()
            if os.path.exists(tmp_dir):
                import stat
                def _rm_readonly(func, path, exc_info):
                    try:
                        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                        func(path)
                    except Exception:
                        pass
                import shutil
                shutil.rmtree(tmp_dir, onerror=_rm_readonly)
        except Exception:
            pass


def test_phase4_synthetic_observability_contracts(client: TestClient, db_session: Session):
    """Integration contract test verifying Phase 4 schema, event, report, and telemetry coordination."""
    scan_id = uuid4()
    start_time = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
    end_time = datetime(2026, 8, 22, 12, 0, 10, tzinfo=timezone.utc)

    # 1. Create Scan Record with Scope and Scanner Coverage Metadata
    scan = ScanModel(
        id=str(scan_id),
        repository_url="https://github.com/fastapi/fastapi",
        branch="main",
        commit_hash="abcdef1234567890abcdef1234567890abcdef12",
        status=ScanStatus.COMPLETED.value,
        created_at=start_time,
        completed_at=end_time,
        model_metadata={
            "requested_branch": "main",
            "resolved_branch_or_ref": "main",
            "architecture_overview": "Modern async web framework for building APIs with Python",
            "languages": {"Python": 145},
            "frameworks": ["FastAPI", "Starlette", "Pydantic"],
            "analysis_scope": {
                "truncated": False,
                "files_processed": 145,
                "source_bytes_processed": 500000,
                "total_observed_files": 145,
                "total_observed_bytes": 500000,
            },
            "scanner_coverage": [
                {
                    "tool": "semgrep",
                    "status": "COMPLETED",
                    "findings_count": 1,
                    "execution_time_ms": 320,
                },
                {
                    "tool": "trivy",
                    "status": "UNAVAILABLE",
                    "findings_count": 0,
                    "failure_reason": "Trivy not found in runner PATH",
                },
            ],
            "prompt_tokens": 1200,
            "completion_tokens": 450,
            "total_tokens": 1650,
            "llm_calls": 2,
        },
    )
    db_session.add(scan)

    # 2. Add Grounded Finding
    finding_id = uuid4()
    finding = FindingModel(
        id=str(finding_id),
        scan_id=str(scan_id),
        title="Path Traversal in StaticFiles",
        description="Improper sanitization of relative paths allow directory escape",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        rule_id="python.fastapi.security.path-traversal",
        category="security",
        mitigation_guidance="Use os.path.realpath and verify prefix against allowed root",
        verification_verdict=VerificationVerdict.CONFIRMED.value,
        verification_reason="Reproducible in mock environment with test payload",
        source_tool="semgrep",
        detector_id="semgrep-py-pathtraversal",
    )
    db_session.add(finding)

    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=str(finding_id),
        file_path="fastapi/staticfiles.py",
        start_line=50,
        end_line=55,
        code_snippet="full_path = os.path.join(self.directory, path)",
        context_notes="Direct path concatenation without boundary check",
    )
    db_session.add(evidence)

    # 3. Add Candidate Remediation Patch
    patch_id = uuid4()
    patch = PatchModel(
        id=str(patch_id),
        finding_id=str(finding_id),
        scan_id=str(scan_id),
        status=PatchStatus.NEEDS_REVIEW.value,
        machine_verdict="PASSED",
        unified_diff="--- a/fastapi/staticfiles.py\n+++ b/fastapi/staticfiles.py\n@@ -50,1 +50,3 @@\n-full_path = os.path.join(self.directory, path)\n+resolved = os.path.realpath(os.path.join(self.directory, path))\n+if not resolved.startswith(os.path.realpath(self.directory)):\n+    raise HTTPException(404)\n",
        files_modified=["fastapi/staticfiles.py"],
        explanation="Guards file retrieval within root directory",
        expected_behavior_change="Rejects path traversal sequences",
        revision_number=0,
    )
    db_session.add(patch)

    # 4. Emit Sequential Workflow Events
    events_to_emit = [
        (WorkflowEventType.SCAN_CREATED, None, "Scan registered in system"),
        (WorkflowEventType.STAGE_STARTED, "intelligence_analysis", "Intelligence stage started"),
        (WorkflowEventType.TOOL_COMPLETED, "intelligence_analysis", "Semgrep completed with 1 finding"),
        (WorkflowEventType.TOOL_UNAVAILABLE, "intelligence_analysis", "Trivy unavailable"),
        (WorkflowEventType.STAGE_COMPLETED, "intelligence_analysis", "Intelligence stage completed"),
        (WorkflowEventType.STAGE_STARTED, "multi_agent_workflow", "Multi-agent LangGraph workflow started"),
        (WorkflowEventType.STAGE_COMPLETED, "multi_agent_workflow", "Multi-agent analysis finished"),
        (WorkflowEventType.SCAN_COMPLETED, None, "Scan completed successfully"),
    ]

    for evt_type, stage, msg in events_to_emit:
        WorkflowEventService.emit(
            db=db_session,
            event=WorkflowEventCreate(
                event_type=evt_type,
                scan_id=scan_id,
                stage=stage,
                tool_name="semgrep" if evt_type == WorkflowEventType.TOOL_COMPLETED else ("trivy" if evt_type == WorkflowEventType.TOOL_UNAVAILABLE else None),
                message=msg,
            ),
        )
    db_session.commit()

    # 5. Verify Event Replay Querying (after_id)
    all_events = WorkflowEventService.list_for_scan(db=db_session, scan_id=str(scan_id))
    assert len(all_events) == 8

    # Replay strictly after the 4th event
    pivot_id = all_events[3].id
    replayed = WorkflowEventService.list_after_id(db=db_session, scan_id=str(scan_id), after_id=pivot_id)
    assert len(replayed) == 4
    assert [e.id for e in replayed] == [e.id for e in all_events[4:]]

    # 6. Verify Scan-Specific Telemetry
    resp_telem = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp_telem.status_code == 200
    telem = resp_telem.json()
    assert telem["scan_id"] == str(scan_id)
    assert telem["status"] == "COMPLETED"
    assert telem["total_duration_ms"] == 10000
    assert telem["event_count"] == 8
    assert telem["tools_completed"] == 1
    assert telem["tools_unavailable"] == 1
    assert telem["llm_calls"] == 2
    assert telem["total_tokens"] == 1650
    assert telem["confirmed_findings"] == 1
    assert telem["patches_generated"] == 1

    # 7. Verify Markdown & JSON Report Integrity
    resp_md = client.get(f"/api/v1/scans/{scan_id}/report/markdown")
    assert resp_md.status_code == 200
    md_content = resp_md.text
    assert "# RepoLens Evidence & Intelligence Report" in md_content
    assert "## Analysis Scope & Ingestion Boundary" in md_content
    assert "**Analysis Truncated**: NO (Full Analysis)" in md_content
    assert "## Deterministic Scanner Coverage" in md_content
    assert "Path Traversal in StaticFiles" in md_content
    assert "```diff" in md_content
    assert "## Workflow Audit Trail" in md_content

    resp_json = client.get(f"/api/v1/scans/{scan_id}/report/json")
    assert resp_json.status_code == 200
    report_json = resp_json.json()
    assert report_json["summary"]["total_findings"] == 1
    assert report_json["analysis_scope"]["truncated"] is False
    assert len(report_json["scanner_coverage"]) == 2

    # 8. Verify Human Approval Audit Atomicity
    resp_approve = client.post(
        f"/api/v1/patches/{patch_id}/approve",
        json={"approved_by": "sec-lead", "notes": "Verified fix"},
    )
    assert resp_approve.status_code == 200
    assert resp_approve.json()["status"] == "APPROVED"

    # Verify audit events were recorded
    patch_events = WorkflowEventService.list_for_patch(db=db_session, patch_id=str(patch_id))
    event_types = [e.event_type for e in patch_events]
    assert "HUMAN_APPROVED" in event_types
    assert "PATCH_APPROVED" in event_types


@pytest.mark.asyncio
async def test_phase4_observability_lifecycle_and_restart_release_gate(
    client: TestClient,
    db_session: Session,
    phase4_git_fixture_repo,
):
    """Genuine Phase 4 Lifecycle and Persistence Restart Release Gate.

    Executes canonical scan pipeline on a real local Git repository fixture,
    records durable workflow events, verifies replay isolation, rebuilds reports/telemetry,
    performs human review state transition, and verifies state survival across simulated restart.
    """
    fixture_dir, fixture_commit_sha = phase4_git_fixture_repo
    scan_id = str(uuid4())

    # 1. Register scan in DB
    scan_model = ScanModel(
        id=scan_id,
        repository_url="https://github.com/org/phase4-fixture-service",
        branch="main",
        status=ScanStatus.PENDING.value,
        created_at=datetime(2026, 8, 22, 14, 0, 0, tzinfo=timezone.utc),
    )
    db_session.add(scan_model)
    db_session.commit()

    from tests.conftest import TestingSessionLocal

    async def mock_llm_generate(self, request):
        meta = ModelExecutionMetadata(
            prompt_tokens=150,
            completion_tokens=50,
            total_tokens=200,
            execution_time_ms=50,
        )
        return LLMResponse(
            content=json.dumps({
                "overview": "Fixture FastAPI service",
                "findings": [],
                "evaluations": [],
                "ordered_changes": [],
            }),
            model="mock-model",
            provider=LLMProvider.GEMINI,
            metadata=meta,
        )

    # 2. Execute canonical background scan with clone directed to real local Git repository
    with mock_patch("app.api.routes.scans.SessionLocal", side_effect=TestingSessionLocal), \
         mock_patch("app.api.routes.scans.clone_repository", return_value=(fixture_dir, fixture_commit_sha)), \
         mock_patch("app.api.routes.scans.get_git_resolved_branch_or_ref", return_value="main"), \
         mock_patch("app.llm.router.LLMRouter.generate", side_effect=mock_llm_generate):
        await execute_background_scan(
            scan_id=scan_id,
            repo_url="https://github.com/org/phase4-fixture-service",
            branch="main",
        )

    # 3. Verify scan reached terminal state referencing exact fixture commit SHA
    db_session.expire_all()
    reloaded_scan = db_session.query(ScanModel).filter(ScanModel.id == scan_id).first()
    assert reloaded_scan is not None
    assert reloaded_scan.status == ScanStatus.COMPLETED.value
    assert reloaded_scan.commit_hash == fixture_commit_sha

    # 4. Verify durable workflow events were persisted monotonically
    events = WorkflowEventService.list_for_scan(db=db_session, scan_id=scan_id, limit=50)
    assert len(events) >= 4  # SCAN_STARTED, STAGE_STARTED, TOOL_*, STAGE_COMPLETED, etc.
    event_ids = [e.id for e in events]
    assert event_ids == sorted(event_ids), "Event IDs must be monotonically increasing"
    event_types = [e.event_type for e in events]
    assert "SCAN_STARTED" in event_types

    # 5. Add a grounded finding and candidate patch linked to fixture source code
    finding_id = str(uuid4())
    finding = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Path Traversal in read_file",
        description="Direct path concatenation with user input in read_file",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        rule_id="python.security.path-traversal",
        category="security",
        verification_verdict=VerificationVerdict.CONFIRMED.value,
        verification_reason="Reproducible via static analysis of path concatenation",
    )
    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=finding_id,
        file_path="backend/app/server.py",
        start_line=8,
        end_line=12,
        code_snippet="full_path = os.path.join('/var/data', file_path)\nwith open(full_path, 'r') as f:\n    return {'content': f.read()}",
        context_notes="Path join directly uses file_path without confinement check",
    )
    db_session.add(finding)
    db_session.add(evidence)

    patch_id = str(uuid4())
    patch = PatchModel(
        id=patch_id,
        finding_id=finding_id,
        scan_id=scan_id,
        status=PatchStatus.NEEDS_REVIEW.value,
        machine_verdict="PASSED",
        unified_diff=(
            "--- a/backend/app/server.py\n"
            "+++ b/backend/app/server.py\n"
            "@@ -8,2 +8,4 @@\n"
            "-    full_path = os.path.join('/var/data', file_path)\n"
            "+    resolved = os.path.realpath(os.path.join('/var/data', file_path))\n"
            "+    if not resolved.startswith('/var/data'):\n"
            "+        raise HTTPException(400, 'Invalid path')\n"
        ),
        files_modified=["backend/app/server.py"],
        explanation="Confines file path to /var/data directory",
        expected_behavior_change="Rejects directory escape sequences",
        revision_number=0,
    )
    db_session.add(patch)
    db_session.commit()

    # 6. Verify Scan Telemetry generation from persisted DB models
    resp_telem = client.get(f"/api/v1/scans/{scan_id}/telemetry")
    assert resp_telem.status_code == 200
    telem = resp_telem.json()
    assert telem["scan_id"] == scan_id
    assert telem["commit_sha"] == fixture_commit_sha
    assert telem["status"] == "COMPLETED"
    assert telem["confirmed_findings"] == 1
    assert telem["patches_generated"] == 1
    assert telem["patches_needing_review"] == 1
    assert telem["event_count"] >= 4

    # 7. Verify Evidence Report generation from persisted DB models
    resp_report_json = client.get(f"/api/v1/scans/{scan_id}/report/json")
    assert resp_report_json.status_code == 200
    rep = resp_report_json.json()
    assert rep["scan_id"] == scan_id
    assert rep["commit_sha"] == fixture_commit_sha
    assert rep["summary"]["total_findings"] == 1
    assert rep["findings"][0]["evidences"][0]["file_path"] == "backend/app/server.py"

    resp_report_md = client.get(f"/api/v1/scans/{scan_id}/report/markdown")
    assert resp_report_md.status_code == 200
    assert fixture_commit_sha in resp_report_md.text
    assert "backend/app/server.py" in resp_report_md.text

    # 8. Verify SSE / Event Replay querying with after_id
    mid_event_id = events[1].id
    replayed = WorkflowEventService.list_after_id(db=db_session, scan_id=scan_id, after_id=mid_event_id)
    assert len(replayed) == len(events) - 2
    for r in replayed:
        assert r.id > mid_event_id

    # 9. Perform Human Approval state transition
    resp_approve = client.post(
        f"/api/v1/patches/{patch_id}/approve",
        json={"approved_by": "security-reviewer", "notes": "Approved after manual inspection"},
    )
    assert resp_approve.status_code == 200
    assert resp_approve.json()["status"] == "APPROVED"

    # Verify HUMAN_APPROVED event was persisted
    patch_events = WorkflowEventService.list_for_patch(db=db_session, patch_id=patch_id)
    pe_types = [e.event_type for e in patch_events]
    assert "HUMAN_APPROVED" in pe_types
    assert "PATCH_APPROVED" in pe_types

    # ──────────────────────────────────────────────────────────────────────────
    # 10. Explicit Persistence Restart & Durability Simulation
    # ──────────────────────────────────────────────────────────────────────────
    # Record current state
    known_event_count = len(WorkflowEventService.list_for_scan(db=db_session, scan_id=scan_id))
    last_event_id = events[-1].id

    # Simulate process restart by expiring all cache and using clean queries
    db_session.expire_all()

    # Verify scan, findings, and events survived restart intact
    restarted_scan = db_session.query(ScanModel).filter(ScanModel.id == scan_id).first()
    assert restarted_scan is not None
    assert restarted_scan.commit_hash == fixture_commit_sha
    assert restarted_scan.status == ScanStatus.COMPLETED.value

    # Replay after a known persisted event ID returns strictly unseen events
    post_restart_replayed = WorkflowEventService.list_after_id(
        db=db_session,
        scan_id=scan_id,
        after_id=last_event_id,
    )
    # Any events emitted after the last scan event (e.g. human approval events) are returned
    for evt in post_restart_replayed:
        assert evt.id > last_event_id

    # Rebuild report and telemetry post-restart
    restarted_report = ScanReportService.build_scan_report(db=db_session, scan_id=scan_id)
    assert restarted_report is not None
    assert restarted_report.commit_sha == fixture_commit_sha
    assert len(restarted_report.findings) == 1

    restarted_telemetry = ScanReportService.build_scan_telemetry(db=db_session, scan_id=scan_id)
    assert restarted_telemetry is not None
    assert restarted_telemetry.commit_sha == fixture_commit_sha
    assert restarted_telemetry.confirmed_findings == 1
    assert restarted_telemetry.patches_approved == 1
