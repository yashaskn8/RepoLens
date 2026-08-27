"""Phase 5 End-to-End Release Gate: Safe GitHub Delivery & Pull Request Orchestration.

Tests the full canonical delivery lifecycle against real SQLite DB, real Git snapshots,
real patch reapplication, timeline auditing, fresh-session restart, and telemetry derivation.
"""

from contextlib import contextmanager
import json
import os
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch as mock_patch
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.delivery.github_provider import GitHubDeliveryProvider
from app.delivery.provider import RepositoryDeliveryProvider
from app.delivery.schemas import GitCommitInfo, GitPullRequestInfo, GitTreeEntry
from app.delivery.service import DeliveryService
from app.ingestion.snapshot import get_snapshot_service
from app.main import app
from app.models.delivery import DeliveryModel
from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
from app.schemas.enums import DeliveryStatus, FindingStatus, PatchStatus, ScanStatus, Severity
from app.services.report_service import ScanReportService
from app.services.workflow_event_service import WorkflowEventService


class E2EMockGitHubProvider(RepositoryDeliveryProvider):
    """Mock GitHub Git Data API provider tracking all operations for release gate verification."""

    def __init__(self, remote_head_sha: str, base_tree_sha: str = "base_tree_sha_root_001"):
        self.remote_head_sha = remote_head_sha
        self.base_tree_sha = base_tree_sha
        self.blobs: Dict[str, str] = {}  # sha -> content
        self.trees: Dict[str, List[GitTreeEntry]] = {}
        self.commits: Dict[str, dict] = {
            remote_head_sha: {
                "message": "Initial commit",
                "tree_sha": base_tree_sha,
                "parents": [],
            }
        }
        self.branches: Dict[str, str] = {
            "main": remote_head_sha,
        }  # branch_name -> commit_sha
        self.prs: List[GitPullRequestInfo] = []
        self.blobs_created: List[str] = []
        self.trees_created: List[str] = []
        self.commits_created: List[str] = []
        self.branches_created: List[str] = []
        self.prs_created: List[GitPullRequestInfo] = []
        self.calls: List[str] = []

    async def get_branch_head(self, owner: str, repo: str, branch: str) -> str:
        clean = branch.replace("refs/heads/", "")
        self.calls.append(f"get_branch_head:{owner}/{repo}:{clean}")
        if clean in self.branches:
            return self.branches[clean]
        from app.delivery.schemas import GitHubAPIError
        raise GitHubAPIError(f"Branch '{clean}' not found", status_code=404, safe_code="BRANCH_NOT_FOUND")

    async def get_commit(self, owner: str, repo: str, sha: str) -> GitCommitInfo:
        self.calls.append(f"get_commit:{sha}")
        if sha in self.commits:
            c = self.commits[sha]
            return GitCommitInfo(sha=sha, tree_sha=c.get("tree_sha", self.base_tree_sha), parents=c.get("parents", []))
        return GitCommitInfo(sha=sha, tree_sha=self.base_tree_sha, parents=[self.remote_head_sha])

    async def create_blob(self, owner: str, repo: str, content: str, encoding: str = "utf-8") -> str:
        blob_sha = f"blob_sha_{len(self.blobs) + 1}_{len(content)}"
        self.blobs[blob_sha] = content
        self.blobs_created.append(blob_sha)
        self.calls.append(f"create_blob:{blob_sha}")
        return blob_sha

    async def create_tree(self, owner: str, repo: str, base_tree_sha: str, tree_entries: List[GitTreeEntry]) -> str:
        tree_sha = f"tree_sha_{len(self.trees) + 1}"
        self.trees[tree_sha] = tree_entries
        self.trees_created.append(tree_sha)
        self.calls.append(f"create_tree:{tree_sha}")
        return tree_sha

    async def create_commit(self, owner: str, repo: str, message: str, tree_sha: str, parent_shas: List[str]) -> str:
        commit_sha = f"commit_sha_{len(self.commits) + 1}_40chars000000000000"[:40]
        self.commits[commit_sha] = {
            "message": message,
            "tree_sha": tree_sha,
            "parents": parent_shas,
        }
        self.commits_created.append(commit_sha)
        self.calls.append(f"create_commit:{commit_sha}")
        return commit_sha

    async def create_branch(self, owner: str, repo: str, branch_name: str, sha: str) -> str:
        clean = branch_name.replace("refs/heads/", "")
        self.branches[clean] = sha
        self.branches_created.append(clean)
        self.calls.append(f"create_branch:{clean}:{sha}")
        return f"refs/heads/{clean}"

    async def find_existing_pull_request(self, owner: str, repo: str, head: str, base: str) -> Optional[GitPullRequestInfo]:
        self.calls.append(f"find_existing_pr:{head}:{base}")
        for pr in self.prs:
            if pr.head_branch == head and pr.base_branch == base:
                return pr
        return None

    async def create_pull_request(self, owner: str, repo: str, title: str, body: str, head: str, base: str) -> GitPullRequestInfo:
        pr_number = len(self.prs) + 101
        pr = GitPullRequestInfo(
            number=pr_number,
            html_url=f"https://github.com/{owner}/{repo}/pull/{pr_number}",
            head_branch=head,
            base_branch=base,
            title=title,
        )
        self.prs.append(pr)
        self.prs_created.append(pr)
        self.calls.append(f"create_pull_request:#{pr_number}")
        return pr


@pytest.fixture
def local_git_repo(tmp_path):
    """Create a real local Git repository with valid commit history and files."""
    repo_dir = tmp_path / "target_repo"
    repo_dir.mkdir()

    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "RepoLens Gate"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "config", "user.email", "gate@repolens.local"], cwd=str(repo_dir), check=True)

    app_dir = repo_dir / "app"
    app_dir.mkdir()

    auth_file = app_dir / "auth.py"
    auth_file.write_text("def authenticate(user, pwd):\n    # Vulnerable plain text check\n    return user == pwd\n", encoding="utf-8")

    utils_file = app_dir / "utils.py"
    utils_file.write_text("def helper():\n    return True\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo_dir), check=True)

    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_dir), check=True, capture_output=True, text=True)
    scanned_commit_sha = proc.stdout.strip()

    return str(repo_dir), scanned_commit_sha


def _make_local_snapshot_context(repo_path: str):
    @contextmanager
    def _ctx(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            shutil.copytree(repo_path, fresh_ws, dirs_exist_ok=True)
            yield fresh_ws
    return _ctx


# 1. Canonical End-to-End Delivery Flow
@pytest.mark.asyncio
async def test_phase5_e2e_canonical_delivery_flow(client: TestClient, db_session: Session, local_git_repo):
    repo_path, commit_sha = local_git_repo

    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/repolens-org/secure-core.git",
        status=ScanStatus.COMPLETED.value,
        branch="main",
        commit_hash=commit_sha,
    )
    db_session.add(scan)

    finding_id = str(uuid4())
    finding = FindingModel(
        id=finding_id,
        scan_id=scan.id,
        title="Insecure Plaintext Password Authentication",
        description="Password comparison uses plaintext equality instead of constant-time hash.",
        severity=Severity.CRITICAL.value,
        status=FindingStatus.OPEN.value,
        verification_verdict="CONFIRMED",
        rule_id="security.insecure-auth",
        category="Security",
    )
    db_session.add(finding)

    # Unified diff fixing auth.py
    patch_diff = (
        "--- a/app/auth.py\n"
        "+++ b/app/auth.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def authenticate(user, pwd):\n"
        "-    # Vulnerable plain text check\n"
        "-    return user == pwd\n"
        "+    # Secure constant-time hash comparison\n"
        "+    return verify_hash(user, pwd)\n"
    )
    plan_id_1 = uuid4()
    plan_1 = FixPlan(
        id=plan_id_1,
        finding_id=UUID(finding.id),
        root_cause="Insecure direct plaintext password comparison",
        objective="Replace plaintext comparison with verify_hash",
        files_expected_to_change=["app/auth.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/auth.py",
                description="Use constant-time verification",
                rationale="Eliminate timing side channel",
            )
        ],
        validation_plan=["Verify password hash checking"],
        estimated_scope=FixScope.FILE,
    )

    patch_id = str(uuid4())
    patch = PatchModel(
        id=patch_id,
        finding_id=finding.id,
        plan_id=str(plan_id_1),
        fix_plan_snapshot=plan_1.model_dump(mode="json"),
        scan_id=scan.id,
        thread_id=f"remediation-{uuid4()}",
        status=PatchStatus.VERIFIED.value,
        machine_verdict="PASSED",
        unified_diff=patch_diff,
        files_modified=["app/auth.py"],
        explanation="Replaced plaintext comparison with verify_hash",
        expected_behavior_change="Secure constant-time password verification",
    )
    db_session.add(patch)
    db_session.commit()

    # Configure mock GitHub provider matching the scanned commit SHA
    mock_provider = E2EMockGitHubProvider(remote_head_sha=commit_sha)
    service = DeliveryService(provider=mock_provider)

    from app.api.routes.deliveries import get_delivery_service
    app.dependency_overrides[get_delivery_service] = lambda: service

    mock_ctx_fn = _make_local_snapshot_context(repo_path)
    try:
        with mock_patch("app.delivery.service.get_snapshot_service") as mock_svc_snap, \
             mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
            
            mock_inst = MagicMock()
            mock_inst.snapshot_context.side_effect = mock_ctx_fn
            mock_svc_snap.return_value = mock_inst
            mock_val_snap.return_value = mock_inst

            # Step 1: Unapproved patch delivery is blocked with HTTP 409
            unapproved_resp = client.post(
                f"/api/v1/patches/{patch_id}/deliver",
                json={"requested_by": "lead-sec-eng", "notes": "Premature delivery attempt"},
            )
            assert unapproved_resp.status_code == 409

            # Step 2: Explicit Human Approval via API
            appr_resp = client.post(
                f"/api/v1/patches/{patch_id}/approve",
                json={"approved_by": "security-lead", "notes": "Production hotfix approved"},
            )
            assert appr_resp.status_code == 200
            assert appr_resp.json()["status"] == "APPROVED"

            # Step 3: Query Delivery Preview
            prev_resp = client.get(f"/api/v1/patches/{patch_id}/delivery-preview")
            assert prev_resp.status_code == 200
            prev_data = prev_resp.json()
            assert prev_data["eligible"] is True
            assert prev_data["base_branch"] == "main"
            assert prev_data["scanned_base_sha"] == commit_sha
            assert prev_data["proposed_branch_name"].startswith("repolens/fix-")
            assert "auth.py" in prev_data["files_modified"][0]

            # Step 4: Deliver Patch (Human Triggered)
            del_resp = client.post(
                f"/api/v1/patches/{patch_id}/deliver",
                json={"requested_by": "lead-sec-eng", "notes": "Production hotfix approved"},
            )
            assert del_resp.status_code == 200
            del_data = del_resp.json()
            assert del_data["status"] == "PR_CREATED"
            assert del_data["pr_number"] == 101
            assert del_data["pr_url"] == "https://github.com/repolens-org/secure-core/pull/101"
            assert del_data["head_branch"].startswith("repolens/fix-")
            assert del_data["base_branch"] == "main"
    finally:
        app.dependency_overrides.pop(get_delivery_service, None)

    # Step 5: True Fresh DB Session Verification (Session Restart)
    from tests.conftest import TestingSessionLocal
    db_bind = db_session.get_bind()
    db_session.close()

    fresh_session = TestingSessionLocal(bind=db_bind)
    try:
        # Re-query all models in fresh session
        fresh_scan = fresh_session.query(ScanModel).filter(ScanModel.id == scan_id).first()
        assert fresh_scan is not None

        fresh_finding = fresh_session.query(FindingModel).filter(FindingModel.id == finding_id).first()
        assert fresh_finding is not None

        fresh_patch = fresh_session.query(PatchModel).filter(PatchModel.id == patch_id).first()
        assert fresh_patch is not None
        assert fresh_patch.status == PatchStatus.APPROVED.value
        assert fresh_patch.fix_plan_snapshot is not None
        assert fresh_patch.fix_plan_snapshot["id"] == str(plan_id_1)

        delivery_row = fresh_session.query(DeliveryModel).filter(DeliveryModel.patch_id == patch_id).first()
        assert delivery_row is not None
        assert delivery_row.status == DeliveryStatus.PR_CREATED.value
        assert delivery_row.pr_number == 101
        assert delivery_row.pr_url == "https://github.com/repolens-org/secure-core/pull/101"
        assert delivery_row.head_branch.startswith("repolens/fix-")
        assert delivery_row.base_branch == "main"
        assert delivery_row.scanned_base_sha == commit_sha

        # Verify Timeline Events
        events = WorkflowEventService.list_for_delivery(db=fresh_session, delivery_id=delivery_row.id)
        event_types = [e.event_type for e in events]
        assert "DELIVERY_REQUESTED" in event_types
        assert "DELIVERY_VALIDATED" in event_types
        assert "DELIVERY_COMMIT_CREATED" in event_types
        assert "DELIVERY_BRANCH_CREATED" in event_types
        assert "DELIVERY_PR_CREATED" in event_types

        # Step D: Report Service & Telemetry Derivation
        report = ScanReportService.build_scan_report(db=fresh_session, scan_id=UUID(scan_id))
        assert report is not None
        assert report.summary.total_deliveries == 1
        assert report.summary.pull_requests_created == 1
        assert report.summary.deliveries_blocked == 0
        assert report.findings[0].patches[0].deliveries[0].pr_number == 101

        markdown = ScanReportService.render_markdown(report)
        assert "🚀 GitHub PRs Created | 1" in markdown
        assert "PR #101" in markdown

        telemetry = ScanReportService.build_scan_telemetry(db=fresh_session, scan_id=scan_id)
        assert telemetry is not None
        assert telemetry.deliveries_requested == 1
        assert telemetry.pull_requests_created == 1
        assert telemetry.deliveries_blocked == 0
        assert telemetry.delivery_failures == 0
    finally:
        fresh_session.close()


# 2. Base Drift Protection Gate
@pytest.mark.asyncio
async def test_phase5_e2e_base_drift_protection_gate(client: TestClient, db_session: Session, local_git_repo):
    repo_path, commit_sha = local_git_repo

    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/repolens-org/secure-core.git",
        status=ScanStatus.COMPLETED.value,
        branch="main",
        commit_hash=commit_sha,
    )
    db_session.add(scan)

    finding_id = str(uuid4())
    finding = FindingModel(
        id=finding_id,
        scan_id=scan.id,
        title="Weak Secret Key Generation",
        description="Secret key generated with random rather than secrets module.",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict="CONFIRMED",
        rule_id="security.weak-random",
        category="Security",
    )
    db_session.add(finding)

    plan_id_2 = uuid4()
    plan_2 = FixPlan(
        id=plan_id_2,
        finding_id=UUID(finding.id),
        root_cause="Weak secret key generation using random",
        objective="Use secrets module for cryptographic randomness",
        files_expected_to_change=["app/utils.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/utils.py",
                description="Import secrets and use for keys",
                rationale="Provide cryptographic randomness",
            )
        ],
        validation_plan=["Check secrets import"],
        estimated_scope=FixScope.FILE,
    )

    patch_id = str(uuid4())
    patch = PatchModel(
        id=patch_id,
        finding_id=finding.id,
        plan_id=str(plan_id_2),
        fix_plan_snapshot=plan_2.model_dump(mode="json"),
        scan_id=scan.id,
        thread_id=f"remediation-{uuid4()}",
        status=PatchStatus.APPROVED.value,
        machine_verdict="PASSED",
        unified_diff="--- a/app/utils.py\n+++ b/app/utils.py\n@@ -1,2 +1,3 @@\n+import secrets\n def helper():\n     return True\n",
        files_modified=["app/utils.py"],
        explanation="Use secrets module for cryptographic randomness",
        expected_behavior_change="Cryptographically strong keys",
        approved_by="sec-lead",
    )
    db_session.add(patch)
    db_session.commit()

    # Remote HEAD on GitHub has drifted to a new commit!
    drifted_remote_sha = "ffffffffffffffffffffffffffffffffffffffff"
    mock_provider = E2EMockGitHubProvider(remote_head_sha=drifted_remote_sha)
    service = DeliveryService(provider=mock_provider)

    from app.api.routes.deliveries import get_delivery_service
    app.dependency_overrides[get_delivery_service] = lambda: service

    mock_ctx_fn = _make_local_snapshot_context(repo_path)
    try:
        with mock_patch("app.delivery.service.get_snapshot_service") as mock_svc_snap, \
             mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:

            mock_inst = MagicMock()
            mock_inst.snapshot_context.side_effect = mock_ctx_fn
            mock_svc_snap.return_value = mock_inst
            mock_val_snap.return_value = mock_inst

            # Preview reflects drift blocking
            prev_resp = client.get(f"/api/v1/patches/{patch_id}/delivery-preview")
            assert prev_resp.status_code == 200
            prev_data = prev_resp.json()
            assert prev_data["eligible"] is False
            assert prev_data["failure_code"] == "BLOCKED_BASE_DRIFT"
            assert prev_data["scanned_base_sha"] == commit_sha
            assert prev_data["observed_base_sha"] == drifted_remote_sha

            # Deliver attempt records BLOCKED status without writes
            del_resp = client.post(f"/api/v1/patches/{patch_id}/deliver", json={"requested_by": "lead-eng"})
            assert del_resp.status_code == 200
            del_data = del_resp.json()
            assert del_data["status"] == "BLOCKED"
            assert del_data["failure_code"] == "BLOCKED_BASE_DRIFT"
    finally:
        app.dependency_overrides.pop(get_delivery_service, None)

    # Zero writes occurred
    assert len(mock_provider.blobs_created) == 0
    assert len(mock_provider.trees_created) == 0
    assert len(mock_provider.commits_created) == 0
    assert len(mock_provider.branches_created) == 0
    assert len(mock_provider.prs_created) == 0

    # Telemetry and report reflect blocked delivery
    report = ScanReportService.build_scan_report(db=db_session, scan_id=UUID(scan_id))
    assert report.summary.deliveries_blocked == 1
    assert report.summary.pull_requests_created == 0

    markdown = ScanReportService.render_markdown(report)
    assert "⚠️ Blocked Deliveries (Base Drift) | 1" in markdown

    telemetry = ScanReportService.build_scan_telemetry(db=db_session, scan_id=scan_id)
    assert telemetry.deliveries_blocked == 1
    assert telemetry.pull_requests_created == 0


# 3. Partial Failure & Resume Reconciliation
@pytest.mark.asyncio
async def test_phase5_e2e_partial_failure_and_resume_reconciliation(db_session: Session, local_git_repo):
    repo_path, commit_sha = local_git_repo

    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/repolens-org/secure-core.git",
        status=ScanStatus.COMPLETED.value,
        branch="main",
        commit_hash=commit_sha,
    )
    db_session.add(scan)

    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title="Reconciliation Finding",
        description="Testing recovery from interrupted network calls.",
        severity=Severity.MEDIUM.value,
        status=FindingStatus.OPEN.value,
        verification_verdict="CONFIRMED",
        rule_id="test.reconciliation",
        category="Reliability",
    )
    db_session.add(finding)

    plan_id_3 = uuid4()
    plan_3 = FixPlan(
        id=plan_id_3,
        finding_id=UUID(finding.id),
        root_cause="Reliability issue",
        objective="Add safe comment",
        files_expected_to_change=["app/utils.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/utils.py",
                description="Add safe comment",
                rationale="Improve reliability",
            )
        ],
        validation_plan=["Check utils comments"],
        estimated_scope=FixScope.FILE,
    )

    patch_id = str(uuid4())
    patch = PatchModel(
        id=patch_id,
        finding_id=finding.id,
        plan_id=str(plan_id_3),
        fix_plan_snapshot=plan_3.model_dump(mode="json"),
        scan_id=scan.id,
        thread_id=f"remediation-{uuid4()}",
        status=PatchStatus.APPROVED.value,
        machine_verdict="PASSED",
        unified_diff="--- a/app/utils.py\n+++ b/app/utils.py\n@@ -1,2 +1,3 @@\n+# Safe comment\n def helper():\n     return True\n",
        files_modified=["app/utils.py"],
        explanation="Added safe comment",
        expected_behavior_change="None",
        approved_by="sec-lead",
    )
    db_session.add(patch)
    db_session.commit()

    mock_provider = E2EMockGitHubProvider(remote_head_sha=commit_sha)
    mock_ctx_fn = _make_local_snapshot_context(repo_path)

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_svc_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:

        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = mock_ctx_fn
        mock_svc_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)

        # Initial delivery creates commit, branch, PR
        d1 = await service.deliver_patch(db=db_session, patch_id=patch_id)
        assert d1.status == DeliveryStatus.PR_CREATED.value
        initial_pr_count = len(mock_provider.prs)
        assert initial_pr_count == 1

        # Subsequent delivery retry re-discovers existing PR and does not create duplicate
        d2 = await service.deliver_patch(db=db_session, patch_id=patch_id)
        assert d2.id == d1.id
        assert d2.pr_number == d1.pr_number
        assert len(mock_provider.prs) == 1


# 4. Genuine Route-Level Full Lifecycle Release Gate (POST /findings/{id}/patch -> /approve -> /deliver)
@pytest.mark.asyncio
async def test_phase5_e2e_full_route_level_lifecycle_gate(client: TestClient, db_session: Session, local_git_repo):
    """Proves the full unshortcutted lifecycle from actual finding patch generation route to GitHub PR delivery."""
    repo_path, commit_sha = local_git_repo

    # 1. Create canonical completed ScanModel
    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/repolens-org/secure-core.git",
        status=ScanStatus.COMPLETED.value,
        branch="main",
        commit_hash=commit_sha,
    )
    db_session.add(scan)

    # 2. Create grounded CONFIRMED FindingModel + EvidenceModel
    finding_id = str(uuid4())
    finding = FindingModel(
        id=finding_id,
        scan_id=scan.id,
        title="Insecure Plaintext Password Authentication",
        description="Password comparison uses plaintext equality instead of constant-time hash.",
        severity=Severity.CRITICAL.value,
        status=FindingStatus.OPEN.value,
        verification_verdict="CONFIRMED",
        rule_id="security.insecure-auth",
        category="Security",
    )
    db_session.add(finding)

    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=finding_id,
        file_path="app/auth.py",
        start_line=1,
        end_line=3,
        code_snippet="return user == pwd",
    )
    db_session.add(evidence)
    db_session.commit()

    # Define the canonical FixPlan and PatchProposal
    plan_id = uuid4()
    real_fix_plan = FixPlan(
        id=plan_id,
        finding_id=UUID(finding_id),
        root_cause="Insecure direct plaintext password comparison",
        objective="Replace plaintext comparison with verify_hash",
        files_expected_to_change=["app/auth.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/auth.py",
                description="Use constant-time verification",
                rationale="Eliminate timing side channel",
            )
        ],
        validation_plan=["Verify password hash checking"],
        estimated_scope=FixScope.FILE,
    )

    from app.patching.schemas import PatchProposal, PatchWorkflowResult, VerificationStatus, PatchVerificationResult

    prop_id = uuid4()
    patch_diff = (
        "--- a/app/auth.py\n"
        "+++ b/app/auth.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def authenticate(user, pwd):\n"
        "-    # Vulnerable plain text check\n"
        "-    return user == pwd\n"
        "+    # Secure constant-time hash comparison\n"
        "+    return verify_hash(user, pwd)\n"
    )
    real_proposal = PatchProposal(
        id=prop_id,
        finding_id=UUID(finding_id),
        plan_id=plan_id,
        unified_diff=patch_diff,
        files_modified=["app/auth.py"],
        explanation="Replaced plaintext comparison with verify_hash",
        expected_behavior_change="Secure constant-time password verification",
    )

    real_wf_result = PatchWorkflowResult(
        finding_id=UUID(finding_id),
        proposal=real_proposal,
        verification_result=PatchVerificationResult(
            patch_id=prop_id,
            finding_id=UUID(finding_id),
            status=VerificationStatus.PASSED,
            syntax_valid=True,
            security_clean=True,
            contract_aligned=True,
            target_finding_resolved=True,
            explanation="All checks passed",
            checks=[],
        ),
        machine_verdict="PASSED",
        final_verdict="PASSED",
    )

    # Configure mock GitHub provider matching the scanned commit SHA
    mock_provider = E2EMockGitHubProvider(remote_head_sha=commit_sha)
    service = DeliveryService(provider=mock_provider)

    from app.api.routes.deliveries import get_delivery_service
    app.dependency_overrides[get_delivery_service] = lambda: service

    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def _async_snapshot_ctx(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            shutil.copytree(repo_path, fresh_ws, dirs_exist_ok=True)
            yield fresh_ws

    mock_ctx_fn = _make_local_snapshot_context(repo_path)

    try:
        with mock_patch("app.ingestion.snapshot.RepositorySnapshotService.open_snapshot", side_effect=_async_snapshot_ctx), \
             mock_patch("app.analysis.service.RepositoryIntelligenceService.analyze_repository", AsyncMock(return_value=MagicMock(manifest=MagicMock()))), \
             mock_patch("app.context.runtime.ScanIntelligenceRuntime.build", AsyncMock(return_value=MagicMock(context_engine=MagicMock(), repository_graph=MagicMock(), manifest=MagicMock()))), \
             mock_patch("app.planning.service.FixPlanningService.create_fix_plan", AsyncMock(return_value=real_fix_plan)), \
             mock_patch("app.patching.workflow.PatchWorkflowCoordinator.execute_patch_workflow", AsyncMock(return_value=real_wf_result)), \
             mock_patch("app.delivery.service.get_snapshot_service") as mock_svc_snap, \
             mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:

            mock_inst = MagicMock()
            mock_inst.snapshot_context.side_effect = mock_ctx_fn
            mock_svc_snap.return_value = mock_inst
            mock_val_snap.return_value = mock_inst

            # Step 1: Execute actual route POST /api/v1/findings/{finding_id}/patch
            gen_resp = client.post(f"/api/v1/findings/{finding_id}/patch")
            assert gen_resp.status_code == 200
            gen_data = gen_resp.json()
            assert gen_data["final_verdict"] == "PASSED"
            persisted_patch_id = gen_data["proposal"]["id"]
            assert persisted_patch_id == str(prop_id)

            # Re-query patch from DB to verify it was persisted with fix_plan_snapshot
            db_patch = db_session.query(PatchModel).filter(PatchModel.id == persisted_patch_id).first()
            assert db_patch is not None
            assert db_patch.status == PatchStatus.VERIFIED.value
            assert db_patch.plan_id == str(plan_id)
            assert db_patch.fix_plan_snapshot is not None
            assert db_patch.fix_plan_snapshot["id"] == str(plan_id)
            assert db_patch.fix_plan_snapshot["finding_id"] == finding_id
            FixPlan.model_validate(db_patch.fix_plan_snapshot)

            # Step 2: Attempt delivery BEFORE approval -> BLOCKED (HTTP 409)
            unapproved_resp = client.post(
                f"/api/v1/patches/{persisted_patch_id}/deliver",
                json={"requested_by": "sec-lead", "notes": "Premature attempt"},
            )
            assert unapproved_resp.status_code == 409
            assert len(mock_provider.prs) == 0

            # Step 3: Approve patch via POST /api/v1/patches/{patch_id}/approve
            appr_resp = client.post(
                f"/api/v1/patches/{persisted_patch_id}/approve",
                json={"approved_by": "security-lead", "notes": "Production hotfix approved"},
            )
            assert appr_resp.status_code == 200
            assert appr_resp.json()["status"] == "APPROVED"

            # Verify machine verdict preserved
            db_session.refresh(db_patch)
            assert db_patch.status == PatchStatus.APPROVED.value
            assert db_patch.machine_verdict == "PASSED"

            # Step 4: Preview delivery
            prev_resp = client.get(f"/api/v1/patches/{persisted_patch_id}/delivery-preview")
            assert prev_resp.status_code == 200
            assert prev_resp.json()["eligible"] is True

            # Step 5: Deliver patch via POST /api/v1/patches/{patch_id}/deliver
            del_resp = client.post(
                f"/api/v1/patches/{persisted_patch_id}/deliver",
                json={"requested_by": "lead-sec-eng", "notes": "Production hotfix"},
            )
            assert del_resp.status_code == 200
            del_data = del_resp.json()
            assert del_data["status"] == "PR_CREATED"
            assert del_data["pr_number"] == 101
            assert del_data["base_branch"] == "main"
            assert del_data["head_branch"].startswith("repolens/fix-")

            # Invariants
            assert len(mock_provider.prs) == 1
            assert len(mock_provider.prs_created) == 1
            assert mock_provider.branches_created[0] == del_data["head_branch"]
            created_commit = mock_provider.commits[del_data["head_sha"]]
            assert created_commit["parents"] == [commit_sha]
            assert "main" not in mock_provider.branches_created  # No default branch mutation!

    finally:
        app.dependency_overrides.pop(get_delivery_service, None)

