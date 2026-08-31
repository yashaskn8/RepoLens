import hashlib
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch as mock_patch
from uuid import UUID, uuid4
import pytest
from fastapi import HTTPException
import httpx
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.delivery.github_provider import GitHubDeliveryProvider
from app.delivery.pr_body import generate_pr_body, generate_pr_title
from app.delivery.provider import RepositoryDeliveryProvider
from app.delivery.schemas import (
    DeliveryProviderError,
    GitCommitInfo,
    GitPullRequestInfo,
    GitTreeEntry,
    GitHubAPIError,
)
from app.delivery.service import DeliveryService, compute_idempotency_key
from app.delivery.validator import (
    DeliveryValidator,
    extract_github_owner_repo,
    sanitize_branch_name,
)
from app.models.delivery import DeliveryModel
from app.models.finding import EvidenceModel, FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.auth import CurrentUser
from app.schemas.enums import DeliveryStatus, FindingStatus, PatchStatus, ScanStatus, Severity
from app.schemas.delivery import DeliveryRequest
from app.services.workflow_event_service import WorkflowEventService


class MockDeliveryProvider(RepositoryDeliveryProvider):
    """Configurable in-memory delivery provider mock for unit testing."""

    def __init__(
        self,
        base_head_sha: str = "1111111111111111111111111111111111111111",
        base_tree_sha: str = "2222222222222222222222222222222222222222",
    ):
        self.base_head_sha = base_head_sha
        self.base_tree_sha = base_tree_sha
        self.branches: dict[str, str] = {"main": base_head_sha}
        self.commits: dict[str, GitCommitInfo] = {
            base_head_sha: GitCommitInfo(sha=base_head_sha, tree_sha=base_tree_sha, parents=[])
        }
        self.blobs_created: list[dict] = []
        self.trees_created: list[dict] = []
        self.commits_created: list[dict] = []
        self.branches_created: list[dict] = []
        self.prs_created: list[dict] = []
        self.prs: dict[str, GitPullRequestInfo] = {}
        self.existing_pr: Optional[GitPullRequestInfo] = None

    async def get_branch_head(self, owner: str, repo: str, branch: str) -> str:
        clean = branch.replace("refs/heads/", "")
        if clean in self.branches:
            return self.branches[clean]
        raise GitHubAPIError(f"Branch '{clean}' not found on remote", status_code=404)

    async def get_commit(self, owner: str, repo: str, sha: str) -> GitCommitInfo:
        if sha in self.commits:
            return self.commits[sha]
        return GitCommitInfo(sha=sha, tree_sha=self.base_tree_sha, parents=[self.base_head_sha])

    async def create_blob(self, owner: str, repo: str, content: str, encoding: str = "utf-8") -> str:
        blob_sha = f"blob_{hashlib.sha256(content.encode('utf-8')).hexdigest()[:12]}"
        self.blobs_created.append({"owner": owner, "repo": repo, "content": content, "sha": blob_sha})
        return blob_sha

    async def create_tree(self, owner: str, repo: str, base_tree_sha: str, tree_entries: list[GitTreeEntry]) -> str:
        entries_repr = "_".join(sorted(f"{e.path}:{e.mode}:{e.sha}" for e in tree_entries))
        tree_sha = f"tree_{hashlib.sha256(entries_repr.encode('utf-8')).hexdigest()[:12]}"
        self.trees_created.append({"owner": owner, "repo": repo, "base_tree_sha": base_tree_sha, "entries": tree_entries, "sha": tree_sha})
        return tree_sha

    async def create_commit(self, owner: str, repo: str, message: str, tree_sha: str, parent_shas: list[str]) -> str:
        commit_sha = f"333333333333333333333333333333333333333{len(self.commits_created) + 1}"
        commit_info = GitCommitInfo(sha=commit_sha, tree_sha=tree_sha, message=message, parents=parent_shas)
        self.commits[commit_sha] = commit_info
        self.commits_created.append({"owner": owner, "repo": repo, "message": message, "tree_sha": tree_sha, "parents": parent_shas, "sha": commit_sha})
        return commit_sha

    async def create_branch(self, owner: str, repo: str, branch_name: str, sha: str) -> str:
        clean = branch_name.replace("refs/heads/", "")
        self.branches[clean] = sha
        self.branches_created.append({"owner": owner, "repo": repo, "branch": clean, "sha": sha})
        return f"refs/heads/{clean}"

    async def find_existing_pull_request(self, owner: str, repo: str, head: str, base: str) -> Optional[GitPullRequestInfo]:
        if self.existing_pr:
            return self.existing_pr
        key = f"{head}:{base}"
        if key in self.prs:
            return self.prs[key]
        for item in self.prs_created:
            p = item["pr"]
            if p.head_branch == head and p.base_branch == base:
                return p
        return None

    async def create_pull_request(self, owner: str, repo: str, title: str, body: str, head: str, base: str) -> GitPullRequestInfo:
        pr_num = len(self.prs_created) + 1
        pr = GitPullRequestInfo(
            number=pr_num,
            html_url=f"https://github.com/{owner}/{repo}/pull/{pr_num}",
            head_branch=head,
            base_branch=base,
            title=title,
        )
        self.prs_created.append({"owner": owner, "repo": repo, "pr": pr, "body": body})
        return pr


@pytest.fixture
def base_entities(db_session: Session):
    """Fixture providing consistent baseline entities with a local temp repo snapshot."""
    scanned_sha = "1111111111111111111111111111111111111111"
    scan = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/example-org/secure-app",
        status=ScanStatus.COMPLETED.value,
        branch="main",
        commit_hash=scanned_sha,
        owner_user_id="phase5-sec-user",
    )
    db_session.add(scan)

    finding = FindingModel(
        id=str(uuid4()),
        scan_id=scan.id,
        title="Path traversal vulnerability",
        description="User supplied path is not confined.",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict="CONFIRMED",
        rule_id="security.path-traversal",
        category="Security",
    )
    db_session.add(finding)

    evidence = EvidenceModel(
        id=str(uuid4()),
        finding_id=finding.id,
        file_path="app/storage.py",
        start_line=10,
        end_line=12,
        code_snippet="open(user_path)",
    )
    db_session.add(evidence)

    from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep
    plan_id = uuid4()
    plan = FixPlan(
        id=plan_id,
        finding_id=UUID(finding.id),
        root_cause="User supplied path is not confined.",
        objective="Added path confinement validation",
        files_expected_to_change=["app/storage.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/storage.py",
                description="Add path validation",
                rationale="Prevent path traversal",
            )
        ],
        validation_plan=["Check file path confinement"],
        estimated_scope=FixScope.FILE,
    )

    valid_diff = "--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n def read_file(p):\n+    validate(p)\n     return open(p)\n"
    patch = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
        plan_id=str(plan_id),
        fix_plan_snapshot=plan.model_dump(mode="json"),
        scan_id=scan.id,
        thread_id=f"remediation-{uuid4()}",
        status=PatchStatus.APPROVED.value,
        machine_verdict="PASSED",
        unified_diff=valid_diff,
        files_modified=["app/storage.py"],
        explanation="Added path confinement validation",
        expected_behavior_change="Rejects traversals outside storage directory",
        approved_by="sec-lead",
    )
    db_session.add(patch)
    db_session.commit()

    return scan, finding, patch


# 1. Unauthorized / non-approved patch delivery rejected with 409
@pytest.mark.asyncio
async def test_unapproved_patch_delivery_rejected_with_409(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    patch.status = PatchStatus.VERIFIED.value
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    service = DeliveryService(provider=mock_provider)

    with pytest.raises(HTTPException) as exc_info:
        await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

    assert exc_info.value.status_code == 409
    assert "explicitly APPROVED" in exc_info.value.detail
    assert len(mock_provider.prs_created) == 0


# 2. Rejected machine verdict patch delivery rejected with 422
@pytest.mark.asyncio
async def test_rejected_verdict_patch_delivery_rejected_with_422(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    patch.status = PatchStatus.APPROVED.value
    patch.machine_verdict = "REJECTED"
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    service = DeliveryService(provider=mock_provider)

    with pytest.raises(HTTPException) as exc_info:
        await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

    assert exc_info.value.status_code == 422
    assert "REJECTED" in exc_info.value.detail
    assert len(mock_provider.prs_created) == 0


# 3. Unknown patch ID returns 404
@pytest.mark.asyncio
async def test_unknown_patch_delivery_returns_404(db_session: Session):
    service = DeliveryService(provider=MockDeliveryProvider())
    with pytest.raises(HTTPException) as exc_info:
        await service.deliver_patch(db=db_session, patch_id=str(uuid4()), payload=DeliveryRequest())

    assert exc_info.value.status_code == 404


# 4. Base branch drift blocks delivery and records drift metadata (0 GitHub writes)
@pytest.mark.asyncio
async def test_base_branch_drift_blocks_delivery_and_records_drift_metadata(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    # Remote HEAD has moved to 9999... while scanned SHA was 1111...
    drifted_sha = "9999999999999999999999999999999999999999"
    mock_provider = MockDeliveryProvider(base_head_sha=drifted_sha)
    service = DeliveryService(provider=mock_provider)

    delivery = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

    assert delivery.status == DeliveryStatus.BLOCKED.value
    assert delivery.failure_code == "BLOCKED_BASE_DRIFT"
    assert delivery.scanned_base_sha == scan.commit_hash
    assert delivery.observed_base_sha == drifted_sha
    assert len(mock_provider.commits_created) == 0
    assert len(mock_provider.branches_created) == 0
    assert len(mock_provider.prs_created) == 0


# 5. Detached HEAD ref rejected as invalid base branch
@pytest.mark.asyncio
async def test_detached_head_ref_rejected_as_invalid_base_branch(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    scan.branch = "HEAD@1111111"
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    val_res = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)

    assert not val_res.eligible
    assert val_res.failure_code == "INVALID_BASE_BRANCH"


# 6. Malicious finding title sanitization in PR title and body
def test_malicious_finding_title_sanitization_in_pr_title_and_body(base_entities):
    scan, finding, patch = base_entities
    finding.title = "XSS Injection <script>alert(1)</script> & `drop table` token sk-1234567890abcdef123456"

    pr_title = generate_pr_title(finding.title)
    assert "<script>" not in pr_title
    assert "alert(1)" in pr_title
    assert "[RepoLens] Fix:" in pr_title

    pr_body = generate_pr_body(finding=finding, patch=patch, scan=scan)
    assert "<script>" not in pr_body
    assert "&lt;script&gt;" in pr_body or "script" in pr_body
    assert "sk-[REDACTED]" in pr_body


# 7. Exact file set mismatch detected by DeliveryValidator
@pytest.mark.asyncio
async def test_exact_file_set_mismatch_detected(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    # Diff modifies app/storage.py, but files_modified declares something else
    patch.files_modified = ["app/other.py"]
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    val_res = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)

    assert not val_res.eligible
    assert val_res.failure_code == "FILE_SET_MISMATCH"


# 8. Secret leakage in patched content blocked by DeliveryValidator
@pytest.mark.asyncio
async def test_secret_leakage_in_patched_content_blocked(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    # Unified diff injecting a hardcoded sk- API key
    secret_diff = "--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n+api_key = 'sk-1234567890abcdef1234567890abcdef'\n def read_file(p):\n     return open(p)\n"
    patch.unified_diff = secret_diff
    db_session.commit()

    mock_provider = MockDeliveryProvider()

    # Mock snapshot workspace
    with tempfile.TemporaryDirectory() as tmp_ws:
        os.makedirs(os.path.join(tmp_ws, "app"), exist_ok=True)
        with open(os.path.join(tmp_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
            f.write("def read_file(p):\n    return open(p)\n")

        with mock_patch("app.delivery.validator.get_snapshot_service") as mock_snap:
            from contextlib import contextmanager

            @contextmanager
            def _fake_snapshot(scan_id, db=None):
                with tempfile.TemporaryDirectory() as fresh_ws:
                    os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
                    with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                        f.write("def read_file(p):\n    return open(p)\n")
                    yield fresh_ws

            mock_inst = MagicMock()
            mock_inst.snapshot_context.side_effect = _fake_snapshot
            mock_snap.return_value = mock_inst

            val_res = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)
            assert not val_res.eligible
            assert val_res.failure_code == "PATCH_CONTAINS_SECRETS"


# 9. Idempotency key is deterministic and unique
def test_idempotency_key_deterministic_and_unique():
    k1 = compute_idempotency_key("owner", "repo", "patch-123", "main", "sha-abc")
    k2 = compute_idempotency_key("OWNER", "REPO", "patch-123", "main", "SHA-ABC")
    assert k1 == k2

    k3 = compute_idempotency_key("owner", "repo", "patch-456", "main", "sha-abc")
    assert k1 != k3


# 10. GitHub provider never exposes token in str/repr
def test_github_provider_never_logs_token():
    token = "ghp_1234567890abcdef1234567890abcdef1234"
    provider = GitHubDeliveryProvider(token=token)
    assert token not in repr(provider)
    assert token not in str(provider)


# 11. GitHub provider redacts error responses
@pytest.mark.asyncio
async def test_github_provider_redacts_error_responses():
    secret_token = "ghp_1234567890abcdef1234567890abcdef1234"

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 403
    mock_resp.is_error = True
    mock_resp.content = b'{"message": "Invalid token ' + secret_token.encode() + b'"}'
    mock_resp.text = f'{{"message": "Invalid token {secret_token}"}}'
    mock_resp.json.return_value = {"message": f"Invalid token {secret_token}"}
    mock_client.request.return_value = mock_resp

    provider = GitHubDeliveryProvider(token="dummy", client=mock_client)

    with pytest.raises(GitHubAPIError) as exc_info:
        await provider.get_branch_head("owner", "repo", "main")

    assert secret_token not in exc_info.value.message
    assert "[REDACTED_GITHUB_TOKEN]" in exc_info.value.message


# 12. Write operations do not blindly retry on failure
@pytest.mark.asyncio
async def test_no_blind_retries_on_write_operations():
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 500
    mock_resp.is_error = True
    mock_resp.content = b'{"message": "Internal Server Error"}'
    mock_resp.text = '{"message": "Internal Server Error"}'
    mock_resp.json.return_value = {"message": "Internal Server Error"}
    mock_client.request.return_value = mock_resp

    provider = GitHubDeliveryProvider(token="dummy", client=mock_client)

    with pytest.raises(GitHubAPIError):
        await provider.create_commit("owner", "repo", "msg", "tree_sha", ["parent_sha"])

    # Must be called exactly once (no blind retry loop for writes)
    assert mock_client.request.call_count == 1


# 13. Canonical owner/repo extraction and branch sanitization
def test_url_extraction_and_branch_sanitization():
    owner, repo = extract_github_owner_repo("https://github.com/facebook/react.git")
    assert owner == "facebook"
    assert repo == "react"

    branch = sanitize_branch_name("abc-1234-5678", "def-9876-5432")
    assert branch.startswith("repolens/fix-")
    assert len(branch) < 40


# 14. Existing PR reconciliation prevents duplicate PR creation
@pytest.mark.asyncio
async def test_existing_pr_reconciliation_prevents_duplicate_creation(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()
    mock_provider.existing_pr = GitPullRequestInfo(
        number=99,
        html_url="https://github.com/example-org/secure-app/pull/99",
        head_branch="repolens/fix-abc-def",
        base_branch="main",
        title="Existing PR",
    )

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        delivery = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert delivery.status == DeliveryStatus.PR_CREATED.value
        assert delivery.pr_number == 99
        assert delivery.pr_url == "https://github.com/example-org/secure-app/pull/99"
        assert len(mock_provider.prs_created) == 0  # Reconciled existing, did not create duplicate


# 15. Concurrent delivery race condition returns existing delivery
@pytest.mark.asyncio
async def test_concurrent_delivery_race_condition_handled(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)

        # First request succeeds
        d1 = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
        assert d1.status == DeliveryStatus.PR_CREATED.value

        # Second request reuses identical idempotency key and returns existing delivery
        d2 = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
        assert d2.id == d1.id
        assert d2.pr_number == d1.pr_number
        assert len(mock_provider.prs_created) == 1


# 16. Fix 1: create_branch GitHubAPIError is correctly imported and caught without NameError
@pytest.mark.asyncio
async def test_create_branch_github_api_error_caught_without_name_error(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    # Simulate race condition: remote created branch with sha, then returned 422
    async def _failing_create_branch(owner, repo, branch_name, sha):
        clean = branch_name.replace("refs/heads/", "")
        mock_provider.branches[clean] = sha
        raise GitHubAPIError("Reference already exists", status_code=422)

    mock_provider.create_branch = _failing_create_branch

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        delivery = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
        assert delivery is not None
        assert delivery.status == DeliveryStatus.PR_CREATED.value


# 17. Fix 2: Case B - Existing branch with different SHA fails closed with HEAD_BRANCH_COLLISION
@pytest.mark.asyncio
async def test_reconciliation_existing_branch_different_sha_fails_closed(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    # Pre-populate branch with collision SHA
    branch_name = sanitize_branch_name(finding.id, patch.id)
    mock_provider.branches[branch_name] = "9999999999999999999999999999999999999999"

    # Pre-create delivery with different local head_sha
    from app.delivery.service import compute_idempotency_key
    owner, repo = "example-org", "secure-app"
    idempotency_key = compute_idempotency_key(owner, repo, patch.id, "main", scan.commit_hash)

    delivery = DeliveryModel(
        id=str(uuid4()),
        scan_id=scan.id,
        finding_id=finding.id,
        patch_id=patch.id,
        idempotency_key=idempotency_key,
        repository_url=scan.repository_url,
        repository_owner=owner,
        repository_name=repo,
        head_branch=branch_name,
        base_branch="main",
        scanned_base_sha=scan.commit_hash,
        head_sha="3333333333333333333333333333333333333331",  # Local expected
        status=DeliveryStatus.READY.value,
    )
    db_session.add(delivery)
    db_session.commit()

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.FAILED.value
        assert res.failure_code == "HEAD_BRANCH_COLLISION"
        assert len(mock_provider.prs_created) == 0


# 18. Fix 2: Case C - Branch exists, local head_sha missing, remote tree and parent match -> adopt safely
@pytest.mark.asyncio
async def test_reconciliation_missing_local_head_sha_verified_commit_adopted(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    branch_name = sanitize_branch_name(finding.id, patch.id)
    remote_sha = "4444444444444444444444444444444444444444"
    mock_provider.branches[branch_name] = remote_sha
    expected_content = "def read_file(p):\n    validate(p)\n    return open(p)\n"
    blob_sha = f"blob_{hashlib.sha256(expected_content.encode('utf-8')).hexdigest()[:12]}"
    expected_tree_sha = f"tree_{hashlib.sha256(f'app/storage.py:100644:{blob_sha}'.encode('utf-8')).hexdigest()[:12]}"
    mock_provider.commits[remote_sha] = GitCommitInfo(
        sha=remote_sha,
        tree_sha=expected_tree_sha,
        parents=[scan.commit_hash],
    )

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.PR_CREATED.value
        assert res.head_sha == remote_sha


# 19. Fix 2: Case C - Branch exists, local head_sha missing, remote tree does NOT match -> fail closed
@pytest.mark.asyncio
async def test_reconciliation_missing_local_head_sha_mismatched_tree_fails_closed(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    branch_name = sanitize_branch_name(finding.id, patch.id)
    remote_sha = "4444444444444444444444444444444444444444"
    mock_provider.branches[branch_name] = remote_sha
    mock_provider.commits[remote_sha] = GitCommitInfo(
        sha=remote_sha,
        tree_sha="tree_alien_mismatch",
        parents=[scan.commit_hash],
    )

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.FAILED.value
        assert res.failure_code == "HEAD_BRANCH_COLLISION"
        assert len(mock_provider.prs_created) == 0


# 20. Fix 2: Provider has no update_branch_ref method and never mutates default branch
def test_no_update_branch_ref_in_provider():
    from app.delivery.provider import RepositoryDeliveryProvider
    from app.delivery.github_provider import GitHubDeliveryProvider

    assert not hasattr(RepositoryDeliveryProvider, "update_branch_ref")
    assert not hasattr(GitHubDeliveryProvider, "update_branch_ref")
    assert not hasattr(RepositoryDeliveryProvider, "merge_pull_request")
    assert not hasattr(GitHubDeliveryProvider, "merge_pull_request")
    assert not hasattr(RepositoryDeliveryProvider, "delete_branch")
    assert not hasattr(GitHubDeliveryProvider, "delete_branch")


# 21. Fix 3: 401 during find_existing_pull_request propagates failure without calling create_pull_request
@pytest.mark.asyncio
async def test_find_existing_pr_401_fails_delivery_without_calling_create_pr(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    async def _failing_find_pr(owner, repo, head, base):
        raise GitHubAPIError("Bad credentials", status_code=401)

    mock_provider.find_existing_pull_request = _failing_find_pr

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.FAILED.value
        assert res.failure_code == "GITHUB_401"
        assert len(mock_provider.prs_created) == 0


# 22. Fix 3: PR create timeout but subsequent reconciliation finds PR -> PR_CREATED
@pytest.mark.asyncio
async def test_pr_create_timeout_with_successful_reconciliation(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    # Make first find_existing_pull_request return None
    # Then create_pull_request raises timeout, but sets remote state
    # Then retry find_existing_pull_request returns the created PR
    created_pr = GitPullRequestInfo(
        number=42,
        html_url="https://github.com/example-org/secure-app/pull/42",
        head_branch=sanitize_branch_name(finding.id, patch.id),
        base_branch="main",
        title="fix(repolens): remediate Path traversal vulnerability",
    )

    find_calls = 0
    async def _mock_find_pr(owner, repo, head, base):
        nonlocal find_calls
        find_calls += 1
        if find_calls == 1:
            return None
        return created_pr

    async def _failing_create_pr(owner, repo, title, body, head, base):
        raise GitHubAPIError("Request timed out", status_code=504, safe_code="GITHUB_TIMEOUT")

    mock_provider.find_existing_pull_request = _mock_find_pr
    mock_provider.create_pull_request = _failing_create_pr

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.PR_CREATED.value
        assert res.pr_number == 42
        assert res.pr_url == "https://github.com/example-org/secure-app/pull/42"


# 23. Fix 4: DeliveryValidator invokes canonical verifier and blocks on syntax failure
@pytest.mark.asyncio
async def test_delivery_validator_blocks_on_syntax_error_via_canonical_verifier(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    # Introduce syntax-breaking code in patch
    syntax_error_diff = "--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n+def broken_syntax(:\n def read_file(p):\n     return open(p)\n"
    patch.unified_diff = syntax_error_diff
    db_session.commit()

    mock_provider = MockDeliveryProvider()

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_val_snap.return_value = mock_inst

        val_res = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)
        assert not val_res.eligible
        assert val_res.failure_code in ("PATCH_SYNTAX_ERROR", "VERIFICATION_FAILED", "VERIFICATION_CHECK_FAILED")


# 24. Fix 5: GITHUB_DELIVERY_ENABLED=False disables delivery even if token is present
@pytest.mark.asyncio
async def test_github_delivery_disabled_by_feature_flag(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    provider = GitHubDeliveryProvider(token="ghp_dummytoken12345678901234567890123456", delivery_enabled=False)

    assert provider.credentials_configured is True
    assert provider.delivery_enabled is False
    assert provider.is_configured is False

    service = DeliveryService(provider=provider)
    preview = await service.get_delivery_preview(db=db_session, patch_id=patch.id)
    assert preview.github_delivery_configured is False

    with pytest.raises(HTTPException) as exc_info:
        await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
    assert exc_info.value.status_code == 503


# 25. Fix 5: GITHUB_DELIVERY_ENABLED=True but token absent is unconfigured
def test_github_delivery_enabled_true_token_absent():
    provider = GitHubDeliveryProvider(token="", delivery_enabled=True)
    assert provider.credentials_configured is False
    assert provider.delivery_enabled is True
    assert provider.is_configured is False


# 26. Fix 5: GITHUB_DELIVERY_ENABLED=True and token present is configured
def test_github_delivery_enabled_true_token_present():
    provider = GitHubDeliveryProvider(token="ghp_realkey123456789012345678901234567890", delivery_enabled=True)
    assert provider.credentials_configured is True
    assert provider.delivery_enabled is True
    assert provider.is_configured is True


# 27. Fix 8B: Fixed trusted GitHub API origin rejects untrusted base_url
def test_github_provider_rejects_untrusted_origin():
    with pytest.raises(ValueError) as exc_info:
        GitHubDeliveryProvider(token="ghp_test", base_url="https://evil.example.com")
    assert "Untrusted API origin" in str(exc_info.value)


# 28. Fix 6: Scan status != COMPLETED blocks delivery
@pytest.mark.asyncio
async def test_scan_status_not_completed_blocks_delivery(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    scan.status = ScanStatus.RUNNING.value
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    val_res = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)
    assert not val_res.eligible
    assert val_res.failure_code == "SCAN_NOT_COMPLETED"

    scan.status = ScanStatus.FAILED.value
    db_session.commit()
    val_res2 = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)
    assert not val_res2.eligible
    assert val_res2.failure_code == "SCAN_NOT_COMPLETED"


# 29. Fix 6: Non-hex or non-40-char commit SHA blocks delivery
@pytest.mark.asyncio
async def test_scan_invalid_commit_sha_blocks_delivery(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    # 39 chars
    scan.commit_hash = "1" * 39
    db_session.commit()
    val_res = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)
    assert not val_res.eligible
    assert val_res.failure_code == "INVALID_COMMIT_SHA"

    # 40 chars with non-hex characters
    scan.commit_hash = "111111111111111111111111111111111111111Z"
    db_session.commit()
    val_res2 = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)
    assert not val_res2.eligible
    assert val_res2.failure_code == "INVALID_COMMIT_SHA"


# 30. Fix 6: Missing base branch blocks delivery without guessing main
@pytest.mark.asyncio
async def test_scan_missing_base_branch_blocks_delivery(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    scan.branch = ""
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    val_res = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)
    assert not val_res.eligible
    assert val_res.failure_code == "BASE_BRANCH_UNRESOLVED"


# 31. Fix 6: Detached HEAD or raw commit SHA as branch blocks delivery
@pytest.mark.asyncio
async def test_scan_detached_head_or_sha_branch_blocks_delivery(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    for invalid_branch in ("HEAD", "HEAD@123456", "1111111111111111111111111111111111111111"):
        scan.branch = invalid_branch
        db_session.commit()
        val_res = await DeliveryValidator.validate(db=db_session, patch_id=patch.id, provider=mock_provider)
        assert not val_res.eligible
        assert val_res.failure_code == "INVALID_BASE_BRANCH"


# 32. Fix 7: Workflow events record explicit delivery_id and preserve commit ordering
@pytest.mark.asyncio
async def test_workflow_events_record_typed_delivery_id(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.PR_CREATED.value

        # Inspect workflow events
        events = db_session.query(WorkflowEventModel).filter(WorkflowEventModel.delivery_id == str(res.id)).all()
        assert len(events) >= 3
        event_types = [e.event_type for e in events]
        assert "DELIVERY_REQUESTED" in event_types
        assert "DELIVERY_COMMIT_CREATED" in event_types
        assert "DELIVERY_PR_CREATED" in event_types


# 33. Fix 8A: DeliveryRequest bounds requested_by to max 128 characters
def test_delivery_request_bounds_requested_by_too_long():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        DeliveryRequest(requested_by="a" * 129)
    # 128 is allowed
    req = DeliveryRequest(requested_by="a" * 128)
    assert len(req.requested_by) == 128


# 34. Fix 8A: DeliveryRequest bounds notes to max 2000 characters
def test_delivery_request_bounds_notes_too_long():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        DeliveryRequest(notes="a" * 2001)
    # 2000 is allowed
    req = DeliveryRequest(notes="a" * 2000)
    assert len(req.notes) == 2000


# 35. Fix 8D: Partial failure on PR create with network error and successful reconciliation retry
@pytest.mark.asyncio
async def test_phase5_partial_failure_network_drop_and_recovery(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    mock_provider = MockDeliveryProvider()

    created_pr = GitPullRequestInfo(
        number=777,
        html_url="https://github.com/example-org/secure-app/pull/777",
        head_branch=sanitize_branch_name(finding.id, patch.id),
        base_branch="main",
        title="fix(repolens): remediate Path traversal vulnerability",
    )

    create_pr_calls = 0

    async def _failing_first_create_pr(owner, repo, title, body, head, base):
        nonlocal create_pr_calls
        create_pr_calls += 1
        # Remotely created the PR, but socket drops before returning response!
        mock_provider.prs[f"{head}:{base}"] = created_pr
        raise httpx.ConnectTimeout("Connection dropped while waiting for GitHub PR response")

    mock_provider.create_pull_request = _failing_first_create_pr

    from contextlib import contextmanager

    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)

        # Attempt 1: socket drop triggers write uncertainty recovery, which adopts remote PR!
        res1 = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
        assert res1.status == DeliveryStatus.PR_CREATED.value
        assert res1.pr_number == 777

        # Attempt 2 (Retry): Reconciles cleanly without creating a second PR or failing on existing branch
        res2 = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
        assert res2.id == res1.id
        assert res2.status == DeliveryStatus.PR_CREATED.value
        assert res2.pr_number == 777
        assert create_pr_calls == 1


# ============================================================
# FIX 1: FixPlan Provenance Persistence and Delivery Enforcement
# ============================================================

@pytest.mark.asyncio
async def test_initial_patch_generation_persists_exact_fix_plan_snapshot(db_session: Session):
    from app.api.routes.findings import request_patch_generation
    from app.patching.schemas import PatchProposal, PatchWorkflowResult, VerificationStatus, PatchVerificationResult
    from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep

    scan_id = str(uuid4())
    scan = ScanModel(
        id=scan_id,
        repository_url="https://github.com/example-org/secure-app",
        status=ScanStatus.COMPLETED.value,
        branch="main",
        commit_hash="1111111111111111111111111111111111111111",
        owner_user_id="phase5-sec-user",
    )
    db_session.add(scan)

    finding_id = str(uuid4())
    finding = FindingModel(
        id=finding_id,
        scan_id=scan.id,
        title="Path traversal vulnerability",
        description="User supplied path is not confined.",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        verification_verdict="CONFIRMED",
        rule_id="security.path-traversal",
        category="Security",
    )
    db_session.add(finding)
    db_session.commit()

    test_plan_id = uuid4()
    mock_plan = FixPlan(
        id=test_plan_id,
        finding_id=UUID(finding_id),
        root_cause="User supplied path is not confined.",
        objective="Added path confinement validation",
        files_expected_to_change=["app/storage.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/storage.py",
                description="Add path validation",
                rationale="Prevent path traversal",
            )
        ],
        validation_plan=["Check file path confinement"],
        estimated_scope=FixScope.FILE,
    )

    prop_id = uuid4()
    mock_proposal = PatchProposal(
        id=prop_id,
        finding_id=UUID(finding_id),
        plan_id=test_plan_id,
        unified_diff="--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n def read_file(p):\n+    validate(p)\n     return open(p)\n",
        files_modified=["app/storage.py"],
        explanation="Added path confinement validation",
        expected_behavior_change="Rejects traversals",
    )

    mock_wf_result = PatchWorkflowResult(
        finding_id=UUID(finding_id),
        proposal=mock_proposal,
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

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_open_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.api.routes.findings.get_snapshot_service") as mock_snap, \
         mock_patch("app.api.routes.findings.get_intelligence_service") as mock_intel, \
         mock_patch("app.api.routes.findings.ScanIntelligenceRuntime.build") as mock_runtime_build, \
         mock_patch("app.api.routes.findings.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_create_plan, \
         mock_patch("app.api.routes.findings.PatchWorkflowCoordinator.execute_patch_workflow", new_callable=AsyncMock) as mock_exec_wf:

        mock_inst = MagicMock()
        mock_inst.open_snapshot.side_effect = _fake_open_snapshot
        mock_snap.return_value = mock_inst

        mock_intel_inst = MagicMock()
        mock_intel_inst.analyze_repository = AsyncMock(return_value=MagicMock(manifest=MagicMock()))
        mock_intel.return_value = mock_intel_inst

        mock_runtime_inst = MagicMock(
            context_engine=MagicMock(),
            repository_graph=MagicMock(),
            manifest=MagicMock(),
        )
        mock_runtime_build.return_value = mock_runtime_inst

        mock_create_plan.return_value = mock_plan
        mock_exec_wf.return_value = mock_wf_result

        user_ctx = CurrentUser(id=scan.owner_user_id, email="sec@example.com", role="USER", is_active=True, session_id="s1")
        result = await request_patch_generation(finding_id=UUID(finding_id), current_user=user_ctx, db=db_session)
        assert result.machine_verdict == "PASSED"

        # Verify persisted PatchModel in database
        saved_patch = db_session.query(PatchModel).filter(PatchModel.id == str(prop_id)).first()
        assert saved_patch is not None
        assert saved_patch.plan_id == str(test_plan_id)
        assert saved_patch.fix_plan_snapshot is not None
        assert saved_patch.fix_plan_snapshot["id"] == str(test_plan_id)
        assert saved_patch.fix_plan_snapshot["finding_id"] == str(finding_id)
        assert saved_patch.fix_plan_snapshot["files_expected_to_change"] == ["app/storage.py"]


@pytest.mark.asyncio
async def test_revision_child_persists_exact_revised_fix_plan_snapshot(db_session: Session, base_entities):
    from app.api.routes.patches import request_patch_revision
    from app.schemas.patch import PatchReviseRequest
    from app.patching.schemas import PatchProposal, PatchWorkflowResult, VerificationStatus, PatchVerificationResult
    from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep

    scan, finding, patch = base_entities
    patch.status = PatchStatus.NEEDS_REVIEW.value
    db_session.commit()

    revised_plan_id = uuid4()
    mock_revised_plan = FixPlan(
        id=revised_plan_id,
        finding_id=UUID(finding.id),
        root_cause="User supplied path is not confined.",
        objective="Added path confinement validation (Human reviewer feedback: please add chroot checks)",
        files_expected_to_change=["app/storage.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(
                step_number=1,
                target_file="app/storage.py",
                description="Add path validation",
                rationale="Prevent path traversal",
            )
        ],
        validation_plan=["Check file path confinement"],
        estimated_scope=FixScope.FILE,
    )

    child_prop_id = uuid4()
    mock_child_proposal = PatchProposal(
        id=child_prop_id,
        finding_id=UUID(finding.id),
        plan_id=revised_plan_id,
        unified_diff="--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n def read_file(p):\n+    validate_chroot(p)\n     return open(p)\n",
        files_modified=["app/storage.py"],
        explanation="Added path confinement and chroot validation",
        expected_behavior_change="Rejects traversals and non-chroot paths",
    )

    mock_wf_result = PatchWorkflowResult(
        finding_id=UUID(finding.id),
        proposal=mock_child_proposal,
        verification_result=PatchVerificationResult(
            patch_id=child_prop_id,
            finding_id=UUID(finding.id),
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

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_open_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.ingestion.snapshot.get_snapshot_service") as mock_snap, \
         mock_patch("app.analysis.service.get_intelligence_service") as mock_intel, \
         mock_patch("app.context.runtime.ScanIntelligenceRuntime.build") as mock_runtime_build, \
         mock_patch("app.planning.service.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_create_plan, \
         mock_patch("app.patching.workflow.PatchWorkflowCoordinator.execute_patch_workflow", new_callable=AsyncMock) as mock_exec_wf:

        mock_inst = MagicMock()
        mock_inst.open_snapshot.side_effect = _fake_open_snapshot
        mock_snap.return_value = mock_inst

        mock_intel_inst = MagicMock()
        mock_intel_inst.analyze_repository = AsyncMock(return_value=MagicMock(manifest=MagicMock()))
        mock_intel.return_value = mock_intel_inst

        mock_runtime_inst = MagicMock(
            context_engine=MagicMock(),
            repository_graph=MagicMock(),
            manifest=MagicMock(),
        )
        mock_runtime_build.return_value = mock_runtime_inst

        mock_create_plan.return_value = mock_revised_plan
        mock_exec_wf.return_value = mock_wf_result

        req = PatchReviseRequest(user_feedback="please add chroot checks")
        user_ctx = CurrentUser(id=scan.owner_user_id, email="sec@example.com", role="USER", is_active=True, session_id="s1")
        res = await request_patch_revision(patch_id=patch.id, payload=req, current_user=user_ctx, db=db_session)

        assert res.id == str(child_prop_id)
        assert res.revision_number == 1

        child_patch = db_session.query(PatchModel).filter(PatchModel.id == str(child_prop_id)).first()
        assert child_patch is not None
        assert child_patch.plan_id == str(revised_plan_id)
        assert child_patch.fix_plan_snapshot is not None
        assert child_patch.fix_plan_snapshot["id"] == str(revised_plan_id)
        assert child_patch.fix_plan_snapshot["finding_id"] == str(finding.id)
        assert "Human reviewer feedback: please add chroot checks" in child_patch.fix_plan_snapshot["objective"]


@pytest.mark.asyncio
async def test_initial_patch_generation_proposal_plan_id_mismatch_blocks_persistence(db_session: Session, base_entities):
    from app.api.routes.findings import request_patch_generation
    from app.patching.schemas import PatchProposal, PatchWorkflowResult, VerificationStatus, PatchVerificationResult
    from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep

    scan, finding, _ = base_entities
    finding_id = finding.id

    real_plan_id = uuid4()
    mock_plan = FixPlan(
        id=real_plan_id,
        finding_id=UUID(finding_id),
        root_cause="User supplied path is not confined.",
        objective="Validate path confinement before file operations",
        files_expected_to_change=["app/storage.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(step_number=1, target_file="app/storage.py", description="Add validation", rationale="Security")
        ],
        validation_plan=["Check path confinement"],
        estimated_scope=FixScope.FILE,
    )

    prop_id = uuid4()
    # proposal with mismatched plan_id
    mock_proposal = PatchProposal(
        id=prop_id,
        finding_id=UUID(finding_id),
        plan_id=uuid4(),  # Mismatched plan_id!
        unified_diff="--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n def read_file(p):\n+    validate(p)\n     return open(p)\n",
        files_modified=["app/storage.py"],
        explanation="Added path confinement validation",
        expected_behavior_change="Rejects traversals",
    )

    mock_wf_result = PatchWorkflowResult(
        finding_id=UUID(finding_id),
        proposal=mock_proposal,
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

    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def _fake_open_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.api.routes.findings.get_snapshot_service") as mock_snap, \
         mock_patch("app.api.routes.findings.get_intelligence_service") as mock_intel, \
         mock_patch("app.api.routes.findings.ScanIntelligenceRuntime.build") as mock_runtime_build, \
         mock_patch("app.api.routes.findings.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_create_plan, \
         mock_patch("app.api.routes.findings.PatchWorkflowCoordinator.execute_patch_workflow", new_callable=AsyncMock) as mock_exec_wf:

        mock_inst = MagicMock()
        mock_inst.open_snapshot.side_effect = _fake_open_snapshot
        mock_snap.return_value = mock_inst

        mock_intel_inst = MagicMock()
        mock_intel_inst.analyze_repository = AsyncMock(return_value=MagicMock(manifest=MagicMock()))
        mock_intel.return_value = mock_intel_inst

        mock_runtime_inst = MagicMock(context_engine=MagicMock(), repository_graph=MagicMock(), manifest=MagicMock())
        mock_runtime_build.return_value = mock_runtime_inst

        mock_create_plan.return_value = mock_plan
        mock_exec_wf.return_value = mock_wf_result

        user_ctx = CurrentUser(id=scan.owner_user_id, email="sec@example.com", role="USER", is_active=True, session_id="s1")
        with pytest.raises(HTTPException) as exc_info:
            await request_patch_generation(finding_id=UUID(finding_id), current_user=user_ctx, db=db_session)
        assert exc_info.value.status_code == 422
        assert "PATCH_PLAN_PROVENANCE_MISMATCH" in exc_info.value.detail

        # Assert no PatchModel was persisted in DB
        saved_patch = db_session.query(PatchModel).filter(PatchModel.id == str(prop_id)).first()
        assert saved_patch is None


@pytest.mark.asyncio
async def test_initial_patch_generation_proposal_finding_id_mismatch_blocks_persistence(db_session: Session, base_entities):
    from app.api.routes.findings import request_patch_generation
    from app.patching.schemas import PatchProposal, PatchWorkflowResult, VerificationStatus, PatchVerificationResult
    from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep

    scan, finding, _ = base_entities
    finding_id = finding.id

    real_plan_id = uuid4()
    mock_plan = FixPlan(
        id=real_plan_id,
        finding_id=UUID(finding_id),
        root_cause="User supplied path is not confined.",
        objective="Validate path confinement before file operations",
        files_expected_to_change=["app/storage.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(step_number=1, target_file="app/storage.py", description="Add validation", rationale="Security")
        ],
        validation_plan=["Check path confinement"],
        estimated_scope=FixScope.FILE,
    )

    prop_id = uuid4()
    # proposal with mismatched finding_id
    mock_proposal = PatchProposal(
        id=prop_id,
        finding_id=uuid4(),  # Mismatched finding_id!
        plan_id=real_plan_id,
        unified_diff="--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n def read_file(p):\n+    validate(p)\n     return open(p)\n",
        files_modified=["app/storage.py"],
        explanation="Added path confinement validation",
        expected_behavior_change="Rejects traversals",
    )

    mock_wf_result = PatchWorkflowResult(
        finding_id=mock_proposal.finding_id,
        proposal=mock_proposal,
        verification_result=PatchVerificationResult(
            patch_id=prop_id,
            finding_id=mock_proposal.finding_id,
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

    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def _fake_open_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.api.routes.findings.get_snapshot_service") as mock_snap, \
         mock_patch("app.api.routes.findings.get_intelligence_service") as mock_intel, \
         mock_patch("app.api.routes.findings.ScanIntelligenceRuntime.build") as mock_runtime_build, \
         mock_patch("app.api.routes.findings.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_create_plan, \
         mock_patch("app.api.routes.findings.PatchWorkflowCoordinator.execute_patch_workflow", new_callable=AsyncMock) as mock_exec_wf:

        mock_inst = MagicMock()
        mock_inst.open_snapshot.side_effect = _fake_open_snapshot
        mock_snap.return_value = mock_inst

        mock_intel_inst = MagicMock()
        mock_intel_inst.analyze_repository = AsyncMock(return_value=MagicMock(manifest=MagicMock()))
        mock_intel.return_value = mock_intel_inst

        mock_runtime_inst = MagicMock(context_engine=MagicMock(), repository_graph=MagicMock(), manifest=MagicMock())
        mock_runtime_build.return_value = mock_runtime_inst

        mock_create_plan.return_value = mock_plan
        mock_exec_wf.return_value = mock_wf_result

        user_ctx = CurrentUser(id=scan.owner_user_id, email="sec@example.com", role="USER", is_active=True, session_id="s1")
        with pytest.raises(HTTPException) as exc_info:
            await request_patch_generation(finding_id=UUID(finding_id), current_user=user_ctx, db=db_session)
        assert exc_info.value.status_code == 422
        assert "PATCH_PLAN_PROVENANCE_MISMATCH" in exc_info.value.detail

        saved_patch = db_session.query(PatchModel).filter(PatchModel.id == str(prop_id)).first()
        assert saved_patch is None


@pytest.mark.asyncio
async def test_revision_patch_proposal_plan_id_mismatch_blocks_persistence(db_session: Session, base_entities):
    from app.api.routes.patches import request_patch_revision
    from app.schemas.patch import PatchReviseRequest
    from app.patching.schemas import PatchProposal, PatchWorkflowResult, VerificationStatus, PatchVerificationResult
    from app.planning.schemas import FixPlan, FixScope, OrderedChangeStep

    scan, finding, patch = base_entities
    patch.status = PatchStatus.NEEDS_REVIEW.value
    db_session.commit()

    revised_plan_id = uuid4()
    mock_revised_plan = FixPlan(
        id=revised_plan_id,
        finding_id=UUID(finding.id),
        root_cause="User supplied path is not confined.",
        objective="Added path confinement validation",
        files_expected_to_change=["app/storage.py"],
        symbols_expected_to_change=[],
        ordered_changes=[
            OrderedChangeStep(step_number=1, target_file="app/storage.py", description="Add path validation", rationale="Security")
        ],
        validation_plan=["Check file path confinement"],
        estimated_scope=FixScope.FILE,
    )

    child_prop_id = uuid4()
    # proposal with mismatched plan_id
    mock_child_proposal = PatchProposal(
        id=child_prop_id,
        finding_id=UUID(finding.id),
        plan_id=uuid4(),  # Mismatched plan_id!
        unified_diff="--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n def read_file(p):\n+    validate_chroot(p)\n     return open(p)\n",
        files_modified=["app/storage.py"],
        explanation="Added path confinement and chroot validation",
        expected_behavior_change="Rejects traversals and non-chroot paths",
    )

    mock_wf_result = PatchWorkflowResult(
        finding_id=UUID(finding.id),
        proposal=mock_child_proposal,
        verification_result=PatchVerificationResult(
            patch_id=child_prop_id,
            finding_id=UUID(finding.id),
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

    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def _fake_open_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.ingestion.snapshot.get_snapshot_service") as mock_snap, \
         mock_patch("app.analysis.service.get_intelligence_service") as mock_intel, \
         mock_patch("app.context.runtime.ScanIntelligenceRuntime.build") as mock_runtime_build, \
         mock_patch("app.planning.service.FixPlanningService.create_fix_plan", new_callable=AsyncMock) as mock_create_plan, \
         mock_patch("app.patching.workflow.PatchWorkflowCoordinator.execute_patch_workflow", new_callable=AsyncMock) as mock_exec_wf:

        mock_inst = MagicMock()
        mock_inst.open_snapshot.side_effect = _fake_open_snapshot
        mock_snap.return_value = mock_inst

        mock_intel_inst = MagicMock()
        mock_intel_inst.analyze_repository = AsyncMock(return_value=MagicMock(manifest=MagicMock()))
        mock_intel.return_value = mock_intel_inst

        mock_runtime_inst = MagicMock(context_engine=MagicMock(), repository_graph=MagicMock(), manifest=MagicMock())
        mock_runtime_build.return_value = mock_runtime_inst

        mock_create_plan.return_value = mock_revised_plan
        mock_exec_wf.return_value = mock_wf_result

        req = PatchReviseRequest(user_feedback="please add chroot checks")
        user_ctx = CurrentUser(id=scan.owner_user_id, email="sec@example.com", role="USER", is_active=True, session_id="s1")
        with pytest.raises(HTTPException) as exc_info:
            await request_patch_revision(patch_id=patch.id, payload=req, current_user=user_ctx, db=db_session)
        assert exc_info.value.status_code == 422
        assert "PATCH_PLAN_PROVENANCE_MISMATCH" in exc_info.value.detail

        child_patch = db_session.query(PatchModel).filter(PatchModel.id == str(child_prop_id)).first()
        assert child_patch is None


@pytest.mark.asyncio
async def test_missing_fix_plan_snapshot_blocks_delivery_with_typed_error(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    patch.fix_plan_snapshot = None
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    service = DeliveryService(provider=mock_provider)

    res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
    assert res.status == DeliveryStatus.FAILED.value
    assert res.failure_code == "FIX_PLAN_PROVENANCE_MISSING"
    assert "missing canonical fix plan provenance" in res.failure_message
    assert len(mock_provider.prs_created) == 0


@pytest.mark.asyncio
async def test_malformed_fix_plan_snapshot_blocks_delivery_with_typed_error(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    patch.fix_plan_snapshot = {"not_a_valid_field": 123}
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    service = DeliveryService(provider=mock_provider)

    res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
    assert res.status == DeliveryStatus.FAILED.value
    assert res.failure_code == "FIX_PLAN_INVALID"
    assert len(mock_provider.prs_created) == 0


@pytest.mark.asyncio
async def test_plan_id_or_finding_id_mismatch_blocks_delivery(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    # Tamper with plan_id
    patch.plan_id = str(uuid4())
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    service = DeliveryService(provider=mock_provider)

    res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
    assert res.status == DeliveryStatus.FAILED.value
    assert res.failure_code == "FIX_PLAN_PROVENANCE_MISMATCH"
    assert len(mock_provider.prs_created) == 0


@pytest.mark.asyncio
async def test_tampered_patch_files_modified_against_fix_plan_blocks_delivery(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    # Tamper with files_modified to touch an unauthorized file
    patch.files_modified = ["app/storage.py", "app/unauthorized.py"]
    db_session.commit()

    mock_provider = MockDeliveryProvider()
    service = DeliveryService(provider=mock_provider)

    res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())
    assert res.status == DeliveryStatus.FAILED.value
    assert res.failure_code == "FILE_SET_MISMATCH"
    assert len(mock_provider.prs_created) == 0


# ============================================================
# FIX 2: Full Canonical Finding Provenance
# ============================================================

def test_finding_provenance_preserved_in_domain_mapping(db_session: Session):
    from app.services.domain_mapping import finding_model_to_schema

    scan_id = str(uuid4())
    finding_id = str(uuid4())
    evidence_id = str(uuid4())

    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="SQL Injection in auth handler",
        description="Raw SQL query constructed with string formatting",
        severity="CRITICAL",
        status="OPEN",
        rule_id="python.lang.security.audit.sqli",
        category="Security",
        mitigation_guidance="Use parameterized queries",
        verification_verdict="CONFIRMED",
        verification_reason="Static analysis confirms user input reaches execute()",
        source_tool="semgrep",
        detector_id="python.lang.security.audit.sqli.rule-42",
        detector_kind="static_scanner",
    )
    db_session.add(fm)

    em = EvidenceModel(
        id=evidence_id,
        finding_id=finding_id,
        file_path="app/auth.py",
        start_line=25,
        end_line=30,
        code_snippet='db.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        context_notes="User parameter unescaped in auth query",
    )
    db_session.add(em)
    db_session.commit()

    # Query with relationships loaded
    loaded_fm = db_session.query(FindingModel).filter(FindingModel.id == finding_id).first()
    assert loaded_fm is not None

    schema = finding_model_to_schema(loaded_fm)
    assert str(schema.id) == finding_id
    assert str(schema.scan_id) == scan_id
    assert schema.title == "SQL Injection in auth handler"
    assert schema.severity.value == "CRITICAL"
    assert schema.status.value == "OPEN"
    assert schema.rule_id == "python.lang.security.audit.sqli"
    assert schema.category == "Security"
    assert schema.mitigation_guidance == "Use parameterized queries"
    assert schema.verification_verdict.value == "CONFIRMED"
    assert schema.source_tool == "semgrep"
    assert schema.detector_id == "python.lang.security.audit.sqli.rule-42"
    assert schema.detector_kind == "static_scanner"
    assert len(schema.evidences) == 1
    assert schema.evidences[0].file_path == "app/auth.py"
    assert schema.evidences[0].start_line == 25
    assert schema.evidences[0].end_line == 30
    assert "db.execute" in schema.evidences[0].code_snippet
    assert schema.evidences[0].context_notes == "User parameter unescaped in auth query"


def test_route_contract_and_secret_detector_provenance_preserved(db_session: Session):
    from app.services.domain_mapping import finding_model_to_schema

    fm1 = FindingModel(
        id=str(uuid4()),
        scan_id=str(uuid4()),
        title="Route parameter mismatch",
        description="Route path parameter does not match handler signature",
        severity="MEDIUM",
        status="OPEN",
        rule_id="route.contract.mismatch",
        category="Architecture",
        verification_verdict="CONFIRMED",
        source_tool="route_contract",
        detector_id="fastapi.route.param_check",
        detector_kind="contract_matcher",
    )
    fm2 = FindingModel(
        id=str(uuid4()),
        scan_id=str(uuid4()),
        title="Hardcoded API key detected",
        description="High entropy string matched known API key format",
        severity="CRITICAL",
        status="OPEN",
        rule_id="secret.api_key",
        category="Security",
        verification_verdict="CONFIRMED",
        source_tool="repolens-secret",
        detector_id="entropy.high_confidence_token",
        detector_kind="deterministic_secret",
    )
    db_session.add_all([fm1, fm2])
    db_session.commit()

    s1 = finding_model_to_schema(fm1)
    assert s1.source_tool == "route_contract"
    assert s1.detector_kind == "contract_matcher"

    s2 = finding_model_to_schema(fm2)
    assert s2.source_tool == "repolens-secret"
    assert s2.detector_kind == "deterministic_secret"


# ============================================================
# FIX 3: Tree and Parent Reconciliation for Existing Delivery Branches
# ============================================================

@pytest.mark.asyncio
async def test_existing_branch_matching_head_sha_wrong_tree_blocked(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    branch_name = sanitize_branch_name(finding.id, patch.id)
    head_sha = "2222222222222222222222222222222222222222"

    mock_provider = MockDeliveryProvider()
    mock_provider.branches[branch_name] = head_sha
    # Commit with WRONG tree_sha
    mock_provider.commits[head_sha] = GitCommitInfo(
        sha=head_sha,
        tree_sha="wrong_tree_sha_0000000000000000000000",
        parents=[scan.commit_hash],
    )

    # Pre-create delivery with head_sha matching the branch
    delivery = DeliveryModel(
        scan_id=scan.id,
        finding_id=finding.id,
        patch_id=patch.id,
        provider="github",
        repository_url=scan.repository_url,
        repository_owner="example-org",
        repository_name="secure-app",
        base_branch=scan.branch,
        scanned_base_sha=scan.commit_hash,
        head_branch=branch_name,
        head_sha=head_sha,
        status=DeliveryStatus.CREATING_COMMIT.value,
        idempotency_key=compute_idempotency_key("example-org", "secure-app", patch.id, scan.branch, scan.commit_hash),
        attempt_count=1,
    )
    db_session.add(delivery)
    db_session.commit()

    from contextlib import contextmanager
    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.FAILED.value
        assert res.failure_code == "HEAD_BRANCH_COLLISION"
        assert len(mock_provider.prs_created) == 0


@pytest.mark.asyncio
async def test_existing_branch_matching_head_sha_two_parents_merge_commit_blocked(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    branch_name = sanitize_branch_name(finding.id, patch.id)
    head_sha = "2222222222222222222222222222222222222222"

    mock_provider = MockDeliveryProvider()
    mock_provider.branches[branch_name] = head_sha
    # Commit with TWO parents (merge commit)
    mock_provider.commits[head_sha] = GitCommitInfo(
        sha=head_sha,
        tree_sha="tree_1",
        parents=[scan.commit_hash, "9999999999999999999999999999999999999999"],
    )

    delivery = DeliveryModel(
        scan_id=scan.id,
        finding_id=finding.id,
        patch_id=patch.id,
        provider="github",
        repository_url=scan.repository_url,
        repository_owner="example-org",
        repository_name="secure-app",
        base_branch=scan.branch,
        scanned_base_sha=scan.commit_hash,
        head_branch=branch_name,
        head_sha=head_sha,
        status=DeliveryStatus.CREATING_COMMIT.value,
        idempotency_key=compute_idempotency_key("example-org", "secure-app", patch.id, scan.branch, scan.commit_hash),
        attempt_count=1,
    )
    db_session.add(delivery)
    db_session.commit()

    from contextlib import contextmanager
    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.FAILED.value
        assert res.failure_code == "HEAD_BRANCH_COLLISION"
        assert len(mock_provider.prs_created) == 0


@pytest.mark.asyncio
async def test_existing_branch_missing_head_sha_merge_commit_blocked(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    branch_name = sanitize_branch_name(finding.id, patch.id)
    head_sha = "2222222222222222222222222222222222222222"

    mock_provider = MockDeliveryProvider()
    mock_provider.branches[branch_name] = head_sha
    # Merge commit with scanned_sha as one of multiple parents
    mock_provider.commits[head_sha] = GitCommitInfo(
        sha=head_sha,
        tree_sha="tree_1",
        parents=[scan.commit_hash, "8888888888888888888888888888888888888888"],
    )

    from contextlib import contextmanager
    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)
        res = await service.deliver_patch(db=db_session, patch_id=patch.id, payload=DeliveryRequest())

        assert res.status == DeliveryStatus.FAILED.value
        assert res.failure_code == "HEAD_BRANCH_COLLISION"
        assert len(mock_provider.prs_created) == 0


# ============================================================
# FIX 4: Remote PR Success + Local DB Failure Recovery
# ============================================================

@pytest.mark.asyncio
async def test_phase5_remote_pr_created_local_db_failure_recovery(db_session: Session, base_entities):
    scan, finding, patch = base_entities
    patch_id = patch.id
    mock_provider = MockDeliveryProvider()

    from contextlib import contextmanager
    @contextmanager
    def _fake_snapshot(scan_id, db=None):
        with tempfile.TemporaryDirectory() as fresh_ws:
            os.makedirs(os.path.join(fresh_ws, "app"), exist_ok=True)
            with open(os.path.join(fresh_ws, "app", "storage.py"), "w", encoding="utf-8") as f:
                f.write("def read_file(p):\n    return open(p)\n")
            yield fresh_ws

    # Wrap mock_provider.create_pull_request to record PR in prs dict so reconciliation finds it
    orig_create_pr = mock_provider.create_pull_request
    async def _recording_create_pr(owner, repo, title, body, head, base):
        pr = await orig_create_pr(owner, repo, title, body, head, base)
        mock_provider.prs[f"{head}:{base}"] = pr
        return pr
    mock_provider.create_pull_request = _recording_create_pr

    with mock_patch("app.delivery.service.get_snapshot_service") as mock_snap, \
         mock_patch("app.delivery.validator.get_snapshot_service") as mock_val_snap:
        mock_inst = MagicMock()
        mock_inst.snapshot_context.side_effect = _fake_snapshot
        mock_snap.return_value = mock_inst
        mock_val_snap.return_value = mock_inst

        service = DeliveryService(provider=mock_provider)

        from sqlalchemy import event
        from sqlalchemy.exc import SQLAlchemyError

        # Inject real SQLAlchemy flush failure during PR_CREATED transition via before_flush listener
        fail_injected = False

        def _fail_on_pr_created_flush(session, flush_context, instances):
            nonlocal fail_injected
            if not fail_injected:
                for obj in session.dirty:
                    if isinstance(obj, DeliveryModel) and obj.status == DeliveryStatus.PR_CREATED.value:
                        fail_injected = True
                        raise SQLAlchemyError("Simulated real SQLAlchemy flush failure on PR_CREATED commit")

        event.listen(db_session, "before_flush", _fail_on_pr_created_flush)

        try:
            # Attempt 1: Remote PR succeeds, but real SQLAlchemy flush fails and rolls back safely!
            res1 = await service.deliver_patch(db=db_session, patch_id=patch_id, payload=DeliveryRequest())
            assert res1.status == DeliveryStatus.FAILED.value
            assert res1.failure_code == "LOCAL_STATE_PERSISTENCE_FAILED"
            assert len(mock_provider.prs_created) == 1
        finally:
            event.remove(db_session, "before_flush", _fail_on_pr_created_flush)

        # Attempt 2 (Retry on session): Reconciles existing PR and existing branch!
        res2 = await service.deliver_patch(db=db_session, patch_id=patch_id, payload=DeliveryRequest())
        assert res2.status == DeliveryStatus.PR_CREATED.value
        assert res2.pr_number == 1
        assert res2.pr_url == "https://github.com/example-org/secure-app/pull/1"
        assert len(mock_provider.prs_created) == 1  # Still exactly 1 PR created!

        # Assert remote branch HEAD == final DeliveryModel.head_sha
        remote_branch_head = await mock_provider.get_branch_head(
            owner=res2.repository_owner,
            repo=res2.repository_name,
            branch=res2.head_branch,
        )
        assert remote_branch_head == res2.head_sha

        # Assert exactly one delivery row
        all_deliveries = db_session.query(DeliveryModel).filter(DeliveryModel.patch_id == patch_id).all()
        assert len(all_deliveries) == 1

        # Check event exists in session
        events = WorkflowEventService.list_for_delivery(db=db_session, delivery_id=res2.id)
        event_types = [e.event_type for e in events]
        assert "DELIVERY_PR_CREATED" in event_types


@pytest.mark.asyncio
async def test_phase5_remote_pr_success_real_db_transaction_failure_recovery(db_session: Session, base_entities):
    """Alias pointing to the real transaction failure recovery test."""
    await test_phase5_remote_pr_created_local_db_failure_recovery(db_session, base_entities)









