"""Phase 5 Security, Idempotency, and Failure-Hardening Unit Test Suite for RepoLens."""

import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch as mock_patch
from uuid import uuid4
import pytest
from fastapi import HTTPException
import httpx
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.delivery.github_provider import GitHubDeliveryProvider
from app.delivery.pr_body import generate_pr_body, generate_pr_title
from app.delivery.provider import RepositoryDeliveryProvider
from app.delivery.schemas import (
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
from app.schemas.enums import DeliveryStatus, FindingStatus, PatchStatus, ScanStatus, Severity
from app.schemas.delivery import DeliveryRequest


class MockDeliveryProvider(RepositoryDeliveryProvider):
    """Configurable in-memory delivery provider mock for unit testing."""

    def __init__(
        self,
        base_head_sha: str = "1111111111111111111111111111111111111111",
        base_tree_sha: str = "2222222222222222222222222222222222222222",
    ):
        self.base_head_sha = base_head_sha
        self.base_tree_sha = base_tree_sha
        self.blobs_created: list[dict] = []
        self.trees_created: list[dict] = []
        self.commits_created: list[dict] = []
        self.branches_created: list[dict] = []
        self.prs_created: list[dict] = []
        self.existing_pr: Optional[GitPullRequestInfo] = None

    async def get_branch_head(self, owner: str, repo: str, branch: str) -> str:
        return self.base_head_sha

    async def get_commit(self, owner: str, repo: str, sha: str) -> GitCommitInfo:
        return GitCommitInfo(sha=sha, tree_sha=self.base_tree_sha)

    async def create_blob(self, owner: str, repo: str, content: str, encoding: str = "utf-8") -> str:
        blob_sha = f"blob_{len(self.blobs_created) + 1}_{len(content)}"
        self.blobs_created.append({"owner": owner, "repo": repo, "content": content, "sha": blob_sha})
        return blob_sha

    async def create_tree(self, owner: str, repo: str, base_tree_sha: str, tree_entries: list[GitTreeEntry]) -> str:
        tree_sha = f"tree_{len(self.trees_created) + 1}"
        self.trees_created.append({"owner": owner, "repo": repo, "base_tree_sha": base_tree_sha, "entries": tree_entries, "sha": tree_sha})
        return tree_sha

    async def create_commit(self, owner: str, repo: str, message: str, tree_sha: str, parent_shas: list[str]) -> str:
        commit_sha = f"333333333333333333333333333333333333333{len(self.commits_created) + 1}"
        self.commits_created.append({"owner": owner, "repo": repo, "message": message, "tree_sha": tree_sha, "parents": parent_shas, "sha": commit_sha})
        return commit_sha

    async def create_branch(self, owner: str, repo: str, branch_name: str, sha: str) -> str:
        self.branches_created.append({"owner": owner, "repo": repo, "branch": branch_name, "sha": sha})
        return f"refs/heads/{branch_name}"

    async def find_existing_pull_request(self, owner: str, repo: str, head: str, base: str) -> Optional[GitPullRequestInfo]:
        return self.existing_pr

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

    valid_diff = "--- a/app/storage.py\n+++ b/app/storage.py\n@@ -1,2 +1,3 @@\n def read_file(p):\n+    validate(p)\n     return open(p)\n"
    patch = PatchModel(
        id=str(uuid4()),
        finding_id=finding.id,
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
