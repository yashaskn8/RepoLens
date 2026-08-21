"""Tests for Phase 3.5P: Truthful branch metadata and exact commit SHA resolution."""

import os
import subprocess
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.core.database import Base, engine, get_db
from app.ingestion.clone import get_git_resolved_branch_or_ref
from app.ingestion.manifest import build_manifest
from app.main import app
from app.models.scan import ScanModel
from app.schemas.scan import ScanCreate


def _init_git_repo(repo_dir: str, branch_name: str = "main") -> str:
    """Initialize a git repository with an initial commit on a specified branch name."""
    subprocess.run(["git", "init", f"--initial-branch={branch_name}"], cwd=repo_dir, capture_output=True, check=False)
    # Configure local git user if not present in environment
    subprocess.run(["git", "config", "user.name", "Test Runner"], cwd=repo_dir, capture_output=True, check=False)
    subprocess.run(["git", "config", "user.email", "test@repolens.ai"], cwd=repo_dir, capture_output=True, check=False)

    # Ensure branch name is active
    subprocess.run(["git", "checkout", "-B", branch_name], cwd=repo_dir, capture_output=True, check=False)

    sample_file = os.path.join(repo_dir, "app.py")
    with open(sample_file, "w", encoding="utf-8") as f:
        f.write("def run():\n    return 42\n")

    subprocess.run(["git", "add", "app.py"], cwd=repo_dir, capture_output=True, check=False)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, capture_output=True, check=False)

    rev_res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, capture_output=True, text=True, check=False)
    return rev_res.stdout.strip()


# =============================================================================
# 1. Main Default Branch Resolution
# =============================================================================

def test_truthful_branch_resolution_main():
    """Verify repository with default branch 'main' correctly resolves to 'main'."""
    with tempfile.TemporaryDirectory(prefix="repo_main_") as tmp_dir:
        commit_sha = _init_git_repo(tmp_dir, branch_name="main")

        resolved_ref = get_git_resolved_branch_or_ref(tmp_dir)
        assert resolved_ref == "main"

        manifest = build_manifest(
            repo_dir=tmp_dir,
            repository_url="https://github.com/org/repo-main.git",
            commit_hash=commit_sha,
            requested_branch=None,
        )

        assert manifest.commit_hash == commit_sha
        assert manifest.commit_sha == commit_sha
        assert manifest.resolved_branch_or_ref == "main"
        assert manifest.requested_branch is None
        assert manifest.branch == "main"


# =============================================================================
# 2. Master Default Branch Resolution (No False Default to "main")
# =============================================================================

def test_truthful_branch_resolution_master():
    """Verify repository with default branch 'master' resolves to 'master' without defaulting to 'main'."""
    with tempfile.TemporaryDirectory(prefix="repo_master_") as tmp_dir:
        commit_sha = _init_git_repo(tmp_dir, branch_name="master")

        resolved_ref = get_git_resolved_branch_or_ref(tmp_dir)
        assert resolved_ref == "master"

        # Manifest built without explicit branch requested
        manifest = build_manifest(
            repo_dir=tmp_dir,
            repository_url="https://github.com/org/legacy-repo.git",
            commit_hash=commit_sha,
            requested_branch=None,
        )

        assert manifest.commit_hash == commit_sha
        assert manifest.commit_sha == commit_sha
        assert manifest.resolved_branch_or_ref == "master"
        assert manifest.requested_branch is None
        assert manifest.branch == "master"


# =============================================================================
# 3. Custom Explicit Branch Resolution
# =============================================================================

def test_truthful_branch_resolution_custom_explicit_branch():
    """Verify explicit custom branch is recorded as requested_branch and resolved_branch_or_ref."""
    with tempfile.TemporaryDirectory(prefix="repo_custom_") as tmp_dir:
        commit_sha = _init_git_repo(tmp_dir, branch_name="feature/security-patch")

        resolved_ref = get_git_resolved_branch_or_ref(tmp_dir)
        assert resolved_ref == "feature/security-patch"

        manifest = build_manifest(
            repo_dir=tmp_dir,
            repository_url="https://github.com/org/feature-repo.git",
            commit_hash=commit_sha,
            branch="feature/security-patch",
            requested_branch="feature/security-patch",
        )

        assert manifest.requested_branch == "feature/security-patch"
        assert manifest.resolved_branch_or_ref == "feature/security-patch"
        assert manifest.branch == "feature/security-patch"
        assert manifest.commit_sha == commit_sha


# =============================================================================
# 4. No Explicit Branch Supplied in Schema & Request
# =============================================================================

def test_truthful_branch_resolution_no_explicit_branch():
    """Verify ScanCreate schema does not force 'main' when no branch is provided."""
    req = ScanCreate(repository_url="https://github.com/org/unspecified-repo.git")
    assert req.branch is None
    assert req.requested_branch is None


# =============================================================================
# 5. Detached Exact Commit SHA Resolution
# =============================================================================

def test_truthful_branch_resolution_detached_exact_sha():
    """Verify detached HEAD state records exact SHA as authoritative identity and avoids fake branch names."""
    with tempfile.TemporaryDirectory(prefix="repo_detached_") as tmp_dir:
        commit_sha = _init_git_repo(tmp_dir, branch_name="main")

        # Detach HEAD to exact commit SHA
        subprocess.run(["git", "checkout", "--detach", commit_sha], cwd=tmp_dir, capture_output=True, check=False)

        resolved_ref = get_git_resolved_branch_or_ref(tmp_dir)
        assert resolved_ref is not None
        assert resolved_ref.startswith("HEAD@") or resolved_ref == "HEAD"

        manifest = build_manifest(
            repo_dir=tmp_dir,
            repository_url="https://github.com/org/detached-repo.git",
            commit_hash=commit_sha,
            requested_branch=None,
        )

        assert manifest.commit_hash == commit_sha
        assert manifest.commit_sha == commit_sha
        assert manifest.requested_branch is None
        assert manifest.resolved_branch_or_ref.startswith("HEAD@") or manifest.resolved_branch_or_ref == "HEAD"


# =============================================================================
# 6. Scans API Contract: Truthful Branch Exposure
# =============================================================================

def test_scans_api_truthful_branch_contract():
    """Verify Scans API endpoint creates and retrieves scan with truthful branch distinctions."""
    client = TestClient(app)

    # 1. Create scan with explicit custom branch
    res1 = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/org/custom-repo", "branch": "release-v2.1"},
    )
    assert res1.status_code == 202
    data1 = res1.json()
    assert data1["requested_branch"] == "release-v2.1"
    assert data1["branch"] == "release-v2.1"

    # 2. Create scan with NO branch specified
    res2 = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/org/default-repo"},
    )
    assert res2.status_code == 202
    data2 = res2.json()
    assert data2["requested_branch"] is None
    assert data2["branch"] is None
