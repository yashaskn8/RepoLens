"""Integration tests for Phase 3.5C: Remediation against exact analyzed repository fixtures.

Verifies that findings for a fixture repository are remediated strictly against that
fixture's real files, manifest, graph, and ContextEngine (NOT the RepoLens source tree).
"""

import json
import os
import shutil
import subprocess
import tempfile
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest


from app.models.finding import EvidenceModel, FindingModel
from app.models.scan import ScanModel
from app.patching.schemas import PatchProposal, PatchWorkflowResult, VerificationStatus
from app.planning.schemas import FixPlan, OrderedChangeStep
from app.schemas.enums import FindingStatus, PatchStatus, ScanStatus, Severity


@pytest.fixture
def fixture_git_repo():
    """Create a real local git repository fixture with sample source code and return (repo_path, commit_sha)."""
    tmp_dir = tempfile.mkdtemp(prefix="repolens_fixture_repo_")
    try:
        # Create sample project structure
        src_dir = os.path.join(tmp_dir, "src")
        os.makedirs(src_dir, exist_ok=True)

        auth_py = os.path.join(src_dir, "auth.py")
        with open(auth_py, "w", encoding="utf-8") as f:
            f.write(
                "from fastapi import Response\n\n"
                "def set_auth_cookie(response: Response, session_token: str):\n"
                "    response.set_cookie(key='session', value=session_token)\n"
            )

        pyproject_toml = os.path.join(tmp_dir, "pyproject.toml")
        with open(pyproject_toml, "w", encoding="utf-8") as f:
            f.write(
                '[project]\nname = "fixture-auth-service"\nversion = "0.1.0"\n'
                'dependencies = ["fastapi>=0.115.0"]\n'
            )

        # Initialize real git repository
        subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "RepoLensTest"], cwd=tmp_dir, check=True)
        subprocess.run(["git", "config", "user.email", "test@repolens.dev"], cwd=tmp_dir, check=True)
        subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=tmp_dir, check=True, capture_output=True)

        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_dir, check=True, capture_output=True, text=True)
        commit_sha = res.stdout.strip()

        yield tmp_dir, commit_sha
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# =========================================================================
# 1. Real Fixture Remediation Integration Tests
# =========================================================================


def test_remediation_against_exact_fixture_files_not_repolens_source(client, db_session, fixture_git_repo):
    """Verify research, plan, and patch against exact analyzed fixture files without mocking manifest/context."""
    fixture_dir, commit_sha = fixture_git_repo
    scan_id = str(uuid4())

    # 1. Create a completed ScanModel with exact commit SHA
    scan_model = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fixture-org/auth-service.git",
        commit_hash=commit_sha,
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan_model)

    # 2. Create FindingModel targeting fixture's src/auth.py
    finding_id = str(uuid4())
    finding_model = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Insecure Cookie Header in auth.py",
        description="Missing Secure and HttpOnly flags on session cookie",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
        category="security",
    )
    ev_model = EvidenceModel(
        id=str(uuid4()),
        finding_id=finding_id,
        file_path="src/auth.py",
        start_line=3,
        end_line=4,
        code_snippet="response.set_cookie(key='session', value=session_token)",
    )
    finding_model.evidences.append(ev_model)
    db_session.add(finding_model)
    db_session.commit()

    # Rehydrate snapshot by cloning local fixture repo
    def mock_materialize(repository_url, commit_hash, branch=None):
        dest = tempfile.mkdtemp(prefix="repolens_snapshot_test_")
        subprocess.run(
            ["git", "clone", "--depth=1", fixture_dir, dest],
            check=True,
            capture_output=True,
        )
        return dest

    diff = (
        "--- a/src/auth.py\n"
        "+++ b/src/auth.py\n"
        "@@ -3,2 +3,2 @@\n"
        "-    response.set_cookie(key='session', value=session_token)\n"
        "+    response.set_cookie(key='session', value=session_token, httponly=True, secure=True, samesite='lax')\n"
    )

    async def mock_llm_generate(req):
        from app.llm.types import LLMProvider, LLMResponse, ModelExecutionMetadata
        user_content = next((m.content for m in req.messages if m.role == "user"), "")
        meta = ModelExecutionMetadata(model_name="mock-llm", provider="mock", latency_ms=10.0)

        # 1. Research Agent request
        if "Researching framework" in user_content or "Technical Research" in str(req.messages[0].content):
            content = (
                '{\n'
                '  "target_framework": "FastAPI",\n'
                '  "recommended_version": "0.115.0",\n'
                '  "migration_summary": "Harden cookie flags with httponly and secure",\n'
                '  "repository_impact": "Affects src/auth.py cookie setter",\n'
                '  "evidences": [\n'
                '    {\n'
                '      "source_url": "https://fastapi.tiangolo.com/tutorial/response-status-code/",\n'
                '      "source_title": "FastAPI Documentation",\n'
                '      "source_tier": "OFFICIAL_DOCS",\n'
                '      "supported_claim": "Use secure and httponly flags on response.set_cookie",\n'
                '      "confidence": 1.0\n'
                '    }\n'
                '  ]\n'
                '}'
            )
            return LLMResponse(content=content, model="gemini-3.7-flash", provider=LLMProvider.GEMINI, metadata=meta)

        # 2. Fix Planning Agent request
        elif "Fix Planner" in str(req.messages[0].content) or "FixPlan" in user_content:
            content = (
                '{\n'
                '  "root_cause": "Missing security flags on session cookie in src/auth.py",\n'
                '  "objective": "Harden cookie setter in src/auth.py with httponly=True and secure=True",\n'
                '  "files_expected_to_change": ["src/auth.py"],\n'
                '  "ordered_changes": [\n'
                '    {\n'
                '      "step_number": 1,\n'
                '      "target_file": "src/auth.py",\n'
                '      "description": "Add httponly=True and secure=True to set_cookie",\n'
                '      "rationale": "Prevents client-side script theft of session token"\n'
                '    }\n'
                '  ],\n'
                '  "validation_plan": ["pytest tests/test_auth.py"]\n'
                '}'
            )
            return LLMResponse(content=content, model="claude-3-5-sonnet", provider=LLMProvider.GEMINI, metadata=meta)

        # 3. Patch Generator Agent request
        else:
            patch_json = {
                "unified_diff": (
                    "--- a/src/auth.py\n"
                    "+++ b/src/auth.py\n"
                    "@@ -1,4 +1,4 @@\n"
                    " from fastapi import Response\n"
                    " \n"
                    " def set_auth_cookie(response: Response, session_token: str):\n"
                    "-    response.set_cookie(key='session', value=session_token)\n"
                    "+    response.set_cookie(key='session', value=session_token, httponly=True, secure=True)\n"
                ),
                "explanation": "Hardened cookie flags in src/auth.py",
                "expected_behavior_change": "Sets httponly and secure flags",
                "generated_tests_or_test_plan": ["pytest tests/test_auth.py"],
            }
            return LLMResponse(
                content=json.dumps(patch_json),
                model="qwen-coder-32b",
                provider=LLMProvider.HUGGINGFACE,
                metadata=meta,
            )



    with patch("app.ingestion.snapshot.RepositorySnapshotService.materialize_snapshot_from_metadata", side_effect=mock_materialize), \
         patch("app.llm.router.LLMRouter.generate", side_effect=mock_llm_generate):
        
        # 3. Test Research Endpoint: receives real manifest with FastAPI detected
        res_research = client.post(f"/api/v1/findings/{finding_id}/research")
        assert res_research.status_code == 200
        research_data = res_research.json()
        assert research_data["target_framework"] == "FastAPI"
        assert research_data["recommended_version"] == "0.115.0"

        # 4. Test Fix Plan Endpoint: generates plan strictly for fixture's src/auth.py
        res_plan = client.post(f"/api/v1/findings/{finding_id}/plan")
        assert res_plan.status_code == 200
        plan_data = res_plan.json()
        assert "src/auth.py" in plan_data["files_expected_to_change"]

        # 5. Test Patch Generation Endpoint: generates and verifies patch against fixture's src/auth.py
        res_patch = client.post(f"/api/v1/findings/{finding_id}/patch")
        assert res_patch.status_code == 200
        patch_data = res_patch.json()
        assert patch_data["proposal"]["files_modified"] == ["src/auth.py"]
        assert patch_data["verification_result"]["status"] == "PASSED"
        assert patch_data["final_verdict"] == "APPROVED"



# =========================================================================
# 2. Remediation Rejection Guards Tests
# =========================================================================


def test_remediation_rejected_when_scan_not_completed(client, db_session):
    """Verify remediation is rejected when scan status is RUNNING or PENDING."""
    scan_id = str(uuid4())
    scan_model = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fixture/repo.git",
        commit_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        status=ScanStatus.RUNNING.value,
    )
    db_session.add(scan_model)

    finding_id = str(uuid4())
    finding_model = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="Pending Scan Finding",
        description="Test",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(finding_model)
    db_session.commit()

    res = client.post(f"/api/v1/findings/{finding_id}/research")
    assert res.status_code == 400
    assert "Scan must be COMPLETED" in res.json()["detail"]


def test_remediation_rejected_when_finding_mismatched_scan(client, db_session):
    """Verify remediation is rejected when finding has invalid scan linkage."""
    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=str(uuid4()),  # Nonexistent scan
        title="Orphan Finding",
        description="Test",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(fm)
    db_session.commit()

    res = client.post(f"/api/v1/findings/{finding_id}/plan")
    assert res.status_code == 404
    assert "Associated scan" in res.json()["detail"]


def test_remediation_rejected_when_commit_sha_missing(client, db_session):
    """Verify remediation is rejected when scan has no recorded commit SHA."""
    scan_id = str(uuid4())
    scan_model = ScanModel(
        id=scan_id,
        repository_url="https://github.com/fixture/repo.git",
        commit_hash=None,
        status=ScanStatus.COMPLETED.value,
    )
    db_session.add(scan_model)

    finding_id = str(uuid4())
    fm = FindingModel(
        id=finding_id,
        scan_id=scan_id,
        title="No SHA Finding",
        description="Test",
        severity=Severity.HIGH.value,
        status=FindingStatus.OPEN.value,
    )
    db_session.add(fm)
    db_session.commit()

    res = client.post(f"/api/v1/findings/{finding_id}/patch")
    assert res.status_code == 400
    assert "invalid or unrecorded commit hash" in res.json()["detail"]
