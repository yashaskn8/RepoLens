"""Comprehensive tests for Public GitHub PR Read Mode and Durable Change Analysis Workflow."""

import asyncio
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
import httpx
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.workflow import execute_background_change_analysis
from app.analysis.workflow_graph import build_change_analysis_graph
from app.core.database import SessionLocal, get_db
from app.ingestion.github_pr import (
    GitHubPRAPIError,
    GitHubPRForbiddenError,
    GitHubPRNotFoundError,
    GitHubPRRateLimitError,
    GitHubPRResolver,
    GitHubPRTimeoutError,
    InvalidPullRequestURLError,
    get_github_pr_resolver,
)
from app.main import app
from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.change_analysis import (
    ChangeAnalysisPRRequest,
    ChangeAnalysisRequest,
    ChangeAnalysisStatus,
    ResolvedPullRequest,
)
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.services.workflow_event_service import WorkflowEventService


class MockAsyncClient:
    """Mock HTTPX client capturing calls and returning canned responses."""

    def __init__(self, status_code: int = 200, json_data: Optional[Dict[str, Any]] = None, text: str = ""):
        self.status_code = status_code
        self.json_data = json_data or {}
        self.text = text
        self.calls: List[Dict[str, Any]] = []

    async def get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: Optional[Any] = None) -> httpx.Response:
        self.calls.append({"method": "GET", "url": url, "headers": headers})
        request = httpx.Request("GET", url)
        return httpx.Response(
            status_code=self.status_code,
            json=self.json_data,
            text=self.text or json.dumps(self.json_data),
            request=request,
        )

    async def post(self, url: str, *args, **kwargs):
        self.calls.append({"method": "POST", "url": url})
        raise RuntimeError("POST is strictly forbidden in read-only PR resolution!")


@pytest.fixture
def mock_pr_payload() -> Dict[str, Any]:
    """Canned GitHub API response for a public PR."""
    return {
        "title": "Refactor auth tokens and middleware",
        "state": "open",
        "base": {
            "ref": "main",
            "sha": "1111111111111111111111111111111111111111",
        },
        "head": {
            "ref": "feature/auth-refactor",
            "sha": "2222222222222222222222222222222222222222",
            "repo": {
                "html_url": "https://github.com/contributor/fastapi",
                "fork": True,
            },
        },
    }


# =========================================================================
# 1. PR URL Parsing Tests
# =========================================================================

def test_pr_url_parsing_valid():
    """Verify valid GitHub PR URL formats parse accurately."""
    resolver = GitHubPRResolver()

    # Standard format
    can_url, owner, repo, pr_num = resolver.parse_pr_url("https://github.com/fastapi/fastapi/pull/456")
    assert can_url == "https://github.com/fastapi/fastapi/pull/456"
    assert owner == "fastapi"
    assert repo == "fastapi"
    assert pr_num == 456

    # With trailing slash
    can_url, owner, repo, pr_num = resolver.parse_pr_url("https://github.com/encode/uvicorn/pull/789/")
    assert can_url == "https://github.com/encode/uvicorn/pull/789"
    assert owner == "encode"
    assert repo == "uvicorn"
    assert pr_num == 789

    # With .git in repo
    can_url, owner, repo, pr_num = resolver.parse_pr_url("https://github.com/psf/black.git/pull/12")
    assert can_url == "https://github.com/psf/black/pull/12"
    assert owner == "psf"
    assert repo == "black"
    assert pr_num == 12


def test_malformed_pr_url_rejected():
    """Verify malformed or invalid PR URLs raise InvalidPullRequestURLError."""
    resolver = GitHubPRResolver()

    invalid_urls = [
        "not-a-url",
        "https://github.com/fastapi/fastapi",  # Missing /pull/123
        "https://github.com/fastapi/fastapi/pull/notanumber",
        "https://github.com/fastapi/fastapi/pull/0",
        "https://github.com/fastapi/fastapi/pull/-5",
        "https://user:pass@github.com/fastapi/fastapi/pull/123",  # Credentials
        "https://github.com/fastapi/fastapi/pull/123; rm -rf /",  # Injection
        "http://github.com/fastapi/fastapi/pull/123",  # Non-HTTPS
    ]

    for inv_url in invalid_urls:
        with pytest.raises(InvalidPullRequestURLError):
            resolver.parse_pr_url(inv_url)


def test_non_github_host_rejected():
    """Verify non-GitHub hosts are strictly rejected."""
    resolver = GitHubPRResolver()

    non_github_urls = [
        "https://gitlab.com/fastapi/fastapi/pull/123",
        "https://bitbucket.org/fastapi/fastapi/pull/123",
        "https://evil.com/github.com/fastapi/fastapi/pull/123",
    ]

    for inv_url in non_github_urls:
        with pytest.raises(InvalidPullRequestURLError):
            resolver.parse_pr_url(inv_url)


# =========================================================================
# 2. Public PR Resolution & Error Handling Tests
# =========================================================================

@pytest.mark.asyncio
async def test_successful_pr_resolution_and_zero_writes(mock_pr_payload):
    """Verify successful public PR resolution resolves exact immutable SHAs with zero write requests."""
    mock_client = MockAsyncClient(status_code=200, json_data=mock_pr_payload)
    resolver = GitHubPRResolver(client=mock_client)

    resolved: ResolvedPullRequest = await resolver.resolve_pr("https://github.com/fastapi/fastapi/pull/1234")

    assert resolved.repository_url == "https://github.com/fastapi/fastapi"
    assert resolved.repository_owner == "fastapi"
    assert resolved.repository_name == "fastapi"
    assert resolved.pr_number == 1234
    assert resolved.title == "Refactor auth tokens and middleware"
    assert resolved.base_branch == "main"
    assert resolved.base_commit_sha == "1111111111111111111111111111111111111111"
    assert resolved.head_branch == "feature/auth-refactor"
    assert resolved.head_commit_sha == "2222222222222222222222222222222222222222"
    assert resolved.is_fork is True

    # Zero writes assertion
    assert len(mock_client.calls) == 1
    assert mock_client.calls[0]["method"] == "GET"
    assert "https://api.github.com/repos/fastapi/fastapi/pulls/1234" in mock_client.calls[0]["url"]


@pytest.mark.asyncio
async def test_pr_resolution_404_not_found():
    """Verify 404 maps to GitHubPRNotFoundError."""
    mock_client = MockAsyncClient(status_code=404, json_data={"message": "Not Found"})
    resolver = GitHubPRResolver(client=mock_client)

    with pytest.raises(GitHubPRNotFoundError) as exc_info:
        await resolver.resolve_pr("https://github.com/fastapi/fastapi/pull/9999")
    assert "not found" in exc_info.value.message.lower()


@pytest.mark.asyncio
async def test_pr_resolution_403_rate_limit():
    """Verify 403 / 429 maps to rate limit / forbidden errors."""
    mock_client = MockAsyncClient(status_code=403, json_data={"message": "API rate limit exceeded"})
    resolver = GitHubPRResolver(client=mock_client)

    with pytest.raises(GitHubPRRateLimitError):
        await resolver.resolve_pr("https://github.com/fastapi/fastapi/pull/123")


@pytest.mark.asyncio
async def test_pr_resolution_500_server_error():
    """Verify 5xx maps to GitHubPRAPIError."""
    mock_client = MockAsyncClient(status_code=502, text="Bad Gateway")
    resolver = GitHubPRResolver(client=mock_client)

    with pytest.raises(GitHubPRAPIError) as exc_info:
        await resolver.resolve_pr("https://github.com/fastapi/fastapi/pull/123")
    assert exc_info.value.status_code == 502


# =========================================================================
# 3. Immutability Test (PR Updated after Analysis Begins)
# =========================================================================

@pytest.mark.asyncio
async def test_pr_immutability_preserves_initial_shas(db_session: Session, mock_pr_payload):
    """Verify that even if the PR branch moves upstream later, the persisted ChangeAnalysis operates strictly on immutable SHAs."""
    mock_client = MockAsyncClient(status_code=200, json_data=mock_pr_payload)
    resolver = GitHubPRResolver(client=mock_client)

    resolved: ResolvedPullRequest = await resolver.resolve_pr("https://github.com/fastapi/fastapi/pull/123")

    analysis = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url=resolved.repository_url,
        repository_owner=resolved.repository_owner,
        repository_name=resolved.repository_name,
        base_ref=resolved.base_branch,
        base_commit_sha=resolved.base_commit_sha,
        head_ref=resolved.head_branch,
        head_commit_sha=resolved.head_commit_sha,
        status="PENDING",
        model_metadata={"pr_number": resolved.pr_number},
    )
    db_session.add(analysis)
    db_session.commit()
    db_session.refresh(analysis)

    # Simulate upstream PR head moving to a new commit
    updated_payload = dict(mock_pr_payload)
    updated_payload["head"] = {
        "ref": "feature/auth-refactor",
        "sha": "3333333333333333333333333333333333333333",  # NEW SHA!
    }
    mock_client.json_data = updated_payload

    # Analysis in DB remains strictly pegged to immutable original SHA
    refetched = db_session.query(ChangeAnalysisModel).filter(ChangeAnalysisModel.id == analysis.id).first()
    assert refetched.head_commit_sha == "2222222222222222222222222222222222222222"
    assert refetched.base_commit_sha == "1111111111111111111111111111111111111111"


# =========================================================================
# 4. API Endpoints Integration Tests
# =========================================================================

def test_api_create_change_analysis_exact_shas(client: TestClient, db_session: Session):
    """Verify POST /api/v1/change-analyses returns 202 Accepted and creates DB record."""
    payload = {
        "repository_url": "https://github.com/fastapi/fastapi",
        "base_commit_sha": "1111111111111111111111111111111111111111",
        "head_commit_sha": "2222222222222222222222222222222222222222",
        "base_ref": "main",
        "head_ref": "feature/auth",
    }

    response = client.post("/api/v1/change-analyses", json=payload)
    assert response.status_code == status.HTTP_202_ACCEPTED
    data = response.json()

    assert data["repository_url"] == "https://github.com/fastapi/fastapi"
    assert data["base_commit_sha"] == "1111111111111111111111111111111111111111"
    assert data["head_commit_sha"] == "2222222222222222222222222222222222222222"
    assert data["status"] in ("PENDING", "ACQUIRING", "DIFFING", "COMPLETED", "FAILED")

    analysis_id = data["id"]
    # Check GET /api/v1/change-analyses/{id}
    get_res = client.get(f"/api/v1/change-analyses/{analysis_id}")
    assert get_res.status_code == status.HTTP_200_OK
    assert get_res.json()["id"] == analysis_id


def test_api_create_change_analysis_from_pr(client: TestClient, db_session: Session, mock_pr_payload, monkeypatch):
    """Verify POST /api/v1/change-analyses/from-pr returns 202 Accepted and resolves PR."""
    mock_client = MockAsyncClient(status_code=200, json_data=mock_pr_payload)
    custom_resolver = GitHubPRResolver(client=mock_client)
    monkeypatch.setattr("app.api.routes.change_analysis.get_github_pr_resolver", lambda: custom_resolver)

    payload = {"pr_url": "https://github.com/fastapi/fastapi/pull/123"}
    response = client.post("/api/v1/change-analyses/from-pr", json=payload)

    assert response.status_code == status.HTTP_202_ACCEPTED
    data = response.json()

    assert data["repository_url"] == "https://github.com/fastapi/fastapi"
    assert data["base_commit_sha"] == "1111111111111111111111111111111111111111"
    assert data["head_commit_sha"] == "2222222222222222222222222222222222222222"
    assert data["model_metadata"]["pr_number"] == 123


def test_api_get_impacts_and_review(client: TestClient, db_session: Session):
    """Verify GET /api/v1/change-analyses/{id}/impacts and /review."""
    analysis_id = str(uuid4())
    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url="https://github.com/fastapi/fastapi",
        repository_owner="fastapi",
        repository_name="fastapi",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        status="COMPLETED",
        risk_level="HIGH",
        impacted_symbols_count=1,
        model_metadata={
            "review_report": {
                "analysis_id": analysis_id,
                "summary": "Sample AI review",
                "findings": [],
                "total_findings": 0,
                "overall_risk_level": "HIGH",
            }
        },
    )
    db_session.add(analysis)

    impact = ChangeImpactModel(
        id=str(uuid4()),
        analysis_id=analysis_id,
        impact_type="CALLER_IMPACT",
        severity="HIGH",
        title="Direct caller login broken",
        description="Login calls deleted auth fn",
        source_file="app/services/auth.py",
        affected_file="app/api/auth.py",
        evidence_payload={"depth": 1},
        confidence=1.0,
        verification_status="FACT",
    )
    db_session.add(impact)
    db_session.commit()

    # GET impacts
    imp_res = client.get(f"/api/v1/change-analyses/{analysis_id}/impacts")
    assert imp_res.status_code == status.HTTP_200_OK
    assert len(imp_res.json()) == 1
    assert imp_res.json()[0]["title"] == "Direct caller login broken"

    # GET review
    rev_res = client.get(f"/api/v1/change-analyses/{analysis_id}/review")
    assert rev_res.status_code == status.HTTP_200_OK
    assert rev_res.json()["summary"] == "Sample AI review"


def test_api_list_analyses_and_events(client: TestClient, db_session: Session):
    """Verify GET /api/v1/change-analyses and GET /api/v1/change-analyses/{id}/events."""
    analysis_id = str(uuid4())
    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url="https://github.com/fastapi/fastapi",
        repository_owner="fastapi",
        repository_name="fastapi",
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        status="COMPLETED",
    )
    db_session.add(analysis)
    db_session.commit()

    WorkflowEventService.emit(
        db=db_session,
        event=WorkflowEventCreate(
            event_type=WorkflowEventType.CHANGE_ANALYSIS_REQUESTED,
            change_analysis_id=UUID(analysis_id),
            message="Analysis requested",
        ),
    )
    db_session.commit()

    # List analyses
    list_res = client.get("/api/v1/change-analyses")
    assert list_res.status_code == status.HTTP_200_OK
    assert any(a["id"] == analysis_id for a in list_res.json())

    # Get events
    ev_res = client.get(f"/api/v1/change-analyses/{analysis_id}/events")
    assert ev_res.status_code == status.HTTP_200_OK
    assert len(ev_res.json()) >= 1
    assert ev_res.json()[0]["event_type"] == "CHANGE_ANALYSIS_REQUESTED"
