"""API contract and route tests for Review Publication (Phase 7).

Uses FastAPI TestClient and conftest fixtures to test all endpoints:
- GET /api/v1/change-analyses/{id}/review-publication
- POST /api/v1/change-analyses/{id}/review-publication/preview
- POST /api/v1/change-analyses/{id}/review-publication/approve
- POST /api/v1/change-analyses/{id}/review-publication/publish
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
import pytest

from app.models.change_analysis import ChangeAnalysisModel
from app.models.review_publication import PullRequestReviewPublicationModel
from app.schemas.change_analysis import ResolvedPullRequest
from app.schemas.review_publication import ReviewPublicationStatus


def _create_test_analysis(db, status="COMPLETED", is_fork=False):
    """Create ChangeAnalysisModel with canonical Phase 6 top-level metadata."""
    analysis = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/octocat/Hello-World",
        repository_owner="octocat",
        repository_name="Hello-World",
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        status=status,
        model_metadata={
            "pr_url": "https://github.com/octocat/Hello-World/pull/42",
            "pr_number": 42,
            "pr_title": "Improve performance",
            "head_repo_url": "https://github.com/octocat/Hello-World",
            "is_fork": is_fork,
            "pr_state": "open",
        },
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis


def test_api_get_publication_not_found(client, db_session):
    """GET on non-existent publication returns 404."""
    analysis_id = str(uuid4())
    resp = client.get(f"/api/v1/change-analyses/{analysis_id}/review-publication")
    assert resp.status_code == 404


def test_api_get_publication_success(client, db_session):
    """GET returns full preview response with deserialized inline comments."""
    analysis = _create_test_analysis(db_session)
    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=analysis.id,
        repository_owner="octocat",
        repository_name="Hello-World",
        pr_number=42,
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        status=ReviewPublicationStatus.PREVIEW_READY.value,
        preview_body="## Review Summary",
        preview_digest="d" * 64,
        inline_comments_payload=[
            {
                "path": "app/main.py",
                "line": 10,
                "side": "RIGHT",
                "body": "Fix this bug",
                "finding_title": "SQL Injection",
                "severity": "HIGH",
            }
        ],
    )
    db_session.add(pub)
    db_session.commit()

    resp = client.get(f"/api/v1/change-analyses/{analysis.id}/review-publication")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "PREVIEW_READY"
    assert data["preview_digest"] == "d" * 64
    assert len(data["inline_comments"]) == 1
    assert data["inline_comments"][0]["path"] == "app/main.py"
    assert data["inline_comments"][0]["line"] == 10
    assert data["inline_comments"][0]["side"] == "RIGHT"
    assert data["inline_comments"][0]["body"] == "Fix this bug"


@patch("app.services.review_publication_service.GitHubReviewPublicationProvider")
def test_api_post_preview_success(mock_provider_cls, client, db_session):
    """POST /preview generates deterministic preview and returns 200."""
    mock_provider = MagicMock()
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/Hello-World",
            repository_owner="octocat",
            repository_name="Hello-World",
            pr_number=42,
            title="Improve performance",
            base_branch="main",
            base_commit_sha="1" * 40,
            head_branch="feature",
            head_commit_sha="2" * 40,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])
    mock_provider_cls.return_value = mock_provider

    analysis = _create_test_analysis(db_session)

    resp = client.post(f"/api/v1/change-analyses/{analysis.id}/review-publication/preview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "PREVIEW_READY"
    assert len(data["preview_digest"]) == 64
    assert data["review_event"] == "COMMENT"


def test_api_post_approve_digest_mismatch(client, db_session):
    """POST /approve with wrong digest returns 409."""
    analysis = _create_test_analysis(db_session)
    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=analysis.id,
        repository_owner="octocat",
        repository_name="Hello-World",
        pr_number=42,
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        status=ReviewPublicationStatus.PREVIEW_READY.value,
        preview_digest="correct_digest_" + "a" * 49,
    )
    db_session.add(pub)
    db_session.commit()

    resp = client.post(
        f"/api/v1/change-analyses/{analysis.id}/review-publication/approve",
        json={"expected_preview_digest": "wrong_digest_" + "b" * 51},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["error_code"] == "PREVIEW_DIGEST_MISMATCH"


def test_api_post_publish_without_approval_rejected(client, db_session):
    """POST /publish on PREVIEW_READY publication returns 409 PUBLICATION_NOT_APPROVED."""
    analysis = _create_test_analysis(db_session)
    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=analysis.id,
        repository_owner="octocat",
        repository_name="Hello-World",
        pr_number=42,
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        status=ReviewPublicationStatus.PREVIEW_READY.value,
        preview_digest="d" * 64,
    )
    db_session.add(pub)
    db_session.commit()

    resp = client.post(
        f"/api/v1/change-analyses/{analysis.id}/review-publication/publish",
        json={"expected_preview_digest": "d" * 64},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["error_code"] == "PUBLICATION_NOT_APPROVED"
