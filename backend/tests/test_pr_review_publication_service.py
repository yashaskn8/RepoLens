"""Unit tests for ReviewPublicationService."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.base import Base
from app.models.change_analysis import ChangeAnalysisModel
from app.models.review_publication import PullRequestReviewPublicationModel
from app.schemas.change_analysis import ResolvedPullRequest
from app.schemas.review_publication import (
    AnalysisNotCompletedError,
    ForkPRUnsupportedError,
    GitHubReviewWriteDisabledError,
    NotPRAnalysisError,
    PRBaseDriftError,
    PRHeadDriftError,
    PreviewDigestMismatchError,
    PublicationNotApprovedError,
    ReviewPublicationStatus,
)
from app.services.review_publication_service import ReviewPublicationService


@pytest.fixture
def db_session():
    """In-memory SQLite database session."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def _create_mock_pr_analysis(db_session, status="COMPLETED", is_fork=False):
    """Helper creating a test ChangeAnalysisModel with canonical Phase 6 top-level PR metadata."""
    analysis_id = str(uuid4())
    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url="https://github.com/octocat/Hello-World",
        repository_owner="octocat",
        repository_name="Hello-World",
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        status=status,
        model_metadata={
            "pr_url": "https://github.com/octocat/Hello-World/pull/42",
            "pr_number": 42,
            "pr_title": "Update app",
            "head_repo_url": "https://github.com/octocat/Hello-World",
            "is_fork": is_fork,
            "pr_state": "open",
            "review_report": {
                "analysis_id": analysis_id,
                "summary": "Verified PR Review Summary",
                "overall_risk": "LOW",
                "findings": [],
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        },
    )
    db_session.add(analysis)
    db_session.commit()
    return analysis


@pytest.mark.asyncio
async def test_generate_preview_happy_path(db_session):
    """Verify preview generation sets PREVIEW_READY, calculates digest, and makes 0 writes."""
    analysis = _create_mock_pr_analysis(db_session)

    mock_provider = MagicMock()
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/Hello-World",
            repository_owner="octocat",
            repository_name="Hello-World",
            pr_number=42,
            title="Update app",
            base_branch="main",
            base_commit_sha="a" * 40,
            head_branch="feature",
            head_commit_sha="b" * 40,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    service = ReviewPublicationService(db=db_session, provider=mock_provider)
    pub = await service.generate_preview(UUID(analysis.id))

    assert pub.status == "PREVIEW_READY"
    assert pub.pr_number == 42
    assert pub.preview_digest is not None
    assert len(pub.preview_digest) == 64
    assert "<!-- repolens-review:" in pub.preview_body

    # Zero writes made to GitHub
    mock_provider.create_comment_review.assert_not_called()


@pytest.mark.asyncio
async def test_generate_preview_blocks_on_head_drift(db_session):
    """Verify preview generation raises PRHeadDriftError if live PR head SHA drifted."""
    analysis = _create_mock_pr_analysis(db_session)

    mock_provider = MagicMock()
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/Hello-World",
            repository_owner="octocat",
            repository_name="Hello-World",
            pr_number=42,
            title="Update app",
            base_branch="main",
            base_commit_sha="a" * 40,
            head_branch="feature",
            head_commit_sha="c" * 40,  # Drifted head SHA!
            state="open",
            is_fork=False,
        )
    )

    service = ReviewPublicationService(db=db_session, provider=mock_provider)
    with pytest.raises(PRHeadDriftError):
        await service.generate_preview(UUID(analysis.id))


@pytest.mark.asyncio
async def test_approve_preview_digest_parity(db_session):
    """Verify approval succeeds only with matching digest and does NOT publish."""
    analysis = _create_mock_pr_analysis(db_session)
    mock_provider = MagicMock()
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/Hello-World",
            repository_owner="octocat",
            repository_name="Hello-World",
            pr_number=42,
            title="Update app",
            base_branch="main",
            base_commit_sha="a" * 40,
            head_branch="feature",
            head_commit_sha="b" * 40,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    service = ReviewPublicationService(db=db_session, provider=mock_provider)
    pub = await service.generate_preview(UUID(analysis.id))
    correct_digest = pub.preview_digest

    # Wrong digest rejected with 409
    with pytest.raises(PreviewDigestMismatchError):
        await service.approve_preview(UUID(analysis.id), expected_preview_digest="wrong_digest" * 5)

    # Correct digest approved
    approved_pub = await service.approve_preview(UUID(analysis.id), expected_preview_digest=correct_digest)
    assert approved_pub.status == "APPROVED"
    assert approved_pub.approved_at is not None

    # Zero writes made during approve
    mock_provider.create_comment_review.assert_not_called()


@pytest.mark.asyncio
async def test_publish_review_happy_path(db_session):
    """Verify publish checks drift, sets PUBLISHING -> PUBLISHED, and writes exactly once."""
    analysis = _create_mock_pr_analysis(db_session)
    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/Hello-World",
            repository_owner="octocat",
            repository_name="Hello-World",
            pr_number=42,
            title="Update app",
            base_branch="main",
            base_commit_sha="a" * 40,
            head_branch="feature",
            head_commit_sha="b" * 40,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])
    mock_provider.create_comment_review = AsyncMock(
        return_value={"id": 99999, "html_url": "https://github.com/octocat/Hello-World/pull/42#pullrequestreview-99999"}
    )

    service = ReviewPublicationService(db=db_session, provider=mock_provider)
    pub = await service.generate_preview(UUID(analysis.id))
    await service.approve_preview(UUID(analysis.id), expected_preview_digest=pub.preview_digest)

    published = await service.publish_review(UUID(analysis.id), expected_preview_digest=pub.preview_digest)
    assert published.status == "PUBLISHED"
    assert published.github_review_id == 99999
    assert published.published_at is not None

    mock_provider.create_comment_review.assert_called_once()


@pytest.mark.asyncio
async def test_publish_reconciliation_on_crash_recovery(db_session):
    """Verify that if review creation succeeded on GitHub but local persistence failed, retry reconciles without second write."""
    analysis = _create_mock_pr_analysis(db_session)
    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/Hello-World",
            repository_owner="octocat",
            repository_name="Hello-World",
            pr_number=42,
            title="Update app",
            base_branch="main",
            base_commit_sha="a" * 40,
            head_branch="feature",
            head_commit_sha="b" * 40,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    service = ReviewPublicationService(db=db_session, provider=mock_provider)
    pub = await service.generate_preview(UUID(analysis.id))
    digest = pub.preview_digest

    # Simulate pub is stuck in PUBLISHING state
    pub.status = ReviewPublicationStatus.PUBLISHING.value
    db_session.commit()

    # Mock list_reviews returning the review with the hidden marker
    mock_provider.list_pull_request_reviews = AsyncMock(
        return_value=[
            {
                "id": 88888,
                "body": f"# Review\n\n<!-- repolens-review:{analysis.id}:{digest} -->",
                "html_url": "https://github.com/octocat/Hello-World/pull/42#pullrequestreview-88888",
            }
        ]
    )

    # Calling publish_review on PUBLISHING state triggers reconciliation
    reconciled = await service.publish_review(UUID(analysis.id), expected_preview_digest=digest)
    assert reconciled.status == "PUBLISHED"
    assert reconciled.github_review_id == 88888
    assert reconciled.reconciliation_occurred is True

    # Zero additional create_comment_review calls!
    mock_provider.create_comment_review.assert_not_called()


@pytest.mark.asyncio
async def test_provenance_canonical_and_legacy(db_session):
    """Verify both canonical top-level PR metadata and legacy nested metadata extract correctly."""
    service = ReviewPublicationService(db=db_session)

    # 1. Canonical top-level
    a1 = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/o/r",
        repository_owner="o",
        repository_name="r",
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        model_metadata={"pr_number": 99, "is_fork": False, "pr_url": "https://github.com/o/r/pull/99"},
    )
    pr_num, is_fork = service._extract_pr_provenance(a1)
    assert pr_num == 99
    assert is_fork is False

    # 2. Legacy nested
    a2 = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/o/r",
        repository_owner="o",
        repository_name="r",
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        model_metadata={"pr_metadata": {"pr_number": 101, "is_fork": False}},
    )
    pr_num2, is_fork2 = service._extract_pr_provenance(a2)
    assert pr_num2 == 101
    assert is_fork2 is False

    # 3. Missing pr_number
    a3 = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/o/r",
        repository_owner="o",
        repository_name="r",
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        model_metadata={},
    )
    with pytest.raises(NotPRAnalysisError):
        service._extract_pr_provenance(a3)

    # 4. Fork rejected
    a4 = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/o/r",
        repository_owner="o",
        repository_name="r",
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        model_metadata={"pr_number": 5, "is_fork": True},
    )
    with pytest.raises(ForkPRUnsupportedError):
        service._extract_pr_provenance(a4)

