"""Phase 7 Security Release Gate Tests.

Verifies invariants that must NEVER be violated:
1. GitHub review event is ALWAYS 'COMMENT' — never APPROVE or REQUEST_CHANGES.
2. Writing is impossible when GITHUB_PR_REVIEW_WRITE_ENABLED=false.
3. SSRF prevention: untrusted API origins are rejected.
4. Publication cannot proceed without explicit human approval.
5. Digest mismatch blocks publication.
6. Secrets are never rendered in review body.
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
import httpx
import pytest

from app.delivery.publication_provider import GITHUB_API_BASE_URL, GitHubReviewPublicationProvider
from app.delivery.review_renderer import ReviewPublicationRenderer
from app.schemas.review_publication import (
    GitHubReviewWriteDisabledError,
    InlineReviewComment,
    PreviewDigestMismatchError,
    PublicationNotApprovedError,
    ReviewPublicationStatus,
)


# ── Invariant 1: COMMENT-only enforcement ──────────────────────────────

@pytest.mark.asyncio
async def test_security_review_event_is_always_comment():
    """Verify that the create_comment_review POST payload strictly contains event='COMMENT'."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": 1, "state": "COMMENTED"}
    mock_client.request = AsyncMock(return_value=mock_resp)

    provider = GitHubReviewPublicationProvider(
        token="tok", write_enabled=True, client=mock_client,
    )

    await provider.create_comment_review(
        owner="o", repo="r", pr_number=1,
        commit_sha="a" * 40, body="Review",
        comments=[InlineReviewComment(path="f.py", line=1, side="RIGHT", body="Fix")],
    )

    payload = mock_client.request.call_args.kwargs["json"]
    assert payload["event"] == "COMMENT", "Review event MUST be COMMENT"
    assert "APPROVE" not in str(payload)
    assert "REQUEST_CHANGES" not in str(payload)


# ── Invariant 2: Write gate enforcement ────────────────────────────────

@pytest.mark.asyncio
async def test_security_write_disabled_blocks_all_writes():
    """Verify writes are impossible when write_enabled is False."""
    provider = GitHubReviewPublicationProvider(token="tok", write_enabled=False)
    with pytest.raises(GitHubReviewWriteDisabledError):
        await provider.create_comment_review(
            owner="o", repo="r", pr_number=1,
            commit_sha="a" * 40, body="Review",
        )


# ── Invariant 3: SSRF prevention ──────────────────────────────────────

def test_security_ssrf_prevention_rejects_untrusted_origin():
    """Verify SSRF: only https://api.github.com is accepted."""
    with pytest.raises(ValueError, match="Untrusted API origin"):
        GitHubReviewPublicationProvider(token="tok", base_url="https://evil.com/api")

    with pytest.raises(ValueError, match="Untrusted API origin"):
        GitHubReviewPublicationProvider(token="tok", base_url="http://api.github.com")

    # Legitimate origin should work
    p = GitHubReviewPublicationProvider(token="tok", base_url=GITHUB_API_BASE_URL)
    assert p.base_url == GITHUB_API_BASE_URL


# ── Invariant 4: No-approval blocks publication ───────────────────────

@pytest.mark.asyncio
async def test_security_publish_without_approval_blocked():
    """Verify publication from PREVIEW_READY state raises PublicationNotApprovedError."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.models.base import Base
    from app.models.change_analysis import ChangeAnalysisModel
    from app.models.review_publication import PullRequestReviewPublicationModel
    from app.services.review_publication_service import ReviewPublicationService
    from uuid import UUID

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    analysis = ChangeAnalysisModel(
        id=str(uuid4()), repository_url="https://github.com/o/r",
        repository_owner="o", repository_name="r",
        base_commit_sha="a" * 40, head_commit_sha="b" * 40, status="COMPLETED",
    )
    db.add(analysis)
    db.commit()

    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()), analysis_id=analysis.id,
        repository_owner="o", repository_name="r", pr_number=1,
        base_commit_sha="a" * 40, head_commit_sha="b" * 40,
        status=ReviewPublicationStatus.PREVIEW_READY.value,
        preview_digest="d" * 64,
    )
    db.add(pub)
    db.commit()

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    service = ReviewPublicationService(db=db, provider=mock_provider)

    with pytest.raises(PublicationNotApprovedError):
        await service.publish_review(UUID(analysis.id), expected_preview_digest="d" * 64)

    db.close()


# ── Invariant 5: Digest mismatch blocks approve ──────────────────────

@pytest.mark.asyncio
async def test_security_digest_mismatch_blocks_approve():
    """Verify wrong digest blocks approval."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.models.base import Base
    from app.models.change_analysis import ChangeAnalysisModel
    from app.models.review_publication import PullRequestReviewPublicationModel
    from app.services.review_publication_service import ReviewPublicationService
    from uuid import UUID

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    analysis = ChangeAnalysisModel(
        id=str(uuid4()), repository_url="https://github.com/o/r",
        repository_owner="o", repository_name="r",
        base_commit_sha="a" * 40, head_commit_sha="b" * 40, status="COMPLETED",
    )
    db.add(analysis)
    db.commit()

    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()), analysis_id=analysis.id,
        repository_owner="o", repository_name="r", pr_number=1,
        base_commit_sha="a" * 40, head_commit_sha="b" * 40,
        status=ReviewPublicationStatus.PREVIEW_READY.value,
        preview_digest="correct_digest_" + "a" * 49,
    )
    db.add(pub)
    db.commit()

    service = ReviewPublicationService(db=db, provider=MagicMock())

    with pytest.raises(PreviewDigestMismatchError):
        await service.approve_preview(UUID(analysis.id), expected_preview_digest="wrong_digest_" + "b" * 51)

    db.close()


# ── Invariant 6: Secret redaction in rendered output ──────────────────

def test_security_secrets_never_in_rendered_output():
    """Verify secrets are redacted from rendered review body."""
    from app.models.change_analysis import ChangeAnalysisModel
    from app.schemas.change_analysis import ChangeReviewReport, ChangeReviewFinding, ChangeReviewVerdict
    from app.schemas.enums import Severity
    from datetime import datetime, timezone
    from uuid import UUID

    analysis = ChangeAnalysisModel(
        id=str(uuid4()), repository_url="https://github.com/o/r",
        repository_owner="o", repository_name="r",
        base_commit_sha="a" * 40, head_commit_sha="b" * 40, status="COMPLETED",
    )

    raw_secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    report = ChangeReviewReport(
        analysis_id=UUID(analysis.id),
        summary=f"Contains secret: {raw_secret}",
        overall_risk=Severity.HIGH,
        findings=[],
        created_at=datetime.now(timezone.utc),
    )

    renderer = ReviewPublicationRenderer()
    pub = renderer.render_publication(analysis=analysis, pr_number=1, review_report=report)

    assert raw_secret not in pub.preview_body, "Secrets MUST be redacted from review body"
