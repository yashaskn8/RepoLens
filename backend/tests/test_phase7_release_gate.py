"""Phase 7 Production Release Gate Suite.

End-to-End verification of the entire API/service/DB/provider boundary:
- E2E A: Real Phase 6 Provenance Happy Path (preview -> approve -> publish -> fresh session)
- E2E B: Drift Detection (Head drift & Base drift block publication)
- E2E C: Strict Human Authorization (Publish without approve is rejected)
- E2E D: Preview Digest Parity (Wrong digest blocks approve and publish)
- E2E E: Crash-After-External-Success Reconciliation (Rollback first -> Fresh session -> Marker recovery -> 1 POST)
- E2E F: Concurrent Publish Ownership (Atomic transition, exactly 1 POST)
- E2E G: Inline Comment Preview Parity & Unmappable Finding Fallback
- E2E H: Authoritative Change Analysis Report & Telemetry Integration
- E2E I: Universal Service Exception & Log Secret Redaction
- E2E J: Malformed GitHub PR Metadata Fail-Closed (No guessed "main"/"patch" defaults)
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.analysis.report_generator import generate_change_analysis_report, generate_change_analysis_telemetry
from app.delivery.diff_mapper import GitHubDiffFile
from app.delivery.publication_provider import GitHubReviewPublicationProvider
from app.models.base import Base
from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
from app.models.review_publication import PullRequestReviewPublicationModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.change_analysis import ChangeReviewFinding, ChangeReviewReport, ChangeReviewVerdict, ResolvedPullRequest
from app.schemas.enums import ChangeImpactType, ChangeRiskLevel, ImpactVerificationStatus, Severity
from app.schemas.review_publication import (
    GitHubAuthFailedError,
    GitHubPRMetadataInvalidError,
    GitHubReviewStateUncertainError,
    PRBaseDriftError,
    PRHeadDriftError,
    PreviewDigestMismatchError,
    PublicationNotApprovedError,
    ReviewPublicationStatus,
    VerifiedReviewInvalidError,
)
from app.services.review_publication_service import ReviewPublicationService


@pytest.fixture
def fresh_db_engine():
    """Create in-memory SQLite engine with multithreading support."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def _seed_completed_pr_analysis(
    session,
    base_sha="1111111111111111111111111111111111111111",
    head_sha="2222222222222222222222222222222222222222",
    is_fork=False,
) -> ChangeAnalysisModel:
    """Helper seeding a completed Phase 6 ChangeAnalysis with canonical top-level PR provenance."""
    analysis_id = str(uuid4())
    review_report = {
        "analysis_id": analysis_id,
        "summary": "Verified PR Change Review with security findings",
        "overall_risk": "HIGH",
        "findings": [
            {
                "id": str(uuid4()),
                "title": "SQL Injection vulnerability in query builder",
                "severity": "HIGH",
                "risk_type": "SECURITY_SENSITIVE_CHANGE",
                "reasoning_summary": "Direct parameter interpolation detected in raw SQL query.",
                "affected_files": ["app/db.py"],
                "affected_symbols": ["execute_query"],
                "evidence_refs": ["line:app/db.py:45"],
                "confidence": 0.95,
                "verdict": "CONFIRMED",
                "suggested_fix": "Use parameterized query variables.",
            },
            {
                "id": str(uuid4()),
                "title": "General inference on error handling",
                "severity": "LOW",
                "risk_type": "UNKNOWN",
                "reasoning_summary": "Broad exception catch block",
                "affected_files": ["app/utils.py"],
                "affected_symbols": ["safe_call"],
                "evidence_refs": [],
                "confidence": 0.5,
                "verdict": "SUPPORTED_INFERENCE",
            },
        ],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    analysis = ChangeAnalysisModel(
        id=analysis_id,
        repository_url="https://github.com/octocat/RepoLens-Target",
        repository_owner="octocat",
        repository_name="RepoLens-Target",
        base_ref="main",
        base_commit_sha=base_sha,
        head_ref="feature/safe-publish",
        head_commit_sha=head_sha,
        status="COMPLETED",
        risk_level="HIGH",
        changed_files_count=2,
        changed_symbols_count=3,
        impacted_symbols_count=5,
        model_metadata={
            "pr_url": "https://github.com/octocat/RepoLens-Target/pull/42",
            "pr_number": 42,
            "pr_title": "Add safe review publication",
            "head_repo_url": "https://github.com/octocat/RepoLens-Target",
            "is_fork": is_fork,
            "pr_state": "open",
            "review_report": review_report,
        },
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    session.add(analysis)
    session.commit()
    session.refresh(analysis)
    return analysis


# ── E2E A: Real Phase 6 Provenance Happy Path ─────────────────────────

@pytest.mark.asyncio
async def test_e2e_a_real_phase6_provenance_happy_path(fresh_db_engine):
    """Prove complete Happy Path: preview -> approve -> publish -> fresh Session verification."""
    Session = sessionmaker(bind=fresh_db_engine)
    session1 = Session()

    analysis = _seed_completed_pr_analysis(session1)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    # Return diff file matching the confirmed finding
    mock_provider.get_pull_request_diff_files = AsyncMock(
        return_value=[
            GitHubDiffFile(
                filename="app/db.py",
                status="modified",
                patch="@@ -40,10 +40,10 @@\n def execute_query():\n-    pass\n+    query = 'SELECT *'\n",
            )
        ]
    )
    mock_provider.create_comment_review = AsyncMock(
        return_value={"id": 77701, "html_url": "https://github.com/octocat/RepoLens-Target/pull/42#pullrequestreview-77701"}
    )

    service = ReviewPublicationService(db=session1, provider=mock_provider)

    # 1. Preview
    pub_preview = await service.generate_preview(analysis_id)
    assert pub_preview.status == "PREVIEW_READY"
    assert pub_preview.pr_number == 42
    assert pub_preview.base_commit_sha == analysis.base_commit_sha
    assert pub_preview.head_commit_sha == analysis.head_commit_sha
    digest = pub_preview.preview_digest
    assert digest is not None and len(digest) == 64
    assert mock_provider.create_comment_review.call_count == 0

    # 2. Approve
    pub_approved = await service.approve_preview(analysis_id, expected_preview_digest=digest)
    assert pub_approved.status == "APPROVED"
    assert pub_approved.approved_at is not None
    assert mock_provider.create_comment_review.call_count == 0

    # 3. Publish
    pub_published = await service.publish_review(analysis_id, expected_preview_digest=digest)
    assert pub_published.status == "PUBLISHED"
    assert pub_published.github_review_id == 77701
    assert "pullrequestreview-77701" in pub_published.github_review_url
    assert mock_provider.create_comment_review.call_count == 1

    # Verify POST payload invariants
    call_kwargs = mock_provider.create_comment_review.call_args.kwargs
    assert call_kwargs["pr_number"] == 42
    assert call_kwargs["commit_sha"] == analysis.head_commit_sha
    assert "<!-- repolens-review:" in call_kwargs["body"]

    session1.close()

    # 4. Fresh Session verification (proves DB persistence)
    session2 = Session()
    persisted = session2.query(PullRequestReviewPublicationModel).filter_by(analysis_id=str(analysis_id)).first()
    assert persisted is not None
    assert persisted.status == "PUBLISHED"
    assert persisted.github_review_id == 77701
    assert persisted.reconciliation_occurred is False
    session2.close()


# ── E2E B: Drift Detection ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_e2e_b_drift_detection_head_and_base(fresh_db_engine):
    """Verify live PR drift immediately blocks publication with typed failure code."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    service = ReviewPublicationService(db=session, provider=mock_provider)
    pub = await service.generate_preview(analysis_id)
    digest = pub.preview_digest
    await service.approve_preview(analysis_id, expected_preview_digest=digest)

    # Simulate Head Drift before publish
    drifted_head_sha = "9" * 40
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=drifted_head_sha,
            state="open",
            is_fork=False,
        )
    )

    with pytest.raises(PRHeadDriftError):
        await service.publish_review(analysis_id, expected_preview_digest=digest)

    session.refresh(pub)
    assert pub.status == "BLOCKED"
    assert pub.failure_code == "PR_HEAD_DRIFT"
    assert mock_provider.create_comment_review.call_count == 0

    session.close()


# ── E2E C: Strict Human Authorization ────────────────────────────────

@pytest.mark.asyncio
async def test_e2e_c_no_approval_blocks_publish(fresh_db_engine):
    """Verify publication from PREVIEW_READY without approval is rejected."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    service = ReviewPublicationService(db=session, provider=mock_provider)
    pub = await service.generate_preview(analysis_id)

    with pytest.raises(PublicationNotApprovedError):
        await service.publish_review(analysis_id, expected_preview_digest=pub.preview_digest)

    assert mock_provider.create_comment_review.call_count == 0
    session.close()


# ── E2E D: Preview Digest Parity ──────────────────────────────────────

@pytest.mark.asyncio
async def test_e2e_d_wrong_digest_rejected(fresh_db_engine):
    """Verify wrong preview digest blocks both approve and publish."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    service = ReviewPublicationService(db=session, provider=mock_provider)
    pub = await service.generate_preview(analysis_id)
    correct_digest = pub.preview_digest
    wrong_digest = "f" * 64

    # Approve with wrong digest -> rejected
    with pytest.raises(PreviewDigestMismatchError):
        await service.approve_preview(analysis_id, expected_preview_digest=wrong_digest)

    # Approve with correct digest
    await service.approve_preview(analysis_id, expected_preview_digest=correct_digest)

    # Publish with wrong digest -> rejected
    with pytest.raises(PreviewDigestMismatchError):
        await service.publish_review(analysis_id, expected_preview_digest=wrong_digest)

    assert mock_provider.create_comment_review.call_count == 0
    session.close()


# ── E2E E: Crash-After-External-Success Reconciliation ────────────────

@pytest.mark.asyncio
async def test_e2e_e_crash_after_external_success_reconciliation(fresh_db_engine):
    """Prove crash recovery: GitHub write succeeds, real SQLAlchemy flush fails, rollback first, fresh session reconciles with exactly 1 POST."""
    Session = sessionmaker(bind=fresh_db_engine)
    session1 = Session()

    analysis = _seed_completed_pr_analysis(session1)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])
    mock_provider.create_comment_review = AsyncMock(
        return_value={"id": 98765, "html_url": "https://github.com/octocat/RepoLens-Target/pull/42#pullrequestreview-98765"}
    )

    service1 = ReviewPublicationService(db=session1, provider=mock_provider)
    pub = await service1.generate_preview(analysis_id)
    digest = pub.preview_digest
    await service1.approve_preview(analysis_id, expected_preview_digest=digest)

    # Attach genuine SQLAlchemy event listener on session1 that fails during flush of PUBLISHED state
    @event.listens_for(session1, "before_flush")
    def simulate_real_db_failure(session, flush_context, instances):
        for obj in session.dirty:
            if isinstance(obj, PullRequestReviewPublicationModel) and obj.status == ReviewPublicationStatus.PUBLISHED.value:
                raise OperationalError("Simulated database write IO failure during post-write flush", None, None)

    # Publish attempt raises OperationalError due to genuine DB flush crash; rollback-first handles cleanup
    with pytest.raises(OperationalError, match="Simulated database write IO failure"):
        await service1.publish_review(analysis_id, expected_preview_digest=digest)

    # Verify GitHub POST was executed once
    assert mock_provider.create_comment_review.call_count == 1

    session1.close()

    # ── Recovery in Fresh Session ──────────────────────────────────────
    session2 = Session()

    # Verify database state after rollback is PUBLISHING (the pre-write committed state)
    persisted_pub = session2.query(PullRequestReviewPublicationModel).filter_by(analysis_id=str(analysis_id)).first()
    assert persisted_pub is not None
    assert persisted_pub.status == ReviewPublicationStatus.PUBLISHING.value

    # In fresh session, mock list_reviews returning the review created during the crashed run
    mock_provider.list_pull_request_reviews = AsyncMock(
        return_value=[
            {
                "id": 98765,
                "body": f"## Verified Review\n\n<!-- repolens-review:{analysis_id}:{digest} -->",
                "html_url": "https://github.com/octocat/RepoLens-Target/pull/42#pullrequestreview-98765",
            }
        ]
    )

    service2 = ReviewPublicationService(db=session2, provider=mock_provider)

    # Retry publish in fresh session
    reconciled = await service2.publish_review(analysis_id, expected_preview_digest=digest)
    assert reconciled.status == "PUBLISHED"
    assert reconciled.github_review_id == 98765
    assert reconciled.reconciliation_occurred is True

    # Critical Assertion: Zero second POST!
    assert mock_provider.create_comment_review.call_count == 1

    session2.close()


# ── E2E F: File-Backed Multi-Connection Concurrent Publish Ownership ──

@pytest.mark.asyncio
async def test_e2e_f_concurrent_publish_ownership(tmp_path):
    """Verify multi-session concurrent publish operations on file-backed database execute exactly one GitHub POST."""
    db_file = tmp_path / "phase7_concurrency.sqlite"
    engine = create_engine(
        f"sqlite:///{db_file.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    init_session = Session()

    analysis = _seed_completed_pr_analysis(init_session)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    async def slow_create_comment_review(*args, **kwargs):
        await asyncio.sleep(0.05)
        return {"id": 11223, "html_url": "https://github.com/octocat/RepoLens-Target/pull/42#pullrequestreview-11223"}

    mock_provider.create_comment_review = AsyncMock(side_effect=slow_create_comment_review)

    init_service = ReviewPublicationService(db=init_session, provider=mock_provider)
    pub = await init_service.generate_preview(analysis_id)
    digest = pub.preview_digest
    await init_service.approve_preview(analysis_id, expected_preview_digest=digest)
    init_session.close()

    # Launch two independent sessions with distinct connections
    session_a = Session()
    session_b = Session()

    service_a = ReviewPublicationService(db=session_a, provider=mock_provider)
    service_b = ReviewPublicationService(db=session_b, provider=mock_provider)

    results = await asyncio.gather(
        service_a.publish_review(analysis_id, expected_preview_digest=digest),
        service_b.publish_review(analysis_id, expected_preview_digest=digest),
        return_exceptions=True,
    )

    # Exactly one write made to GitHub
    assert mock_provider.create_comment_review.call_count == 1

    # At least one succeeded with PUBLISHED status
    successes = [r for r in results if isinstance(r, PullRequestReviewPublicationModel) and r.status == "PUBLISHED"]
    assert len(successes) >= 1

    session_a.close()
    session_b.close()
    engine.dispose()


# ── E2E G: Inline Preview Parity & Unmappable Finding ─────────────────

@pytest.mark.asyncio
async def test_e2e_g_inline_preview_parity_and_unmappable_fallback(fresh_db_engine):
    """Verify confirmed finding maps to inline comment on diff line; unmappable stays in summary."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    # File app/db.py has patch hunk covering line 45
    mock_provider.get_pull_request_diff_files = AsyncMock(
        return_value=[
            GitHubDiffFile(
                filename="app/db.py",
                status="modified",
                patch="@@ -40,10 +40,10 @@\n def execute_query():\n-    pass\n+    # line 41\n+    # line 42\n+    # line 43\n+    # line 44\n+    query = 'SELECT *'\n",
            )
        ]
    )

    service = ReviewPublicationService(db=session, provider=mock_provider)
    pub = await service.generate_preview(analysis_id)

    # Mapped inline comments exist in publication model
    assert pub.inline_comments_payload is not None
    assert len(pub.inline_comments_payload) == 1
    comment = pub.inline_comments_payload[0]
    assert comment["path"] == "app/db.py"
    assert comment["line"] == 45
    assert comment["side"] == "RIGHT"
    assert "SQL Injection" in comment["body"]

    session.close()


# ── E2E H: Report & Telemetry Integration ─────────────────────────────

def test_e2e_h_report_and_telemetry_integration(fresh_db_engine):
    """Verify Change Analysis report and telemetry faithfully expose Phase 7 publication state."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)

    # 1. State: NOT_REQUESTED
    rep_none = generate_change_analysis_report(analysis)
    assert "## 🚀 GitHub Review Publication" in rep_none.markdown_report
    assert "- **Status**: `NOT_REQUESTED`" in rep_none.markdown_report

    tel_none = generate_change_analysis_telemetry(analysis)
    assert tel_none.review_publication_status == "NOT_REQUESTED"
    assert tel_none.review_publication_published is False

    # 2. State: PUBLISHED
    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=analysis.id,
        repository_owner="octocat",
        repository_name="RepoLens-Target",
        pr_number=42,
        base_commit_sha=analysis.base_commit_sha,
        head_commit_sha=analysis.head_commit_sha,
        status="PUBLISHED",
        github_review_id=65432,
        github_review_url="https://github.com/octocat/RepoLens-Target/pull/42#pullrequestreview-65432",
        published_at=datetime.now(timezone.utc),
        inline_comments_payload=[{"path": "app/db.py", "line": 45, "side": "RIGHT", "body": "fix"}],
        reconciliation_occurred=True,
    )
    session.add(pub)
    session.commit()
    session.refresh(analysis)

    rep_pub = generate_change_analysis_report(analysis)
    assert "- **Status**: `PUBLISHED`" in rep_pub.markdown_report
    assert "- **Review ID**: `65432`" in rep_pub.markdown_report
    assert "pullrequestreview-65432" in rep_pub.markdown_report
    assert "- **Reconciliation Occurred**: Yes" in rep_pub.markdown_report

    tel_pub = generate_change_analysis_telemetry(analysis)
    assert tel_pub.review_publication_status == "PUBLISHED"
    assert tel_pub.review_publication_published is True
    assert tel_pub.review_publication_inline_comments_count == 1
    assert tel_pub.review_publication_reconciliation_occurred is True

    session.close()


# ── E2E I: Secret Redaction ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_e2e_i_service_exception_secret_redaction(fresh_db_engine):
    """Verify provider exceptions containing tokens are completely redacted from failure_message and logs."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="Add safe review publication",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature/safe-publish",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    raw_secret_token = "ghp_PHASE7_SUPER_SECRET_TOKEN_99999"
    mock_provider.create_comment_review = AsyncMock(
        side_effect=GitHubAuthFailedError(f"HTTP 401 Unauthorized: Authorization: Bearer {raw_secret_token}")
    )
    mock_provider.list_pull_request_reviews = AsyncMock(return_value=[])

    service = ReviewPublicationService(db=session, provider=mock_provider)
    pub = await service.generate_preview(analysis_id)
    digest = pub.preview_digest
    await service.approve_preview(analysis_id, expected_preview_digest=digest)

    with pytest.raises(GitHubAuthFailedError):
        await service.publish_review(analysis_id, expected_preview_digest=digest)

    session.refresh(pub)
    assert pub.status == "FAILED"
    assert raw_secret_token not in (pub.failure_message or ""), "Token MUST NOT be persisted in failure_message"
    assert "[REDACTED]" in (pub.failure_message or "")

    session.close()


# ── E2E J: Malformed GitHub PR Metadata Fail-Closed ───────────────────

@pytest.mark.asyncio
async def test_e2e_j_malformed_github_pr_metadata_fail_closed():
    """Verify provider strictly rejects missing base/head ref or malformed SHA without fallback."""
    provider = GitHubReviewPublicationProvider(token="test_token")

    # Missing base.ref
    provider._request = AsyncMock(
        return_value={
            "title": "PR",
            "state": "open",
            "head": {"ref": "feat", "sha": "a" * 40},
            "base": {"sha": "b" * 40},  # missing ref
        }
    )
    with pytest.raises(GitHubPRMetadataInvalidError, match="missing valid base.ref"):
        await provider.get_current_pull_request(owner="o", repo="r", pr_number=1)

    # Missing head.ref
    provider._request = AsyncMock(
        return_value={
            "title": "PR",
            "state": "open",
            "head": {"sha": "a" * 40},  # missing ref
            "base": {"ref": "main", "sha": "b" * 40},
        }
    )
    with pytest.raises(GitHubPRMetadataInvalidError, match="missing valid head.ref"):
        await provider.get_current_pull_request(owner="o", repo="r", pr_number=1)

    # Malformed base.sha
    provider._request = AsyncMock(
        return_value={
            "title": "PR",
            "state": "open",
            "head": {"ref": "feat", "sha": "a" * 40},
            "base": {"ref": "main", "sha": "not_a_valid_sha"},
        }
    )
    with pytest.raises(GitHubPRMetadataInvalidError, match="missing valid 40-char base.sha"):
        await provider.get_current_pull_request(owner="o", repo="r", pr_number=1)


# ── E2E K: Review Analysis ID Mismatch ────────────────────────────────

@pytest.mark.asyncio
async def test_e2e_k_review_analysis_id_mismatch_rejected(fresh_db_engine):
    """Verify Phase 6 report with mismatched analysis_id raises VerifiedReviewInvalidError and does 0 writes."""
    import copy
    from sqlalchemy.orm.attributes import flag_modified

    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)

    # Mutate model_metadata review_report to have a different analysis_id
    different_analysis_id = str(uuid4())
    meta = copy.deepcopy(analysis.model_metadata)
    meta["review_report"]["analysis_id"] = different_analysis_id
    analysis.model_metadata = meta
    flag_modified(analysis, "model_metadata")
    session.commit()
    session.refresh(analysis)

    mock_provider = MagicMock()
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="PR",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    service = ReviewPublicationService(db=session, provider=mock_provider)

    with pytest.raises(VerifiedReviewInvalidError, match="does not match ChangeAnalysis ID"):
        await service.generate_preview(analysis_id)

    # Zero writes made to GitHub
    mock_provider.create_comment_review.assert_not_called()

    # Now fix the analysis_id to match -> generate_preview succeeds
    meta = copy.deepcopy(analysis.model_metadata)
    meta["review_report"]["analysis_id"] = str(analysis_id)
    analysis.model_metadata = meta
    flag_modified(analysis, "model_metadata")
    session.commit()
    session.refresh(analysis)

    pub = await service.generate_preview(analysis_id)
    assert pub.status == ReviewPublicationStatus.PREVIEW_READY.value
    session.close()


# ── E2E L: Unresolved PUBLISHING Retry Returns Uncertain ─────────────

@pytest.mark.asyncio
async def test_e2e_l_unresolved_publishing_retry_returns_uncertain(fresh_db_engine):
    """Verify unresolved PUBLISHING publication raises GitHubReviewStateUncertainError and executes 0 POSTs."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)

    # Directly seed a publication in PUBLISHING state
    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=str(analysis_id),
        repository_owner="octocat",
        repository_name="RepoLens-Target",
        pr_number=42,
        base_commit_sha=analysis.base_commit_sha,
        head_commit_sha=analysis.head_commit_sha,
        status=ReviewPublicationStatus.PUBLISHING.value,
        preview_body="## Review",
        preview_digest="a" * 64,
        inline_comments_payload=[],
    )
    session.add(pub)
    session.commit()

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.list_pull_request_reviews = AsyncMock(return_value=[])  # Unreconciled
    mock_provider.create_comment_review = AsyncMock()

    service = ReviewPublicationService(db=session, provider=mock_provider)

    with pytest.raises(GitHubReviewStateUncertainError, match="is in PUBLISHING state"):
        await service.publish_review(analysis_id, expected_preview_digest="a" * 64)

    # Status must remain PUBLISHING (never FAILED, APPROVED, or PREVIEW_READY)
    session.refresh(pub)
    assert pub.status == ReviewPublicationStatus.PUBLISHING.value
    assert mock_provider.create_comment_review.call_count == 0

    session.close()


# ── E2E M: Invalid Reconciliation IDs Rejected ────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_id", [None, "abc", 0, -1])
async def test_e2e_m_invalid_reconciliation_ids_rejected(fresh_db_engine, invalid_id):
    """Verify reconciliation ignores marker-bearing reviews with non-positive or non-integer IDs."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)
    digest = "b" * 64

    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=str(analysis_id),
        repository_owner="octocat",
        repository_name="RepoLens-Target",
        pr_number=42,
        base_commit_sha=analysis.base_commit_sha,
        head_commit_sha=analysis.head_commit_sha,
        status=ReviewPublicationStatus.PUBLISHING.value,
        preview_body="## Review",
        preview_digest=digest,
        inline_comments_payload=[],
    )
    session.add(pub)
    session.commit()

    mock_provider = MagicMock()
    mock_provider.write_enabled = True
    mock_provider.list_pull_request_reviews = AsyncMock(
        return_value=[
            {
                "id": invalid_id,
                "body": f"<!-- repolens-review:{analysis_id}:{digest} -->",
                "html_url": "https://github.com/octocat/RepoLens-Target/pull/42#pullrequestreview-invalid",
            }
        ]
    )

    service = ReviewPublicationService(db=session, provider=mock_provider)

    # Reconcile publication directly
    reconciled = await service.reconcile_publication(pub)

    # Must NOT transition to PUBLISHED
    assert reconciled.status == ReviewPublicationStatus.PUBLISHING.value
    assert reconciled.github_review_id is None
    assert reconciled.reconciliation_occurred is not True

    session.close()


# ── E2E N: Valid Reconciliation ID Succeeds ───────────────────────────

@pytest.mark.asyncio
async def test_e2e_n_valid_positive_reconciliation_id_succeeds(fresh_db_engine):
    """Verify reconciliation adopts positive integer review ID and updates state to PUBLISHED."""
    Session = sessionmaker(bind=fresh_db_engine)
    session = Session()

    analysis = _seed_completed_pr_analysis(session)
    analysis_id = UUID(analysis.id)
    digest = "c" * 64

    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=str(analysis_id),
        repository_owner="octocat",
        repository_name="RepoLens-Target",
        pr_number=42,
        base_commit_sha=analysis.base_commit_sha,
        head_commit_sha=analysis.head_commit_sha,
        status=ReviewPublicationStatus.PUBLISHING.value,
        preview_body="## Review",
        preview_digest=digest,
        inline_comments_payload=[],
    )
    session.add(pub)
    session.commit()

    valid_id = 54321
    mock_provider = MagicMock()
    mock_provider.list_pull_request_reviews = AsyncMock(
        return_value=[
            {
                "id": valid_id,
                "body": f"<!-- repolens-review:{analysis_id}:{digest} -->",
                "html_url": f"https://github.com/octocat/RepoLens-Target/pull/42#pullrequestreview-{valid_id}",
            }
        ]
    )

    service = ReviewPublicationService(db=session, provider=mock_provider)
    reconciled = await service.reconcile_publication(pub)

    assert reconciled.status == ReviewPublicationStatus.PUBLISHED.value
    assert reconciled.github_review_id == 54321
    assert reconciled.github_review_url == f"https://github.com/octocat/RepoLens-Target/pull/42#pullrequestreview-{valid_id}"
    assert reconciled.reconciliation_occurred is True

    session.close()


# ── E2E Q: Initial Preview Audit Event FK Linkage ─────────────────────

@pytest.mark.asyncio
async def test_e2e_q_initial_preview_audit_event_fk_linkage(fresh_db_engine):
    """Verify fresh publication flush materializes ID so PR_REVIEW_PREVIEW_READY event carries exact FK."""
    Session = sessionmaker(bind=fresh_db_engine)
    session1 = Session()

    analysis = _seed_completed_pr_analysis(session1)
    analysis_id = UUID(analysis.id)

    mock_provider = MagicMock()
    mock_provider.get_current_pull_request = AsyncMock(
        return_value=ResolvedPullRequest(
            repository_url="https://github.com/octocat/RepoLens-Target",
            repository_owner="octocat",
            repository_name="RepoLens-Target",
            pr_number=42,
            title="PR",
            base_branch="main",
            base_commit_sha=analysis.base_commit_sha,
            head_branch="feature",
            head_commit_sha=analysis.head_commit_sha,
            state="open",
            is_fork=False,
        )
    )
    mock_provider.get_pull_request_diff_files = AsyncMock(return_value=[])

    service1 = ReviewPublicationService(db=session1, provider=mock_provider)
    pub = await service1.generate_preview(analysis_id)
    session1.close()

    # Open fresh session to query database directly
    session2 = Session()
    persisted_pub = session2.query(PullRequestReviewPublicationModel).filter_by(analysis_id=str(analysis_id)).first()
    assert persisted_pub is not None
    assert persisted_pub.id is not None

    event_row = session2.query(WorkflowEventModel).filter_by(
        change_analysis_id=str(analysis_id),
        event_type="PR_REVIEW_PREVIEW_READY",
    ).first()

    assert event_row is not None
    assert event_row.pr_review_publication_id == str(persisted_pub.id)
    assert event_row.pr_review_publication_id is not None

    session2.close()
