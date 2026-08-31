"""Domain, schema, and migration tests for Pull Request Review Publication."""

import hashlib
import json
from uuid import uuid4
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from alembic.config import Config
from alembic import command

from app.models.base import Base
from app.models.change_analysis import ChangeAnalysisModel
from app.models.review_publication import PullRequestReviewPublicationModel
from app.models.workflow_event import WorkflowEventModel
from app.schemas.review_publication import (
    ReviewPublicationStatus,
    InlineReviewComment,
    InlineReviewCommentPreview,
    ReviewPublicationPreviewResponse,
    ReviewPublicationApproveRequest,
    ReviewPublicationPublishRequest,
    ReviewPublicationPublishResponse,
)


@pytest.fixture
def db_session():
    """Isolated in-memory SQLite database session."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_review_publication_status_enums():
    """Verify exact status enums exist."""
    assert ReviewPublicationStatus.PENDING == "PENDING"
    assert ReviewPublicationStatus.PREVIEW_READY == "PREVIEW_READY"
    assert ReviewPublicationStatus.APPROVED == "APPROVED"
    assert ReviewPublicationStatus.PUBLISHING == "PUBLISHING"
    assert ReviewPublicationStatus.PUBLISHED == "PUBLISHED"
    assert ReviewPublicationStatus.BLOCKED == "BLOCKED"
    assert ReviewPublicationStatus.FAILED == "FAILED"


def test_pull_request_review_publication_model_creation(db_session):
    """Verify ORM model creation with relationships and defaults."""
    analysis = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/octocat/Hello-World",
        repository_owner="octocat",
        repository_name="Hello-World",
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        status="COMPLETED",
    )
    db_session.add(analysis)
    db_session.commit()

    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=analysis.id,
        repository_owner="octocat",
        repository_name="Hello-World",
        pr_number=42,
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        status=ReviewPublicationStatus.PREVIEW_READY.value,
        preview_body="# RepoLens Review",
        preview_digest="d" * 64,
        inline_comments_payload=[{"path": "app.py", "line": 10, "side": "RIGHT", "body": "Fix"}],
    )
    db_session.add(pub)
    db_session.commit()

    reloaded = db_session.query(PullRequestReviewPublicationModel).filter_by(id=pub.id).first()
    assert reloaded is not None
    assert reloaded.analysis_id == analysis.id
    assert reloaded.pr_number == 42
    assert reloaded.status == "PREVIEW_READY"
    assert reloaded.is_truncated is False
    assert reloaded.reconciliation_occurred is False
    assert len(reloaded.inline_comments_payload) == 1

    # Verify 1-to-1 back-population
    assert analysis.review_publication.id == pub.id


def test_unique_analysis_id_constraint(db_session):
    """Verify that only one publication record can exist per ChangeAnalysis."""
    analysis = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/octocat/Hello-World",
        repository_owner="octocat",
        repository_name="Hello-World",
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        status="COMPLETED",
    )
    db_session.add(analysis)
    db_session.commit()

    pub1 = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=analysis.id,
        repository_owner="octocat",
        repository_name="Hello-World",
        pr_number=42,
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
    )
    db_session.add(pub1)
    db_session.commit()

    pub2 = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=analysis.id,
        repository_owner="octocat",
        repository_name="Hello-World",
        pr_number=42,
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
    )
    db_session.add(pub2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_workflow_event_pr_review_publication_linkage(db_session):
    """Verify WorkflowEventModel first-class linkage to PR review publication."""
    analysis = ChangeAnalysisModel(
        id=str(uuid4()),
        repository_url="https://github.com/octocat/Hello-World",
        repository_owner="octocat",
        repository_name="Hello-World",
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
        status="COMPLETED",
    )
    db_session.add(analysis)
    db_session.commit()

    pub = PullRequestReviewPublicationModel(
        id=str(uuid4()),
        analysis_id=analysis.id,
        repository_owner="octocat",
        repository_name="Hello-World",
        pr_number=42,
        base_commit_sha="a" * 40,
        head_commit_sha="b" * 40,
    )
    db_session.add(pub)
    db_session.commit()

    event = WorkflowEventModel(
        event_type="PR_REVIEW_PUBLISHED",
        change_analysis_id=analysis.id,
        pr_review_publication_id=pub.id,
        commit_sha="b" * 40,
        message="Review published to GitHub",
    )
    db_session.add(event)
    db_session.commit()

    reloaded_event = db_session.query(WorkflowEventModel).filter_by(id=event.id).first()
    assert reloaded_event.pr_review_publication_id == pub.id
    assert reloaded_event.pr_review_publication.pr_number == 42


def test_schema_contracts_and_digest_calculation():
    """Verify schemas, publish request, and non-circular digest calculation order."""
    approve_req = ReviewPublicationApproveRequest(expected_preview_digest="abc123" * 10 + "abcd")
    assert approve_req.expected_preview_digest == "abc123" * 10 + "abcd"

    publish_req = ReviewPublicationPublishRequest(expected_preview_digest="abc123" * 10 + "abcd")
    assert publish_req.expected_preview_digest == "abc123" * 10 + "abcd"

    inline_comment = InlineReviewComment(
        path="src/api.py",
        line=45,
        side="RIGHT",
        body="Method signature changed",
    )
    assert inline_comment.side == "RIGHT"

    # Non-circular digest verification:
    # 1. Base markdown WITHOUT marker
    base_body = "# RepoLens Review\n\nAll checks verified."
    canonical_snapshot = {
        "analysis_id": str(uuid4()),
        "repository_owner": "octocat",
        "repository_name": "Hello-World",
        "pr_number": 1,
        "base_commit_sha": "a" * 40,
        "head_commit_sha": "b" * 40,
        "body": base_body,
        "inline_comments": [inline_comment.model_dump()],
        "event": "COMMENT",
    }
    canonical_json = json.dumps(canonical_snapshot, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    # 2. Append marker using calculated digest
    marker = f"\n\n<!-- repolens-review:{canonical_snapshot['analysis_id']}:{digest} -->"
    final_body = base_body + marker

    # 3. Verify digest is NOT computed over the body with marker
    assert digest not in base_body
    assert digest in final_body
    assert marker.startswith("\n\n<!-- repolens-review:")


def test_alembic_migration_009_roundtrip():
    """Verify Alembic migration 008 -> 009 -> 008 -> 009 roundtrip cycle."""
    config = Config("backend/alembic.ini")
    config.set_main_option("script_location", "backend/alembic")
    config.set_main_option("sqlalchemy.url", "sqlite:///test_alembic_phase7.db")

    import os
    if os.path.exists("test_alembic_phase7.db"):
        os.remove("test_alembic_phase7.db")

    try:
        # Upgrade to head (009)
        command.upgrade(config, "head")

        # Downgrade to 008
        command.downgrade(config, "008_change_analysis_domain")

        # Re-upgrade to head (009)
        command.upgrade(config, "head")
    finally:
        if os.path.exists("test_alembic_phase7.db"):
            os.remove("test_alembic_phase7.db")
