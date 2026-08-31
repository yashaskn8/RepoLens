"""Canonical domain service for Safe Pull Request Review Publication.

Guarantees:
- Strictly enforces two-stage human authorization: preview -> approve -> publish.
- Validates immutable commit SHAs at preview and re-validates immediately before publication.
- Atomic concurrency transition (APPROVED -> PUBLISHING) preventing race conditions.
- Rollback-first error handling on DB commit failure after external write.
- Deterministic crash recovery and reconciliation using hidden review markers.
- Never performs autonomous PR approval, request_changes, or merging.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.schemas.change_analysis import ChangeReviewReport
from app.core.config import get_settings
from app.delivery.publication_provider import (
    GitHubReviewPublicationProvider,
    PullRequestReviewPublicationProvider,
)
from app.delivery.review_renderer import ReviewPublicationRenderer
from app.models.change_analysis import ChangeAnalysisModel
from app.models.review_publication import PullRequestReviewPublicationModel
from app.schemas.review_publication import (
    AnalysisNotCompletedError,
    ForkPRUnsupportedError,
    GitHubAuthFailedError,
    GitHubReviewStateUncertainError,
    GitHubReviewWriteDisabledError,
    InlineReviewComment,
    NotPRAnalysisError,
    PRBaseDriftError,
    PRClosedError,
    PRHeadDriftError,
    PRMergedError,
    PRNotFoundError,
    PreviewDigestMismatchError,
    PublicationNotApprovedError,
    ReviewPublicationError,
    ReviewPublicationStatus,
    VerifiedReviewInvalidError,
    VerifiedReviewNotAvailableError,
)
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.security.redaction import redact_secrets
from app.services.workflow_event_service import WorkflowEventService

logger = logging.getLogger(__name__)


def _utc_now():
    return datetime.now(timezone.utc)


class ReviewPublicationService:
    """Coordinates deterministic rendering, authorization, drift checks, publication, and reconciliation."""

    def __init__(
        self,
        db: Session,
        provider: Optional[PullRequestReviewPublicationProvider] = None,
        renderer: Optional[ReviewPublicationRenderer] = None,
        event_service: Optional[WorkflowEventService] = None,
    ):
        self.db = db
        settings = get_settings()
        self.provider = provider or GitHubReviewPublicationProvider(settings=settings)
        self.renderer = renderer or ReviewPublicationRenderer(
            max_body_chars=getattr(settings, "MAX_REVIEW_BODY_CHARS", 50000),
            max_inline_comments=getattr(settings, "MAX_REVIEW_INLINE_COMMENTS", 20),
        )
        self.event_service = event_service or WorkflowEventService()

    def _extract_pr_provenance(self, analysis: ChangeAnalysisModel) -> tuple[int, bool]:
        """Extract and validate immutable PR provenance from analysis metadata."""
        meta = analysis.model_metadata or {}

        # Primary: Canonical top-level PR metadata persisted by Phase 6 /from-pr
        pr_number = meta.get("pr_number")
        is_fork = meta.get("is_fork")

        # Fallback: Legacy nested representation if present
        if pr_number is None:
            nested = meta.get("pr_metadata") or meta.get("pull_request") or {}
            pr_number = nested.get("pr_number")
            if is_fork is None:
                is_fork = nested.get("is_fork")

        if pr_number is None:
            raise NotPRAnalysisError("ChangeAnalysis does not contain valid pull request provenance (missing pr_number)")

        try:
            pr_num_int = int(pr_number)
            if pr_num_int <= 0:
                raise ValueError()
        except (TypeError, ValueError):
            raise NotPRAnalysisError(f"Invalid pull request number: {pr_number}")

        is_fork_bool = bool(is_fork) if is_fork is not None else False
        if is_fork_bool:
            raise ForkPRUnsupportedError("Pull request originates from a fork repository")

        if not analysis.repository_owner or not analysis.repository_name:
            raise NotPRAnalysisError("ChangeAnalysis is missing valid repository owner or name")

        if not analysis.base_commit_sha or not analysis.head_commit_sha:
            raise NotPRAnalysisError("ChangeAnalysis is missing base or head commit SHA")

        return pr_num_int, is_fork_bool

    async def generate_preview(self, analysis_id: UUID) -> PullRequestReviewPublicationModel:
        """Generate deterministic review publication preview (ZERO GitHub writes)."""
        # 1. Query ChangeAnalysis
        analysis = self.db.query(ChangeAnalysisModel).filter_by(id=str(analysis_id)).first()
        if not analysis:
            raise ReviewPublicationError(f"ChangeAnalysis '{analysis_id}' not found", error_code="ANALYSIS_NOT_FOUND", status_code=404)

        if analysis.status != "COMPLETED":
            raise AnalysisNotCompletedError(f"ChangeAnalysis status is '{analysis.status}', must be 'COMPLETED'")

        # 2. Extract and validate PR provenance
        pr_number, _ = self._extract_pr_provenance(analysis)

        # 3. Re-read current PR from GitHub to detect drift
        current_pr = await self.provider.get_current_pull_request(
            owner=analysis.repository_owner,
            repo=analysis.repository_name,
            pr_number=pr_number,
        )

        if current_pr.is_fork:
            raise ForkPRUnsupportedError("Pull request originates from a fork repository")
        if current_pr.state == "merged":
            raise PRMergedError(f"Pull request #{pr_number} has already been merged")
        if current_pr.state != "open":
            raise PRClosedError(f"Pull request #{pr_number} is closed")
        if current_pr.base_commit_sha != analysis.base_commit_sha:
            raise PRBaseDriftError(
                f"Base commit SHA drifted (analyzed: {analysis.base_commit_sha}, current PR: {current_pr.base_commit_sha})"
            )
        if current_pr.head_commit_sha != analysis.head_commit_sha:
            raise PRHeadDriftError(
                f"Head commit SHA drifted (analyzed: {analysis.head_commit_sha}, current PR: {current_pr.head_commit_sha})"
            )

        # 4. Fetch changed files from PR for exact inline comment mapping
        diff_files = await self.provider.get_pull_request_diff_files(
            owner=analysis.repository_owner,
            repo=analysis.repository_name,
            pr_number=pr_number,
        )

        # 5. FIX 7: Validate Phase 6 verified review report is available and parseable
        meta = analysis.model_metadata or {}
        review_report_dict = meta.get("review_report")
        if not review_report_dict:
            raise VerifiedReviewNotAvailableError(
                f"ChangeAnalysis '{analysis_id}' does not contain a Phase 6 verified review_report in model_metadata"
            )
        try:
            review_report = ChangeReviewReport.model_validate(review_report_dict)
        except Exception as e:
            raise VerifiedReviewInvalidError(
                f"Phase 6 review_report in analysis metadata is malformed: {redact_secrets(str(e))[:256]}"
            )

        # FIX A: Bind verified review to current analysis ID
        if str(review_report.analysis_id) != str(analysis.id):
            raise VerifiedReviewInvalidError(
                f"Phase 6 review_report analysis_id '{review_report.analysis_id}' does not match "
                f"ChangeAnalysis ID '{analysis.id}'"
            )

        # 6. Render deterministic review publication
        rendered = self.renderer.render_publication(
            analysis=analysis,
            pr_number=pr_number,
            review_report=review_report,
            impacts=analysis.impacts,
            diff_files=diff_files,
        )

        # 7. Upsert publication model with state-machine enforcement
        pub = self.db.query(PullRequestReviewPublicationModel).filter_by(analysis_id=str(analysis_id)).first()
        if not pub:
            pub = PullRequestReviewPublicationModel(
                analysis_id=str(analysis_id),
                repository_owner=analysis.repository_owner,
                repository_name=analysis.repository_name,
                pr_number=pr_number,
                base_commit_sha=analysis.base_commit_sha,
                head_commit_sha=analysis.head_commit_sha,
                status=ReviewPublicationStatus.PREVIEW_READY.value,
                preview_body=rendered.preview_body,
                preview_digest=rendered.preview_digest,
                inline_comments_payload=[c.model_dump() for c in rendered.inline_comments],
                is_truncated=rendered.is_truncated,
                truncation_reason=rendered.truncation_reason,
            )
            self.db.add(pub)
            # FIX F: Materialize pub.id within caller transaction before emitting audit event
            self.db.flush()
        else:
            # FIX 1: PUBLISHING is uncertain-write; reconcile instead of blind reset
            if pub.status == ReviewPublicationStatus.PUBLISHING.value:
                reconciled = await self.reconcile_publication(pub)
                if reconciled.status == ReviewPublicationStatus.PUBLISHED.value:
                    return reconciled
                raise GitHubReviewStateUncertainError(
                    f"Publication '{pub.id}' is in PUBLISHING state. "
                    f"Reconciliation did not find a matching review on GitHub. "
                    f"Cannot regenerate preview until state is resolved."
                )

            # FIX 1: PUBLISHED is idempotent return
            if pub.status == ReviewPublicationStatus.PUBLISHED.value:
                return pub

            # FIX 2: BLOCKED is immutable — drift already occurred
            if pub.status == ReviewPublicationStatus.BLOCKED.value:
                raise ReviewPublicationError(
                    f"Publication '{pub.id}' is BLOCKED due to immutable drift "
                    f"(failure_code: {pub.failure_code}). Cannot regenerate preview.",
                    error_code="PUBLICATION_BLOCKED",
                    status_code=409,
                )

            # Safe to regenerate: PREVIEW_READY, APPROVED, FAILED
            pub.repository_owner = analysis.repository_owner
            pub.repository_name = analysis.repository_name
            pub.pr_number = pr_number
            pub.base_commit_sha = analysis.base_commit_sha
            pub.head_commit_sha = analysis.head_commit_sha
            pub.preview_body = rendered.preview_body
            pub.preview_digest = rendered.preview_digest
            pub.inline_comments_payload = [c.model_dump() for c in rendered.inline_comments]
            pub.is_truncated = rendered.is_truncated
            pub.truncation_reason = rendered.truncation_reason
            # Regenerating preview resets approval
            pub.status = ReviewPublicationStatus.PREVIEW_READY.value
            pub.approved_at = None
            pub.failure_code = None
            pub.failure_message = None

        # FIX 3: Emit audit event BEFORE commit for atomicity (pub.id guaranteed materialized)
        self.event_service.emit_critical(
            self.db,
            WorkflowEventCreate(
                event_type=WorkflowEventType.PR_REVIEW_PREVIEW_READY,
                change_analysis_id=analysis_id,
                pr_review_publication_id=UUID(pub.id),
                commit_sha=analysis.head_commit_sha,
                message=f"Review publication preview generated for PR #{pr_number}",
                metadata_payload={
                    "preview_digest": rendered.preview_digest,
                    "inline_comments_count": len(rendered.inline_comments),
                    "is_truncated": rendered.is_truncated,
                },
            ),
        )

        self.db.commit()
        self.db.refresh(pub)

        return pub

    async def approve_preview(self, analysis_id: UUID, expected_preview_digest: str) -> PullRequestReviewPublicationModel:
        """Explicit human approval bound strictly to expected preview digest."""
        pub = self.db.query(PullRequestReviewPublicationModel).filter_by(analysis_id=str(analysis_id)).first()
        if not pub:
            raise ReviewPublicationError("Review publication preview has not been generated", error_code="PREVIEW_NOT_FOUND", status_code=404)

        if pub.status == ReviewPublicationStatus.PUBLISHED.value:
            return pub

        if pub.status not in (ReviewPublicationStatus.PREVIEW_READY.value, ReviewPublicationStatus.APPROVED.value):
            raise PublicationNotApprovedError(f"Cannot approve publication in '{pub.status}' state")

        if pub.preview_digest != expected_preview_digest:
            raise PreviewDigestMismatchError(
                f"Digest mismatch (expected: {expected_preview_digest}, current: {pub.preview_digest})"
            )

        pub.status = ReviewPublicationStatus.APPROVED.value
        pub.approved_at = _utc_now()

        # FIX 3: Emit audit event BEFORE commit for atomicity
        self.event_service.emit_critical(
            self.db,
            WorkflowEventCreate(
                event_type=WorkflowEventType.PR_REVIEW_APPROVED,
                change_analysis_id=analysis_id,
                pr_review_publication_id=UUID(pub.id),
                commit_sha=pub.head_commit_sha,
                message=f"Review publication approved for PR #{pub.pr_number}",
                metadata_payload={"preview_digest": pub.preview_digest},
            ),
        )

        self.db.commit()
        self.db.refresh(pub)

        return pub

    async def publish_review(self, analysis_id: UUID, expected_preview_digest: str) -> PullRequestReviewPublicationModel:
        """Publish approved review to GitHub with drift check, atomic ownership, and crash reconciliation."""
        pub = self.db.query(PullRequestReviewPublicationModel).filter_by(analysis_id=str(analysis_id)).first()
        if not pub:
            raise ReviewPublicationError("Review publication preview has not been generated", error_code="PREVIEW_NOT_FOUND", status_code=404)

        # Idempotent return if already published
        if pub.status == ReviewPublicationStatus.PUBLISHED.value:
            return pub

        # FIX B: Check if currently in uncertain PUBLISHING state (reconcile first)
        if pub.status == ReviewPublicationStatus.PUBLISHING.value:
            reconciled = await self.reconcile_publication(pub)
            if reconciled.status == ReviewPublicationStatus.PUBLISHED.value:
                return reconciled
            raise GitHubReviewStateUncertainError(
                f"Publication '{pub.id}' is in PUBLISHING state. "
                f"Reconciliation did not find a matching review on GitHub. "
                f"State remains PUBLISHING."
            )

        if pub.status != ReviewPublicationStatus.APPROVED.value:
            raise PublicationNotApprovedError(f"Publication must be in APPROVED state before publishing (current: {pub.status})")

        if pub.preview_digest != expected_preview_digest:
            raise PreviewDigestMismatchError("Provided digest does not match the approved publication digest")

        if not self.provider.write_enabled:
            raise GitHubReviewWriteDisabledError()

        # Step 1: Final drift validation immediately before write
        current_pr = await self.provider.get_current_pull_request(
            owner=pub.repository_owner,
            repo=pub.repository_name,
            pr_number=pub.pr_number,
        )

        # FIX 3: Block drift checks emit audit event atomically with BLOCKED status
        drift_error = None
        drift_failure_code = None
        drift_failure_message = None

        if current_pr.is_fork:
            drift_failure_code = "FORK_PR_UNSUPPORTED"
            drift_failure_message = "Pull request originates from a fork repository"
            drift_error = ForkPRUnsupportedError(drift_failure_message)
        elif current_pr.state == "merged":
            drift_failure_code = "PR_MERGED"
            drift_failure_message = f"Pull request #{pub.pr_number} has already been merged"
            drift_error = PRMergedError(drift_failure_message)
        elif current_pr.state != "open":
            drift_failure_code = "PR_CLOSED"
            drift_failure_message = f"Pull request #{pub.pr_number} is closed"
            drift_error = PRClosedError(drift_failure_message)
        elif current_pr.base_commit_sha != pub.base_commit_sha:
            drift_failure_code = "PR_BASE_DRIFT"
            drift_failure_message = f"Base commit SHA drifted (analyzed: {pub.base_commit_sha}, current PR: {current_pr.base_commit_sha})"
            drift_error = PRBaseDriftError("Base commit SHA has drifted")
        elif current_pr.head_commit_sha != pub.head_commit_sha:
            drift_failure_code = "PR_HEAD_DRIFT"
            drift_failure_message = f"Head commit SHA drifted (analyzed: {pub.head_commit_sha}, current PR: {current_pr.head_commit_sha})"
            drift_error = PRHeadDriftError("Head commit SHA has drifted")

        if drift_error is not None:
            pub.status = ReviewPublicationStatus.BLOCKED.value
            pub.failure_code = drift_failure_code
            pub.failure_message = drift_failure_message
            self.event_service.emit_critical(
                self.db,
                WorkflowEventCreate(
                    event_type=WorkflowEventType.PR_REVIEW_BLOCKED,
                    change_analysis_id=analysis_id,
                    pr_review_publication_id=UUID(pub.id),
                    commit_sha=pub.head_commit_sha,
                    message=f"Review publication blocked: {drift_failure_message}",
                    metadata_payload={"failure_code": drift_failure_code},
                ),
            )
            self.db.commit()
            raise drift_error

        # Step 2: Atomic transition APPROVED -> PUBLISHING
        updated = self.db.query(PullRequestReviewPublicationModel).filter(
            PullRequestReviewPublicationModel.id == pub.id,
            PullRequestReviewPublicationModel.status == ReviewPublicationStatus.APPROVED.value,
        ).update({
            PullRequestReviewPublicationModel.status: ReviewPublicationStatus.PUBLISHING.value,
            PullRequestReviewPublicationModel.updated_at: _utc_now(),
        })

        if updated == 0:
            self.db.refresh(pub)
            if pub.status == ReviewPublicationStatus.PUBLISHED.value:
                return pub
            raise ReviewPublicationError("Concurrent publish operation in progress", error_code="CONCURRENT_PUBLISH_IN_PROGRESS", status_code=409)

        # FIX 3: Emit audit event BEFORE commit for atomicity with PUBLISHING transition
        self.event_service.emit_critical(
            self.db,
            WorkflowEventCreate(
                event_type=WorkflowEventType.PR_REVIEW_PUBLISH_STARTED,
                change_analysis_id=analysis_id,
                pr_review_publication_id=UUID(pub.id),
                commit_sha=pub.head_commit_sha,
                message=f"Starting review publication to GitHub PR #{pub.pr_number}",
            ),
        )

        self.db.commit()

        # Step 3: Execute single GitHub create-review POST
        inline_comments = [
            InlineReviewComment.model_validate(c) for c in (pub.inline_comments_payload or [])
        ]

        try:
            res = await self.provider.create_comment_review(
                owner=pub.repository_owner,
                repo=pub.repository_name,
                pr_number=pub.pr_number,
                commit_sha=pub.head_commit_sha,
                body=pub.preview_body,
                comments=inline_comments,
            )
        except Exception as external_exc:
            safe_ext_err = redact_secrets(str(external_exc))[:500]
            # Definite pre-write rejection (no external write occurred)
            if isinstance(external_exc, (GitHubReviewWriteDisabledError, GitHubAuthFailedError)):
                pub.status = ReviewPublicationStatus.FAILED.value
                pub.failure_code = getattr(external_exc, "error_code", "GITHUB_REVIEW_CREATE_FAILED")
                pub.failure_message = safe_ext_err
                self.event_service.emit_critical(
                    self.db,
                    WorkflowEventCreate(
                        event_type=WorkflowEventType.PR_REVIEW_FAILED,
                        change_analysis_id=analysis_id,
                        pr_review_publication_id=UUID(pub.id),
                        commit_sha=pub.head_commit_sha,
                        message=f"Review publication failed before write: {safe_ext_err}",
                        metadata_payload={"failure_code": pub.failure_code},
                    ),
                )
                self.db.commit()
                raise

            logger.warning(f"External write threw exception or uncertain outcome: {safe_ext_err}. Attempting reconciliation...")
            reconciled = await self.reconcile_publication(pub)
            if reconciled.status == ReviewPublicationStatus.PUBLISHED.value:
                return reconciled

            # FIX 1: Uncertain write outcome: status remains PUBLISHING (never FAILED).
            raise GitHubReviewStateUncertainError(
                f"External GitHub review creation resulted in an uncertain state ({safe_ext_err}). "
                f"Reconciliation did not find the review on GitHub. Publication status remains PUBLISHING."
            ) from external_exc

        # Step 4: Persist PUBLISHED state + audit event atomically
        github_review_id = res.get("id")
        github_review_url = f"https://github.com/{pub.repository_owner}/{pub.repository_name}/pull/{pub.pr_number}#pullrequestreview-{github_review_id}"

        try:
            pub.status = ReviewPublicationStatus.PUBLISHED.value
            pub.github_review_id = github_review_id
            pub.github_review_url = github_review_url
            pub.published_at = _utc_now()

            # FIX 3: Emit completion event atomically in same transaction before commit
            self.event_service.emit_critical(
                self.db,
                WorkflowEventCreate(
                    event_type=WorkflowEventType.PR_REVIEW_PUBLISHED,
                    change_analysis_id=analysis_id,
                    pr_review_publication_id=UUID(pub.id),
                    commit_sha=pub.head_commit_sha,
                    message=f"Review published to GitHub PR #{pub.pr_number}",
                    metadata_payload={
                        "github_review_id": github_review_id,
                        "github_review_url": github_review_url,
                        "inline_comments_count": len(inline_comments),
                    },
                ),
            )
            self.db.commit()
            self.db.refresh(pub)
        except Exception as db_exc:
            # Rule 6: Rollback first on DB failure after external write
            self.db.rollback()
            safe_db_err = redact_secrets(str(db_exc))[:500]
            logger.error(f"Database commit failed after successful GitHub review creation: {safe_db_err}")
            raise

        return pub

    async def reconcile_publication(self, pub: PullRequestReviewPublicationModel) -> PullRequestReviewPublicationModel:
        """Search GitHub for deterministic hidden marker and reconcile state if review exists."""
        if not pub.preview_digest:
            return pub

        marker1 = f"<!-- repolens-review:{pub.analysis_id}:{pub.preview_digest} -->"
        marker2 = f"<!-- repolens-review:{pub.id}:{pub.preview_digest} -->"

        try:
            reviews = await self.provider.list_pull_request_reviews(
                owner=pub.repository_owner,
                repo=pub.repository_name,
                pr_number=pub.pr_number,
                max_pages=3,
                per_page=100,
            )
        except Exception as e:
            safe_recon_err = redact_secrets(str(e))[:500]
            logger.warning(f"Reconciliation list_reviews failed: {safe_recon_err}")
            return pub

        for rev in reviews:
            body = rev.get("body") or ""
            if marker1 in body or marker2 in body:
                github_review_id = rev.get("id")
                # FIX C: Validate review ID as a positive integer during reconciliation
                if not isinstance(github_review_id, int) or github_review_id <= 0:
                    logger.warning(
                        f"Reconciliation matched marker for publication {pub.id} but review ID is invalid: {github_review_id}"
                    )
                    continue

                github_review_url = f"https://github.com/{pub.repository_owner}/{pub.repository_name}/pull/{pub.pr_number}#pullrequestreview-{github_review_id}"

                pub.status = ReviewPublicationStatus.PUBLISHED.value
                pub.github_review_id = github_review_id
                pub.github_review_url = github_review_url
                pub.reconciliation_occurred = True
                pub.published_at = _utc_now()

                # Emit audit event for reconciled publication atomically
                self.event_service.emit_critical(
                    self.db,
                    WorkflowEventCreate(
                        event_type=WorkflowEventType.PR_REVIEW_PUBLISHED,
                        change_analysis_id=UUID(pub.analysis_id),
                        pr_review_publication_id=UUID(pub.id),
                        commit_sha=pub.head_commit_sha,
                        message=f"Review reconciled and published to GitHub PR #{pub.pr_number}",
                        metadata_payload={
                            "github_review_id": github_review_id,
                            "github_review_url": github_review_url,
                            "reconciliation_occurred": True,
                        },
                    ),
                )
                self.db.commit()
                self.db.refresh(pub)
                logger.info(f"Successfully reconciled publication {pub.id} to review {github_review_id}")
                return pub

        return pub


# Helper type alias
Tuple_PR_Info = tuple[int, bool]
