"""Canonical DeliveryService orchestrating idempotent, safe GitHub pull request delivery."""

from datetime import datetime, timezone
import hashlib
import logging
import os
from typing import Optional, Set
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.delivery.github_provider import GitHubDeliveryProvider
from app.delivery.pr_body import generate_pr_body, generate_pr_title
from app.delivery.provider import RepositoryDeliveryProvider
from app.delivery.schemas import DeliveryProviderError, GitTreeEntry
from app.delivery.validator import (
    DeliveryValidationResult,
    DeliveryValidator,
    extract_github_owner_repo,
    sanitize_branch_name,
    _normalize_path,
)
from app.ingestion.snapshot import get_snapshot_service
from app.models.delivery import DeliveryModel
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.schemas.delivery import (
    DeliveryPreviewResponse,
    DeliveryRequest,
    DeliveryResponse,
)
from app.schemas.enums import DeliveryStatus, PatchStatus
from app.schemas.workflow_event import WorkflowEventCreate, WorkflowEventType
from app.security.redaction import redact_secrets
from app.services.workflow_event_service import WorkflowEventService

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_idempotency_key(
    owner: str,
    repo: str,
    patch_id: str,
    base_branch: str,
    scanned_base_sha: str,
) -> str:
    """Generate a deterministic sha256 idempotency key for delivery targets."""
    raw = f"github:{owner.lower()}:{repo.lower()}:{str(patch_id).lower()}:{base_branch}:{scanned_base_sha.lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DeliveryService:
    """Service orchestrating safe GitHub delivery preview, validation, and PR creation."""

    def __init__(
        self,
        provider: Optional[RepositoryDeliveryProvider] = None,
        settings: Optional[Settings] = None,
    ):
        self.settings = settings or get_settings()
        self.provider = provider or GitHubDeliveryProvider(settings=self.settings)

    async def get_delivery_preview(
        self,
        db: Session,
        patch_id: str,
    ) -> DeliveryPreviewResponse:
        """Provide a read-only deterministic preview of delivery eligibility and proposed parameters."""
        patch: Optional[PatchModel] = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
        if not patch:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Patch proposal '{patch_id}' not found.",
            )

        val_result: DeliveryValidationResult = await DeliveryValidator.validate(
            db=db,
            patch_id=patch_id,
            provider=self.provider,
            check_remote_head=self.provider.is_configured,
        )

        return DeliveryPreviewResponse(
            eligible=val_result.eligible,
            blocking_reason=val_result.blocking_reason,
            failure_code=val_result.failure_code,
            repository_url=val_result.repository_url,
            repository_owner=val_result.repository_owner,
            repository_name=val_result.repository_name,
            base_branch=val_result.base_branch,
            scanned_base_sha=val_result.scanned_base_sha,
            observed_base_sha=val_result.observed_base_sha,
            files_modified=val_result.files_modified,
            patch_status=val_result.patch_status,
            machine_verdict=val_result.machine_verdict,
            human_approved=val_result.human_approved,
            proposed_branch_name=val_result.proposed_branch_name,
            proposed_pr_title=val_result.proposed_pr_title,
            github_delivery_configured=self.provider.is_configured,
        )

    async def deliver_patch(
        self,
        db: Session,
        patch_id: str,
        payload: Optional[DeliveryRequest] = None,
    ) -> DeliveryModel:
        """Execute safe, idempotent GitHub pull request delivery for an approved patch."""
        if payload is None:
            payload = DeliveryRequest()
        # 1. Inspect patch and domain constraints
        patch: Optional[PatchModel] = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
        if not patch:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Patch proposal '{patch_id}' not found.",
            )

        if patch.status != PatchStatus.APPROVED.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot deliver patch with status '{patch.status}'. Patch must be explicitly APPROVED by a human first.",
            )

        if patch.machine_verdict == "REJECTED":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Cannot deliver a patch whose machine verification verdict is REJECTED.",
            )

        finding: Optional[FindingModel] = db.query(FindingModel).filter(FindingModel.id == str(patch.finding_id)).first()
        scan: Optional[ScanModel] = db.query(ScanModel).filter(ScanModel.id == str(patch.scan_id)).first()
        if not finding or not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Associated finding or scan records not found.",
            )

        owner, repo = extract_github_owner_repo(scan.repository_url)
        base_branch = scan.branch or "main"
        scanned_sha = scan.commit_hash or ""

        # 2. Compute deterministic idempotency key
        idem_key = compute_idempotency_key(
            owner=owner,
            repo=repo,
            patch_id=str(patch.id),
            base_branch=base_branch,
            scanned_base_sha=scanned_sha,
        )

        # 3. Handle concurrency & acquire or create DeliveryModel
        delivery: Optional[DeliveryModel] = db.query(DeliveryModel).filter(DeliveryModel.idempotency_key == idem_key).first()

        if delivery:
            # Reconcile existing delivery state
            if delivery.status == DeliveryStatus.PR_CREATED.value:
                logger.info(f"Delivery {delivery.id} already completed with PR #{delivery.pr_number}. Returning existing.")
                return delivery

            if delivery.status == DeliveryStatus.BLOCKED.value and delivery.failure_code == "BLOCKED_BASE_DRIFT":
                logger.info(f"Delivery {delivery.id} is BLOCKED due to base drift. Returning blocked delivery.")
                return delivery

            # Retry attempt on FAILED or in-flight delivery
            delivery.attempt_count += 1
            delivery.last_attempt_at = _utc_now()
            delivery.status = DeliveryStatus.PENDING.value
            delivery.requested_by = payload.requested_by or delivery.requested_by
            db.commit()
            db.refresh(delivery)
        else:
            proposed_branch = sanitize_branch_name(str(finding.id), str(patch.id))
            delivery = DeliveryModel(
                scan_id=str(scan.id),
                finding_id=str(finding.id),
                patch_id=str(patch.id),
                provider="github",
                repository_url=scan.repository_url,
                repository_owner=owner,
                repository_name=repo,
                base_branch=base_branch,
                scanned_base_sha=scanned_sha,
                head_branch=proposed_branch,
                status=DeliveryStatus.PENDING.value,
                idempotency_key=idem_key,
                requested_by=payload.requested_by or "user",
                attempt_count=1,
                last_attempt_at=_utc_now(),
            )
            try:
                db.add(delivery)
                db.commit()
                db.refresh(delivery)
            except IntegrityError:
                # Concurrent race condition caught safely
                db.rollback()
                delivery = db.query(DeliveryModel).filter(DeliveryModel.idempotency_key == idem_key).first()
                if not delivery:
                    raise HTTPException(status_code=500, detail="Failed to acquire delivery record.")
                if delivery.status == DeliveryStatus.PR_CREATED.value:
                    return delivery

        # 4. Emit DELIVERY_REQUESTED audit event
        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.DELIVERY_REQUESTED,
                scan_id=UUID(str(scan.id)),
                finding_id=UUID(str(finding.id)),
                patch_id=UUID(str(patch.id)),
                stage="delivery",
                provider="github",
                message=f"GitHub pull request delivery requested by {delivery.requested_by}",
                metadata_payload={
                    "delivery_id": str(delivery.id),
                    "repository": f"{owner}/{repo}",
                    "base_branch": base_branch,
                    "scanned_base_sha": scanned_sha,
                    "attempt_count": delivery.attempt_count,
                },
            ),
            critical=False,
        )

        # 5. Transition to VALIDATING and run DeliveryValidator
        delivery.status = DeliveryStatus.VALIDATING.value
        db.commit()

        val_result = await DeliveryValidator.validate(
            db=db,
            patch_id=str(patch.id),
            provider=self.provider,
            check_remote_head=True,
        )

        delivery.observed_base_sha = val_result.observed_base_sha

        if not val_result.eligible:
            delivery.status = DeliveryStatus.BLOCKED.value if val_result.failure_code == "BLOCKED_BASE_DRIFT" else DeliveryStatus.FAILED.value
            delivery.failure_code = val_result.failure_code or "VALIDATION_FAILED"
            delivery.failure_message = redact_secrets(val_result.blocking_reason)[:512]
            delivery.completed_at = _utc_now()

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.DELIVERY_BLOCKED if delivery.status == DeliveryStatus.BLOCKED.value else WorkflowEventType.DELIVERY_FAILED,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding.id)),
                    patch_id=UUID(str(patch.id)),
                    stage="delivery",
                    provider="github",
                    message=f"Delivery validation blocked: {delivery.failure_message}",
                    metadata_payload={
                        "delivery_id": str(delivery.id),
                        "failure_code": delivery.failure_code,
                        "scanned_base_sha": scanned_sha,
                        "observed_base_sha": val_result.observed_base_sha,
                    },
                ),
                critical=False,
            )
            db.commit()
            db.refresh(delivery)
            return delivery

        # 6. Transition to READY
        delivery.status = DeliveryStatus.READY.value
        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.DELIVERY_VALIDATED,
                scan_id=UUID(str(scan.id)),
                finding_id=UUID(str(finding.id)),
                patch_id=UUID(str(patch.id)),
                stage="delivery",
                provider="github",
                message="Delivery pre-flight validation passed cleanly.",
                metadata_payload={
                    "delivery_id": str(delivery.id),
                    "base_branch": base_branch,
                    "scanned_base_sha": scanned_sha,
                    "head_branch": delivery.head_branch,
                },
            ),
            critical=False,
        )
        db.commit()

        # 7. Execute Git Data API steps
        try:
            # 7a. CREATING_COMMIT
            delivery.status = DeliveryStatus.CREATING_COMMIT.value
            db.commit()

            commit_info = await self.provider.get_commit(owner=owner, repo=repo, sha=scanned_sha)

            # Rehydrate snapshot to extract patched files
            snapshot_service = get_snapshot_service()
            tree_entries = []

            with snapshot_service.snapshot_context(str(scan.id), db=db) as workspace:
                from app.patching.applier import apply_unified_diff_to_directory
                try:
                    apply_unified_diff_to_directory(patch.unified_diff, workspace)
                except Exception as apply_err:
                    raise DeliveryProviderError(f"Patch apply failed during tree assembly: {apply_err}", safe_code="TREE_BUILD_APPLY_FAILED")

                for f_rel in (patch.files_modified or []):
                    norm_f = _normalize_path(f_rel)
                    full_p = os.path.join(workspace, norm_f)
                    if os.path.exists(full_p):
                        with open(full_p, "r", encoding="utf-8", errors="replace") as f_obj:
                            file_content = f_obj.read()
                        blob_sha = await self.provider.create_blob(owner=owner, repo=repo, content=file_content)
                        tree_entries.append(GitTreeEntry(path=norm_f, mode="100644", type="blob", sha=blob_sha))
                    else:
                        # Deletion
                        tree_entries.append(GitTreeEntry(path=norm_f, mode="100644", type="blob", sha=None))

            tree_sha = await self.provider.create_tree(
                owner=owner,
                repo=repo,
                base_tree_sha=commit_info.tree_sha,
                tree_entries=tree_entries,
            )

            commit_msg = f"fix(repolens): remediate {finding.title[:80]}"
            head_sha = await self.provider.create_commit(
                owner=owner,
                repo=repo,
                message=commit_msg,
                tree_sha=tree_sha,
                parent_shas=[scanned_sha],
            )
            delivery.head_sha = head_sha

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.DELIVERY_COMMIT_CREATED,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding.id)),
                    patch_id=UUID(str(patch.id)),
                    stage="delivery",
                    provider="github",
                    message=f"Created remediation commit {head_sha[:8]} on GitHub",
                    metadata_payload={"delivery_id": str(delivery.id), "commit_sha": head_sha},
                ),
                critical=False,
            )
            db.commit()

            # 7b. CREATING_BRANCH
            delivery.status = DeliveryStatus.CREATING_BRANCH.value
            db.commit()

            try:
                await self.provider.create_branch(
                    owner=owner,
                    repo=repo,
                    branch_name=delivery.head_branch,
                    sha=head_sha,
                )
            except GitHubAPIError as branch_err:
                # If branch already exists (e.g. from prior interrupted attempt), reconcile safely
                if "already exists" not in branch_err.message.lower() and branch_err.status_code != 422:
                    raise

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.DELIVERY_BRANCH_CREATED,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding.id)),
                    patch_id=UUID(str(patch.id)),
                    stage="delivery",
                    provider="github",
                    message=f"Created dedicated remediation branch '{delivery.head_branch}'",
                    metadata_payload={"delivery_id": str(delivery.id), "branch": delivery.head_branch, "commit_sha": head_sha},
                ),
                critical=False,
            )
            db.commit()

            # 7c. CREATING_PR
            delivery.status = DeliveryStatus.CREATING_PR.value
            db.commit()

            # Reconcile existing PR before attempting creation
            existing_pr = await self.provider.find_existing_pull_request(
                owner=owner,
                repo=repo,
                head=delivery.head_branch,
                base=base_branch,
            )

            if existing_pr:
                pr_info = existing_pr
                logger.info(f"Reconciled existing GitHub PR #{pr_info.number} for branch {delivery.head_branch}")
            else:
                pr_title = generate_pr_title(finding.title)
                pr_body = generate_pr_body(
                    finding=finding,
                    patch=patch,
                    scan=scan,
                    requested_by=payload.requested_by or "user",
                    notes=payload.notes,
                )
                pr_info = await self.provider.create_pull_request(
                    owner=owner,
                    repo=repo,
                    title=pr_title,
                    body=pr_body,
                    head=delivery.head_branch,
                    base=base_branch,
                )

            # 7d. PR_CREATED - final atomic state and audit event
            delivery.pr_number = pr_info.number
            delivery.pr_url = f"https://github.com/{owner}/{repo}/pull/{pr_info.number}"
            delivery.status = DeliveryStatus.PR_CREATED.value
            delivery.completed_at = _utc_now()
            delivery.failure_code = None
            delivery.failure_message = None

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.DELIVERY_PR_CREATED,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding.id)),
                    patch_id=UUID(str(patch.id)),
                    stage="delivery",
                    provider="github",
                    message=f"GitHub Pull Request #{pr_info.number} successfully created",
                    metadata_payload={
                        "delivery_id": str(delivery.id),
                        "pr_number": pr_info.number,
                        "pr_url": delivery.pr_url,
                        "head_branch": delivery.head_branch,
                        "base_branch": base_branch,
                    },
                ),
                critical=True,
            )

            db.commit()
            db.refresh(delivery)
            return delivery

        except Exception as exc:
            logger.error(f"Delivery failed during execution for patch {patch.id}: {exc}", exc_info=True)
            delivery.status = DeliveryStatus.FAILED.value
            delivery.failure_code = getattr(exc, "safe_code", "DELIVERY_FAILED")
            delivery.failure_message = redact_secrets(str(exc))[:512]
            delivery.completed_at = _utc_now()

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.DELIVERY_FAILED,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding.id)),
                    patch_id=UUID(str(patch.id)),
                    stage="delivery",
                    provider="github",
                    message=f"Delivery execution failed: {delivery.failure_message}",
                    metadata_payload={
                        "delivery_id": str(delivery.id),
                        "failure_code": delivery.failure_code,
                    },
                ),
                critical=False,
            )
            db.commit()
            db.refresh(delivery)
            return delivery
