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
from app.delivery.schemas import DeliveryProviderError, GitHubAPIError, GitTreeEntry
from app.delivery.validator import (
    DeliveryValidationResult,
    DeliveryValidator,
    extract_github_owner_repo,
    sanitize_branch_name,
    _normalize_path,
)
from app.execution.context import (
    current_claim,
    mark_current_side_effect_completed,
    mark_current_side_effect_started,
)
from app.governance.events import AuditLedger, DomainOutbox
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

    def prepare_delivery(
        self,
        db: Session,
        patch_id: str,
        payload: Optional[DeliveryRequest] = None,
    ) -> DeliveryModel:
        """Create or reuse the local delivery intent without performing a GitHub call."""
        payload = payload or DeliveryRequest()
        if not self.provider.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="GitHub delivery is not configured or is administratively disabled for this RepoLens instance.",
            )
        patch = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
        if patch is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patch proposal not found.")
        if patch.status != PatchStatus.APPROVED.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Patch must be explicitly APPROVED before GitHub delivery can be queued.",
            )
        if patch.machine_verdict == "REJECTED":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A machine-rejected patch cannot be delivered.",
            )
        finding = db.query(FindingModel).filter(FindingModel.id == str(patch.finding_id)).first()
        scan = db.query(ScanModel).filter(ScanModel.id == str(patch.scan_id)).first()
        if finding is None or scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Associated finding or scan not found.")
        if scan.status != "COMPLETED" or not scan.branch or not scan.commit_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Delivery requires a completed scan bound to an exact branch and commit.",
            )
        owner, repo = extract_github_owner_repo(scan.repository_url)
        idem_key = compute_idempotency_key(owner, repo, str(patch.id), scan.branch.strip(), scan.commit_hash)
        existing = db.query(DeliveryModel).filter(DeliveryModel.idempotency_key == idem_key).first()
        if existing is not None:
            if existing.status not in {DeliveryStatus.PR_CREATED.value, DeliveryStatus.BLOCKED.value}:
                existing.requested_by = payload.requested_by or existing.requested_by
                existing.request_notes = payload.notes or existing.request_notes
            return existing

        delivery = DeliveryModel(
            scan_id=str(scan.id),
            finding_id=str(finding.id),
            patch_id=str(patch.id),
            provider="github",
            repository_url=scan.repository_url,
            repository_owner=owner,
            repository_name=repo,
            base_branch=scan.branch.strip(),
            scanned_base_sha=scan.commit_hash,
            head_branch=sanitize_branch_name(str(finding.id), str(patch.id)),
            status=DeliveryStatus.PENDING.value,
            idempotency_key=idem_key,
            requested_by=payload.requested_by or "user",
            request_notes=payload.notes,
            attempt_count=0,
        )
        try:
            with db.begin_nested():
                db.add(delivery)
                db.flush()
        except IntegrityError:
            existing = db.query(DeliveryModel).filter(DeliveryModel.idempotency_key == idem_key).one()
            return existing
        return delivery

    async def deliver_patch(
        self,
        db: Session,
        patch_id: str,
        payload: Optional[DeliveryRequest] = None,
    ) -> DeliveryModel:
        """Execute safe, idempotent GitHub pull request delivery for an approved patch."""
        if payload is None:
            payload = DeliveryRequest()

        if not self.provider.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="GitHub delivery is not configured or is administratively disabled for this RepoLens instance.",
            )

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

        if scan.status != "COMPLETED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot deliver patch: Associated scan status is '{scan.status}'. Only COMPLETED scans may be delivered.",
            )

        if not scan.branch or not scan.branch.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deliver patch: Scan has no recorded base branch.",
            )

        owner, repo = extract_github_owner_repo(scan.repository_url)
        base_branch = scan.branch.strip()
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

            claim = current_claim()
            active_statuses = {
                DeliveryStatus.VALIDATING.value,
                DeliveryStatus.READY.value,
                DeliveryStatus.CREATING_COMMIT.value,
                DeliveryStatus.CREATING_BRANCH.value,
                DeliveryStatus.CREATING_PR.value,
            }
            if delivery.failure_code == "EXTERNAL_STATE_UNCERTAIN":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Delivery remote state must be reconciled before another write attempt.",
                )
            if delivery.status in active_statuses and claim is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Delivery execution is already owned by a durable work lease.",
                )
            if claim is not None and str(claim.resource_id) != str(delivery.id):
                raise HTTPException(status_code=409, detail="Durable work lease does not own this delivery.")

            # Only the durable lease owner (or a legacy FAILED retry) may reset execution state.
            delivery.attempt_count += 1
            delivery.last_attempt_at = _utc_now()
            delivery.status = DeliveryStatus.PENDING.value
            delivery.requested_by = payload.requested_by or delivery.requested_by
            delivery.request_notes = payload.notes or delivery.request_notes
            delivery.failure_code = None
            delivery.failure_message = None
            delivery.completed_at = None
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
                request_notes=payload.notes,
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
                delivery_id=UUID(str(delivery.id)),
                stage="delivery",
                provider="github",
                message=f"GitHub pull request delivery requested by {delivery.requested_by}",
                metadata_payload={
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
        db.refresh(delivery)

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
            db.commit()
            db.refresh(delivery)

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.DELIVERY_BLOCKED if delivery.status == DeliveryStatus.BLOCKED.value else WorkflowEventType.DELIVERY_FAILED,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding.id)),
                    patch_id=UUID(str(patch.id)),
                    delivery_id=UUID(str(delivery.id)),
                    stage="delivery",
                    provider="github",
                    message=f"Delivery validation blocked: {delivery.failure_message}",
                    metadata_payload={
                        "failure_code": delivery.failure_code,
                        "scanned_base_sha": scanned_sha,
                        "observed_base_sha": val_result.observed_base_sha,
                    },
                ),
                critical=False,
            )
            return delivery

        # 6. Transition to READY
        delivery.status = DeliveryStatus.READY.value
        db.commit()
        db.refresh(delivery)

        WorkflowEventService.emit(
            db=db,
            event=WorkflowEventCreate(
                event_type=WorkflowEventType.DELIVERY_VALIDATED,
                scan_id=UUID(str(scan.id)),
                finding_id=UUID(str(finding.id)),
                patch_id=UUID(str(patch.id)),
                delivery_id=UUID(str(delivery.id)),
                stage="delivery",
                provider="github",
                message="Delivery pre-flight validation passed cleanly.",
                metadata_payload={
                    "base_branch": base_branch,
                    "scanned_base_sha": scanned_sha,
                    "head_branch": delivery.head_branch,
                },
            ),
            critical=False,
        )

        # 7. Execute Git Data API steps
        pr_info = None
        delivery_id = str(delivery.id)
        head_branch_name = delivery.head_branch
        idem_key_local = delivery.idempotency_key
        scan_id_str = str(scan.id)
        finding_id_str = str(finding.id)
        patch_id_str = str(patch.id)
        repo_url_str = scan.repository_url
        requested_by_str = delivery.requested_by or "system"
        tenant_id = str(scan.owner_user_id or "legacy-local")
        external_write_started = False

        def record_write_intent() -> None:
            """Persist the fence immediately before the first mutating provider call."""
            nonlocal external_write_started
            if external_write_started:
                return
            operation_id = f"github-delivery:{delivery.id}:{delivery.idempotency_key}"
            mark_current_side_effect_started(
                db=db,
                external_operation_id=operation_id,
            )
            DomainOutbox.append(
                db,
                tenant_id=tenant_id,
                aggregate_type="DELIVERY",
                aggregate_id=str(delivery.id),
                event_type="GITHUB_DELIVERY_WRITE_STARTED",
                deduplication_key=f"delivery:{delivery.id}:write-started",
                payload={"provider": "github", "head_branch": delivery.head_branch},
            )
            AuditLedger.append(
                db,
                tenant_id=tenant_id,
                actor_id=delivery.requested_by,
                event_type="GITHUB_DELIVERY_WRITE_STARTED",
                resource_type="DELIVERY",
                resource_id=str(delivery.id),
                state_digest=delivery.idempotency_key,
                payload={"head_branch": delivery.head_branch, "base_branch": base_branch},
            )
            db.commit()
            external_write_started = True

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
                        record_write_intent()
                        blob_sha = await self.provider.create_blob(owner=owner, repo=repo, content=file_content)
                        tree_entries.append(GitTreeEntry(path=norm_f, mode="100644", type="blob", sha=blob_sha))
                    else:
                        # Deletion
                        tree_entries.append(GitTreeEntry(path=norm_f, mode="100644", type="blob", sha=None))

            record_write_intent()
            tree_sha = await self.provider.create_tree(
                owner=owner,
                repo=repo,
                base_tree_sha=commit_info.tree_sha,
                tree_entries=tree_entries,
            )

            # Resolve whether dedicated head branch already exists on GitHub
            existing_branch_sha = await self.provider.try_get_branch_head(
                owner=owner,
                repo=repo,
                branch=delivery.head_branch,
            )

            if existing_branch_sha is None:
                # CASE A: Head branch does NOT exist -> create commit and branch
                commit_msg = f"fix(repolens): remediate {finding.title[:80]}"
                head_sha = await self.provider.create_commit(
                    owner=owner,
                    repo=repo,
                    message=commit_msg,
                    tree_sha=tree_sha,
                    parent_shas=[scanned_sha],
                )
                delivery.head_sha = head_sha
                db.commit()
                db.refresh(delivery)

                WorkflowEventService.emit(
                    db=db,
                    event=WorkflowEventCreate(
                        event_type=WorkflowEventType.DELIVERY_COMMIT_CREATED,
                        scan_id=UUID(str(scan.id)),
                        finding_id=UUID(str(finding.id)),
                        patch_id=UUID(str(patch.id)),
                        delivery_id=UUID(str(delivery.id)),
                        commit_sha=head_sha,
                        stage="delivery",
                        provider="github",
                        message=f"Created remediation commit {head_sha[:8]} on GitHub",
                        metadata_payload={"commit_sha": head_sha},
                    ),
                    critical=False,
                )

                # Transition to CREATING_BRANCH
                delivery.status = DeliveryStatus.CREATING_BRANCH.value
                db.commit()
                db.refresh(delivery)

                try:
                    await self.provider.create_branch(
                        owner=owner,
                        repo=repo,
                        branch_name=delivery.head_branch,
                        sha=head_sha,
                    )
                except GitHubAPIError as branch_err:
                    # CASE D: create_branch returned 422
                    if branch_err.status_code == 422 or "already exists" in branch_err.message.lower():
                        resolved_sha = await self.provider.get_branch_head(owner=owner, repo=repo, branch=delivery.head_branch)
                        if resolved_sha != head_sha:
                            raise DeliveryProviderError(
                                f"Branch '{delivery.head_branch}' already exists at unexpected commit {resolved_sha} (expected {head_sha})",
                                status_code=409,
                                safe_code="HEAD_BRANCH_COLLISION",
                            )
                    else:
                        raise

                # Verify branch HEAD matches delivery.head_sha
                observed_branch_sha = await self.provider.get_branch_head(owner=owner, repo=repo, branch=delivery.head_branch)
                if observed_branch_sha != head_sha:
                    raise DeliveryProviderError(
                        f"Branch HEAD verification mismatch: expected {head_sha}, observed {observed_branch_sha}",
                        status_code=409,
                        safe_code="HEAD_BRANCH_SHA_MISMATCH",
                    )

                created_commit_info = await self.provider.get_commit(owner=owner, repo=repo, sha=head_sha)
                if created_commit_info.tree_sha != tree_sha or created_commit_info.parents != [scanned_sha]:
                    raise DeliveryProviderError(
                        f"Created commit {head_sha} failed verification: expected tree {tree_sha} and parent [{scanned_sha}], observed tree {created_commit_info.tree_sha} and parents {created_commit_info.parents}",
                        status_code=409,
                        safe_code="HEAD_BRANCH_COLLISION",
                    )

            else:
                # Dedicated branch ALREADY EXISTS
                if delivery.head_sha:
                    # CASE B: Head branch exists and head_sha is persisted locally
                    if existing_branch_sha != delivery.head_sha:
                        raise DeliveryProviderError(
                            f"Dedicated branch '{delivery.head_branch}' exists with SHA {existing_branch_sha} which does not match expected delivery SHA {delivery.head_sha}",
                            status_code=409,
                            safe_code="HEAD_BRANCH_COLLISION",
                        )
                    branch_commit = await self.provider.get_commit(owner=owner, repo=repo, sha=existing_branch_sha)
                    if branch_commit.sha != existing_branch_sha or branch_commit.tree_sha != tree_sha or branch_commit.parents != [scanned_sha]:
                        raise DeliveryProviderError(
                            f"Dedicated branch '{delivery.head_branch}' commit {existing_branch_sha} does not match expected parent [{scanned_sha}] and tree {tree_sha}",
                            status_code=409,
                            safe_code="HEAD_BRANCH_COLLISION",
                        )
                    head_sha = delivery.head_sha
                else:
                    # CASE C: Head branch exists but local head_sha is missing
                    branch_commit = await self.provider.get_commit(owner=owner, repo=repo, sha=existing_branch_sha)
                    matches_parent = (branch_commit.parents == [scanned_sha])
                    matches_tree = (branch_commit.tree_sha == tree_sha)

                    if matches_parent and matches_tree:
                        head_sha = existing_branch_sha
                        delivery.head_sha = head_sha
                        db.commit()
                        db.refresh(delivery)
                        logger.info(f"Reconciled and adopted existing verified branch commit {head_sha} for branch {delivery.head_branch}")
                    else:
                        raise DeliveryProviderError(
                            f"Existing branch '{delivery.head_branch}' commit {existing_branch_sha} does not match expected parent [{scanned_sha}] and tree {tree_sha}",
                            status_code=409,
                            safe_code="HEAD_BRANCH_COLLISION",
                        )

            WorkflowEventService.emit(
                db=db,
                event=WorkflowEventCreate(
                    event_type=WorkflowEventType.DELIVERY_BRANCH_CREATED,
                    scan_id=UUID(str(scan.id)),
                    finding_id=UUID(str(finding.id)),
                    patch_id=UUID(str(patch.id)),
                    delivery_id=UUID(str(delivery.id)),
                    commit_sha=head_sha,
                    stage="delivery",
                    provider="github",
                    message=f"Created dedicated remediation branch '{delivery.head_branch}'",
                    metadata_payload={"branch": delivery.head_branch, "commit_sha": head_sha},
                ),
                critical=False,
            )

            # 7c. CREATING_PR
            delivery.status = DeliveryStatus.CREATING_PR.value
            db.commit()
            db.refresh(delivery)

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
                    notes=payload.notes or delivery.request_notes,
                )
                try:
                    pr_info = await self.provider.create_pull_request(
                        owner=owner,
                        repo=repo,
                        title=pr_title,
                        body=pr_body,
                        head=delivery.head_branch,
                        base=base_branch,
                    )
                except Exception as pr_create_err:
                    # Write uncertainty: check if PR was actually created remotely despite error/timeout
                    try:
                        reconciled_pr = await self.provider.find_existing_pull_request(
                            owner=owner,
                            repo=repo,
                            head=delivery.head_branch,
                            base=base_branch,
                        )
                    except Exception:
                        reconciled_pr = None

                    if reconciled_pr:
                        logger.info(f"Reconciled PR #{reconciled_pr.number} after uncertain PR creation error: {pr_create_err}")
                        pr_info = reconciled_pr
                    else:
                        raise pr_create_err

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
                    delivery_id=UUID(str(delivery.id)),
                    stage="delivery",
                    provider="github",
                    message=f"GitHub Pull Request #{pr_info.number} successfully created",
                    metadata_payload={
                        "pr_number": pr_info.number,
                        "pr_url": delivery.pr_url,
                        "head_branch": delivery.head_branch,
                        "base_branch": base_branch,
                    },
                ),
                critical=True,
            )

            external_operation_id = f"github-pr:{owner}/{repo}:{pr_info.number}"
            mark_current_side_effect_completed(
                db=db,
                external_operation_id=external_operation_id,
            )
            DomainOutbox.append(
                db,
                tenant_id=tenant_id,
                aggregate_type="DELIVERY",
                aggregate_id=str(delivery.id),
                event_type="GITHUB_DELIVERY_COMPLETED",
                deduplication_key=f"delivery:{delivery.id}:completed",
                payload={"pr_number": pr_info.number, "pr_url": delivery.pr_url},
            )
            AuditLedger.append(
                db,
                tenant_id=tenant_id,
                actor_id=delivery.requested_by,
                event_type="GITHUB_DELIVERY_PUBLISHED",
                resource_type="DELIVERY",
                resource_id=str(delivery.id),
                state_digest=delivery.idempotency_key,
                payload={"pr_number": pr_info.number, "head_branch": delivery.head_branch},
            )

            db.commit()
            db.refresh(delivery)
            return delivery

        except Exception as exc:
            logger.error(f"Delivery failed during execution for patch {patch_id_str}: {exc}", exc_info=True)
            # 1. Immediately roll back the failed transaction
            db.rollback()

            # Determine failure code
            known_failure_code = getattr(exc, "safe_code", None)
            remote_identity_known = pr_info is not None or bool(known_failure_code)
            if external_write_started and remote_identity_known:
                try:
                    operation_id = (
                        f"github-pr:{owner}/{repo}:{pr_info.number}"
                        if pr_info is not None
                        else f"known-failure:github-delivery:{delivery_id}:{known_failure_code}"
                    )
                    mark_current_side_effect_completed(db=db, external_operation_id=operation_id)
                    db.commit()
                except Exception:
                    db.rollback()
                    remote_identity_known = False
            failure_code = (
                "LOCAL_STATE_PERSISTENCE_FAILED"
                if pr_info is not None and remote_identity_known
                else known_failure_code
                if known_failure_code
                else "EXTERNAL_STATE_UNCERTAIN"
                if external_write_started
                else "DELIVERY_FAILED"
            )
            failure_message = redact_secrets(str(exc))[:512]

            # 2. Re-query DeliveryModel on clean session if persistence is possible
            try:
                failed_delivery = db.query(DeliveryModel).filter(DeliveryModel.id == delivery_id).first()
                if failed_delivery:
                    failed_delivery.status = DeliveryStatus.FAILED.value
                    failed_delivery.failure_code = failure_code
                    failed_delivery.failure_message = failure_message
                    failed_delivery.completed_at = _utc_now()
                    db.commit()
                    db.refresh(failed_delivery)

                    try:
                        tenant_id = str(scan.owner_user_id or "legacy-local")
                        DomainOutbox.append(
                            db,
                            tenant_id=tenant_id,
                            aggregate_type="DELIVERY",
                            aggregate_id=str(failed_delivery.id),
                            event_type="GITHUB_DELIVERY_FAILED",
                            deduplication_key=f"delivery:{failed_delivery.id}:failed:{failed_delivery.attempt_count}",
                            payload={"failure_code": failed_delivery.failure_code},
                        )
                        AuditLedger.append(
                            db,
                            tenant_id=tenant_id,
                            actor_id=failed_delivery.requested_by,
                            event_type=(
                                "EXTERNAL_STATE_RECONCILIATION_REQUIRED"
                                if failed_delivery.failure_code == "EXTERNAL_STATE_UNCERTAIN"
                                else "GITHUB_DELIVERY_FAILED"
                            ),
                            resource_type="DELIVERY",
                            resource_id=str(failed_delivery.id),
                            state_digest=failed_delivery.idempotency_key,
                            payload={"failure_code": failed_delivery.failure_code},
                        )
                        db.commit()
                    except Exception:
                        db.rollback()
                        logger.warning("Could not persist canonical delivery failure events.", exc_info=True)

                    try:
                        WorkflowEventService.emit(
                            db=db,
                            event=WorkflowEventCreate(
                                event_type=WorkflowEventType.DELIVERY_FAILED,
                                scan_id=UUID(scan_id_str),
                                finding_id=UUID(finding_id_str),
                                patch_id=UUID(patch_id_str),
                                delivery_id=UUID(str(failed_delivery.id)),
                                stage="delivery",
                                provider="github",
                                message=f"Delivery execution failed: {failed_delivery.failure_message}",
                                metadata_payload={
                                    "failure_code": failed_delivery.failure_code,
                                },
                            ),
                            critical=False,
                        )
                    except Exception as evt_err:
                        logger.warning(f"Could not emit failure event: {evt_err}")

                    return failed_delivery
            except Exception as save_err:
                logger.warning(f"Could not persist failure status after rollback: {save_err}")
                db.rollback()

            # 3. If the delivery row was lost during rollback, attempt fresh re-query
            try:
                failed_delivery = db.query(DeliveryModel).filter(DeliveryModel.id == delivery_id).first()
                if failed_delivery:
                    return failed_delivery
            except Exception:
                pass

            # 4. Last resort: re-create a minimal failed delivery row so caller gets a clean response
            try:
                failed_delivery = DeliveryModel(
                    id=delivery_id,
                    scan_id=scan_id_str,
                    finding_id=finding_id_str,
                    patch_id=patch_id_str,
                    provider="github",
                    repository_url=repo_url_str or f"https://github.com/{owner}/{repo}",
                    repository_owner=owner,
                    repository_name=repo,
                    base_branch=base_branch,
                    scanned_base_sha=scanned_sha,
                    head_branch=head_branch_name,
                    status=DeliveryStatus.FAILED.value,
                    failure_code=failure_code,
                    failure_message=failure_message,
                    idempotency_key=idem_key_local,
                    requested_by=requested_by_str,
                    completed_at=_utc_now(),
                )
                db.add(failed_delivery)
                db.commit()
                db.refresh(failed_delivery)
                return failed_delivery
            except Exception as recreate_err:
                logger.warning(f"Could not re-create delivery row after rollback: {recreate_err}")
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Delivery failed and could not persist failure state: {failure_message}",
                )

    async def reconcile_delivery(self, db: Session, delivery_id: str) -> str:
        """Read GitHub state before any replay of an uncertain delivery."""
        delivery = db.query(DeliveryModel).filter(DeliveryModel.id == str(delivery_id)).first()
        if delivery is None:
            return "MISSING"
        if delivery.status == DeliveryStatus.PR_CREATED.value and delivery.pr_number:
            return "COMPLETED"
        existing_pr = await self.provider.find_existing_pull_request(
            owner=delivery.repository_owner,
            repo=delivery.repository_name,
            head=delivery.head_branch,
            base=delivery.base_branch,
        )
        branch_sha = await self.provider.try_get_branch_head(
            owner=delivery.repository_owner,
            repo=delivery.repository_name,
            branch=delivery.head_branch,
        )
        if existing_pr is not None:
            if not delivery.head_sha or branch_sha != delivery.head_sha:
                delivery.failure_code = "EXTERNAL_STATE_UNCERTAIN"
                delivery.failure_message = "A matching pull request exists, but its branch identity cannot be proven."
                db.commit()
                return "UNCERTAIN"
            delivery.status = DeliveryStatus.PR_CREATED.value
            delivery.pr_number = existing_pr.number
            delivery.pr_url = f"https://github.com/{delivery.repository_owner}/{delivery.repository_name}/pull/{existing_pr.number}"
            delivery.completed_at = _utc_now()
            delivery.failure_code = None
            delivery.failure_message = None
            delivery.reconciliation_occurred = True
            tenant_id = str(delivery.scan.owner_user_id or "legacy-local")
            DomainOutbox.append(
                db,
                tenant_id=tenant_id,
                aggregate_type="DELIVERY",
                aggregate_id=str(delivery.id),
                event_type="GITHUB_DELIVERY_RECONCILED",
                deduplication_key=f"delivery:{delivery.id}:reconciled",
                payload={"pr_number": existing_pr.number},
            )
            AuditLedger.append(
                db,
                tenant_id=tenant_id,
                event_type="GITHUB_DELIVERY_RECONCILED",
                resource_type="DELIVERY",
                resource_id=str(delivery.id),
                state_digest=delivery.idempotency_key,
                payload={"pr_number": existing_pr.number},
            )
            db.commit()
            return "COMPLETED"
        if branch_sha is None:
            return "ABSENT_SAFE_TO_RETRY"
        delivery.failure_code = "EXTERNAL_STATE_UNCERTAIN"
        delivery.failure_message = "A deterministic delivery branch exists without a matching pull request."
        db.commit()
        return "UNCERTAIN"
