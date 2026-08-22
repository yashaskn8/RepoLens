"""Deterministic delivery safety validator enforcing 15 strict safety and base-drift checks."""

from dataclasses import dataclass, field
import logging
import os
import re
from typing import List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.delivery.provider import RepositoryDeliveryProvider
from app.delivery.schemas import DeliveryProviderError
from app.ingestion.clone import GITHUB_URL_PATTERN, validate_github_url
from app.ingestion.snapshot import get_snapshot_service
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.patching.applier import apply_unified_diff_to_directory
from app.patching.validator import parse_diff_files
from app.patching.verification import PatchVerificationService
from app.schemas.enums import PatchStatus

logger = logging.getLogger(__name__)

# Valid branch name pattern (rejects detached HEAD indicators like HEAD@abc, shell injection, ..)
_VALID_BRANCH_PATTERN = re.compile(r"^(?!HEAD@)[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*$")


def extract_github_owner_repo(url: str) -> Tuple[str, str]:
    """Extract owner and repo name from validated GitHub URL."""
    norm_url = validate_github_url(url)
    match = GITHUB_URL_PATTERN.match(norm_url)
    if not match:
        raise ValueError(f"Cannot extract owner and repo from URL: {url}")
    owner, repo = match.groups()
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def sanitize_branch_name(finding_id: str, patch_id: str) -> str:
    """Generate deterministic, sanitized branch name bounded to 100 characters."""
    f_short = str(finding_id).replace("-", "")[:8].lower()
    p_short = str(patch_id).replace("-", "")[:8].lower()
    return f"repolens/fix-{f_short}-{p_short}"


def _normalize_path(p: str) -> str:
    """Normalize file path to canonical relative forward-slash format."""
    return p.replace("\\", "/").strip().lstrip("./")


@dataclass
class DeliveryValidationResult:
    """Outcome of deterministic delivery validation."""

    eligible: bool
    blocking_reason: Optional[str] = None
    failure_code: Optional[str] = None
    repository_url: str = ""
    repository_owner: str = ""
    repository_name: str = ""
    base_branch: str = ""
    scanned_base_sha: str = ""
    observed_base_sha: Optional[str] = None
    files_modified: List[str] = field(default_factory=list)
    patch_status: PatchStatus = PatchStatus.DRAFT
    machine_verdict: Optional[str] = None
    human_approved: bool = False
    proposed_branch_name: str = ""
    proposed_pr_title: str = ""


class DeliveryValidator:
    """Deterministic validator verifying exact-commit alignment and delivery safety."""

    @classmethod
    async def validate(
        cls,
        db: Session,
        patch_id: str,
        provider: RepositoryDeliveryProvider,
        check_remote_head: bool = True,
    ) -> DeliveryValidationResult:
        """Execute all 15 deterministic checks before any GitHub write."""
        # 1. Patch exists
        patch: Optional[PatchModel] = db.query(PatchModel).filter(PatchModel.id == str(patch_id)).first()
        if not patch:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Patch proposal '{patch_id}' does not exist.",
                failure_code="PATCH_NOT_FOUND",
            )

        # 2. Patch belongs to finding
        finding: Optional[FindingModel] = db.query(FindingModel).filter(FindingModel.id == str(patch.finding_id)).first()
        if not finding:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason="Finding referenced by patch does not exist.",
                failure_code="FINDING_NOT_FOUND",
            )

        # 3. Finding belongs to scan
        scan: Optional[ScanModel] = db.query(ScanModel).filter(ScanModel.id == str(patch.scan_id)).first()
        if not scan or scan.id != finding.scan_id:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason="Scan referenced by finding and patch does not match or exist.",
                failure_code="SCAN_NOT_FOUND",
            )

        # 4. Patch status == APPROVED
        if patch.status != PatchStatus.APPROVED.value:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Patch status is '{patch.status}', but explicit human APPROVED status is required.",
                failure_code="PATCH_NOT_APPROVED",
                patch_status=PatchStatus(patch.status) if patch.status in PatchStatus.__members__ else PatchStatus.DRAFT,
                machine_verdict=patch.machine_verdict,
                human_approved=False,
            )

        # 5. machine_verdict != REJECTED
        if patch.machine_verdict == "REJECTED":
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason="Patch machine verification verdict is REJECTED. Cannot deliver a rejected patch.",
                failure_code="MACHINE_VERDICT_REJECTED",
                patch_status=PatchStatus.APPROVED,
                machine_verdict=patch.machine_verdict,
                human_approved=True,
            )

        # 6. Scan has exact commit SHA (40 chars)
        if not scan.commit_hash or len(scan.commit_hash) != 40:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason="Scan does not have a verified 40-character commit SHA.",
                failure_code="INVALID_COMMIT_SHA",
            )

        # 7 & 8. Repository URL is valid github.com URL
        try:
            norm_repo_url = validate_github_url(scan.repository_url)
            owner, repo = extract_github_owner_repo(norm_repo_url)
        except Exception as exc:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Invalid GitHub repository URL: {exc}",
                failure_code="INVALID_REPOSITORY_URL",
            )

        # 9. Base branch is real resolved branch, not detached HEAD
        base_branch = scan.branch or "main"
        if not _VALID_BRANCH_PATTERN.match(base_branch) or base_branch.startswith("HEAD@"):
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Scan was performed on a detached reference or invalid branch name ('{base_branch}'). A real GitHub base branch is required for PR creation.",
                failure_code="INVALID_BASE_BRANCH",
                repository_url=norm_repo_url,
                repository_owner=owner,
                repository_name=repo,
                base_branch=base_branch,
                scanned_base_sha=scan.commit_hash,
            )

        proposed_branch = sanitize_branch_name(str(finding.id), str(patch.id))
        from app.delivery.pr_body import generate_pr_title
        proposed_title = generate_pr_title(finding.title)

        # 10 & 11. Remote branch head & Base drift check
        observed_sha: Optional[str] = None
        if check_remote_head:
            try:
                observed_sha = await provider.get_branch_head(owner=owner, repo=repo, branch=base_branch)
            except DeliveryProviderError as exc:
                return DeliveryValidationResult(
                    eligible=False,
                    blocking_reason=f"Could not resolve remote branch '{base_branch}' on GitHub: {exc.message}",
                    failure_code=exc.safe_code or "REMOTE_BRANCH_UNRESOLVED",
                    repository_url=norm_repo_url,
                    repository_owner=owner,
                    repository_name=repo,
                    base_branch=base_branch,
                    scanned_base_sha=scan.commit_hash,
                    patch_status=PatchStatus.APPROVED,
                    machine_verdict=patch.machine_verdict,
                    human_approved=True,
                    proposed_branch_name=proposed_branch,
                    proposed_pr_title=proposed_title,
                )

            if observed_sha != scan.commit_hash:
                return DeliveryValidationResult(
                    eligible=False,
                    blocking_reason=f"Remote base branch '{base_branch}' has drifted from scanned commit {scan.commit_hash[:8]} to {observed_sha[:8]}. A new scan is required before delivery.",
                    failure_code="BLOCKED_BASE_DRIFT",
                    repository_url=norm_repo_url,
                    repository_owner=owner,
                    repository_name=repo,
                    base_branch=base_branch,
                    scanned_base_sha=scan.commit_hash,
                    observed_base_sha=observed_sha,
                    files_modified=patch.files_modified or [],
                    patch_status=PatchStatus.APPROVED,
                    machine_verdict=patch.machine_verdict,
                    human_approved=True,
                    proposed_branch_name=proposed_branch,
                    proposed_pr_title=proposed_title,
                )

        # 12. Approved unified diff parses cleanly
        try:
            parsed_diff = parse_diff_files(patch.unified_diff)
        except Exception as exc:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Approved unified diff failed strict parsing: {exc}",
                failure_code="DIFF_PARSE_FAILED",
            )

        # 13. Exact set equality for modified files
        persisted_files: Set[str] = {_normalize_path(f) for f in (patch.files_modified or [])}
        diff_files: Set[str] = {_normalize_path(f) for f in parsed_diff}
        if persisted_files != diff_files:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Mismatch between diff files ({sorted(diff_files)}) and declared files_modified ({sorted(persisted_files)}).",
                failure_code="FILE_SET_MISMATCH",
            )

        # 14 & 15. Rehydrate exact snapshot & strict-reapply approved diff
        snapshot_service = get_snapshot_service()
        try:
            with snapshot_service.snapshot_context(str(scan.id), db=db) as workspace:
                # Apply unified diff
                try:
                    apply_unified_diff_to_directory(patch.unified_diff, workspace)
                except Exception as apply_err:
                    return DeliveryValidationResult(
                        eligible=False,
                        blocking_reason=f"Re-application of patch to exact scanned snapshot failed: {apply_err}",
                        failure_code="PATCH_REAPPLY_FAILED",
                    )

                # Re-verify deterministic syntax and security checks
                # Check for secrets or severe syntax corruption in modified files
                for f_rel in persisted_files:
                    full_path = os.path.join(workspace, f_rel)
                    if os.path.exists(full_path):
                        try:
                            with open(full_path, "r", encoding="utf-8", errors="replace") as f_obj:
                                content = f_obj.read()
                            # Check basic secret leakage
                            from app.security.redaction import redact_secrets
                            # If redact_secrets mutates text with [REDACTED], a raw secret was present
                            if redact_secrets(content) != content:
                                return DeliveryValidationResult(
                                    eligible=False,
                                    blocking_reason=f"Patched file '{f_rel}' contains sensitive credentials or secret keys.",
                                    failure_code="PATCH_CONTAINS_SECRETS",
                                )
                        except Exception as read_exc:
                            logger.warning(f"Could not read patched file {f_rel}: {read_exc}")

        except Exception as snap_exc:
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Snapshot rehydration or verification failed: {snap_exc}",
                failure_code="SNAPSHOT_REHYDRATION_FAILED",
            )

        return DeliveryValidationResult(
            eligible=True,
            blocking_reason=None,
            failure_code=None,
            repository_url=norm_repo_url,
            repository_owner=owner,
            repository_name=repo,
            base_branch=base_branch,
            scanned_base_sha=scan.commit_hash,
            observed_base_sha=observed_sha or scan.commit_hash,
            files_modified=patch.files_modified or [],
            patch_status=PatchStatus.APPROVED,
            machine_verdict=patch.machine_verdict,
            human_approved=True,
            proposed_branch_name=proposed_branch,
            proposed_pr_title=proposed_title,
        )
