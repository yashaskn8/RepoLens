"""Deterministic delivery safety validator enforcing 15 strict safety and base-drift checks."""

from dataclasses import dataclass, field
import logging
import os
import re
from typing import List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from uuid import UUID, uuid4
from app.delivery.provider import RepositoryDeliveryProvider
from app.delivery.schemas import DeliveryProviderError
from app.ingestion.clone import GITHUB_URL_PATTERN, validate_github_url
from app.ingestion.manifest import build_manifest
from app.ingestion.snapshot import get_snapshot_service
from app.models.finding import FindingModel
from app.models.patch import PatchModel
from app.models.scan import ScanModel
from app.patching.applier import apply_unified_diff_to_directory
from app.patching.schemas import CheckStatus, PatchProposal, VerificationStatus
from app.patching.validator import parse_diff_files
from app.patching.verification import PatchVerificationService
from app.planning.schemas import FixPlan, FixScope
from app.schemas.enums import FindingStatus, PatchStatus, Severity, VerificationVerdict
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)

_HEX_40_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
# Valid branch name pattern (rejects detached HEAD indicators like HEAD@abc, HEAD, raw commit SHAs, shell injection, ..)
_VALID_BRANCH_PATTERN = re.compile(r"^(?!HEAD@)(?!HEAD$)[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*$")


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
    """Deterministic validator verifying that an approved patch is safe to deliver via GitHub PR."""

    @classmethod
    async def validate(
        cls,
        db: Session,
        patch_id: str,
        provider: RepositoryDeliveryProvider,
        check_remote_head: bool = True,
    ) -> DeliveryValidationResult:
        """Execute all deterministic checks before any GitHub write."""
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

        # 3b. Scan must be COMPLETED
        if scan.status != "COMPLETED":
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Associated scan status is '{scan.status}'. Only COMPLETED scans may be delivered.",
                failure_code="SCAN_NOT_COMPLETED",
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

        # 6. Scan has exact 40-hex commit SHA
        if not scan.commit_hash or not _HEX_40_PATTERN.match(scan.commit_hash):
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason=f"Scan does not have a verified 40-character hexadecimal commit SHA (got '{scan.commit_hash}').",
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

        # 9. Base branch is real resolved branch, not guessed and not detached HEAD/SHA
        if not scan.branch or not scan.branch.strip():
            return DeliveryValidationResult(
                eligible=False,
                blocking_reason="Scan has no recorded base branch. A real GitHub base branch is required for PR delivery.",
                failure_code="BASE_BRANCH_UNRESOLVED",
                repository_url=norm_repo_url,
                repository_owner=owner,
                repository_name=repo,
                scanned_base_sha=scan.commit_hash,
            )

        base_branch = scan.branch.strip()
        if (
            not _VALID_BRANCH_PATTERN.match(base_branch)
            or base_branch.startswith("HEAD@")
            or base_branch == "HEAD"
            or _HEX_40_PATTERN.match(base_branch)
        ):
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

        # 14 & 15. Rehydrate exact snapshot and rerun canonical deterministic verification
        snapshot_service = get_snapshot_service()
        try:
            with snapshot_service.snapshot_context(str(scan.id), db=db) as workspace:
                manifest = build_manifest(
                    repo_dir=workspace,
                    repository_url=scan.repository_url,
                    commit_hash=scan.commit_hash,
                    branch=scan.branch,
                )

                proposal = PatchProposal(
                    id=UUID(str(patch.id)),
                    finding_id=UUID(str(finding.id)),
                    plan_id=UUID(str(patch.plan_id)) if patch.plan_id else None,
                    unified_diff=patch.unified_diff,
                    files_modified=patch.files_modified or [],
                    explanation=patch.explanation or f"Remediation patch for {finding.title}",
                    expected_behavior_change=patch.explanation or f"Remediation patch for {finding.title}",
                )

                finding_schema = Finding(
                    id=UUID(str(finding.id)),
                    scan_id=UUID(str(scan.id)),
                    title=finding.title,
                    description=finding.description or "",
                    severity=Severity(finding.severity),
                    status=FindingStatus(finding.status),
                    rule_id=finding.rule_id,
                    category=finding.category,
                    verification_verdict=VerificationVerdict(finding.verification_verdict) if finding.verification_verdict else None,
                    verification_reason=finding.verification_reason,
                    created_at=finding.created_at,
                    updated_at=finding.updated_at,
                )

                from app.planning.schemas import OrderedChangeStep

                ordered_steps = [
                    OrderedChangeStep(
                        step_number=idx + 1,
                        target_file=f_path,
                        description=f"Remediate vulnerability in {f_path}",
                        rationale=f"Fix identified finding: {finding.title}",
                    )
                    for idx, f_path in enumerate(patch.files_modified or ["unknown"])
                ]

                fix_plan = FixPlan(
                    id=UUID(str(patch.plan_id)) if patch.plan_id else uuid4(),
                    finding_id=UUID(str(finding.id)),
                    root_cause=finding.description or f"Root cause for {finding.title}",
                    objective=f"Remediate {finding.title}",
                    files_expected_to_change=patch.files_modified or ["unknown"],
                    symbols_expected_to_change=[],
                    ordered_changes=ordered_steps,
                    validation_plan=["Verify syntax, boundaries, and security properties"],
                    estimated_scope=FixScope.FILE if len(patch.files_modified or []) <= 1 else FixScope.CROSS_FILE,
                )

                verification_service = PatchVerificationService()
                verif_res = await verification_service.verify_patch(
                    proposal=proposal,
                    finding=finding_schema,
                    fix_plan=fix_plan,
                    original_repo_dir=workspace,
                    manifest=manifest,
                )

                if not verif_res.security_clean:
                    return DeliveryValidationResult(
                        eligible=False,
                        blocking_reason=f"Canonical deterministic verification detected secret leakage: {verif_res.explanation}",
                        failure_code="PATCH_CONTAINS_SECRETS",
                        repository_url=norm_repo_url,
                        repository_owner=owner,
                        repository_name=repo,
                        base_branch=base_branch,
                        scanned_base_sha=scan.commit_hash,
                        observed_base_sha=observed_sha or scan.commit_hash,
                    )

                if not verif_res.syntax_valid:
                    return DeliveryValidationResult(
                        eligible=False,
                        blocking_reason=f"Canonical deterministic verification detected syntax error: {verif_res.explanation}",
                        failure_code="PATCH_SYNTAX_ERROR",
                        repository_url=norm_repo_url,
                        repository_owner=owner,
                        repository_name=repo,
                        base_branch=base_branch,
                        scanned_base_sha=scan.commit_hash,
                        observed_base_sha=observed_sha or scan.commit_hash,
                    )

                if verif_res.status == VerificationStatus.FAILED:
                    return DeliveryValidationResult(
                        eligible=False,
                        blocking_reason=f"Canonical deterministic verification failed: {verif_res.explanation or 'Failed verification checks'}",
                        failure_code="VERIFICATION_FAILED",
                        repository_url=norm_repo_url,
                        repository_owner=owner,
                        repository_name=repo,
                        base_branch=base_branch,
                        scanned_base_sha=scan.commit_hash,
                        observed_base_sha=observed_sha or scan.commit_hash,
                    )

                critical_failures = [
                    f"{c.check_name}: {c.details}"
                    for c in verif_res.checks
                    if c.status == CheckStatus.FAILED
                ]
                if critical_failures:
                    return DeliveryValidationResult(
                        eligible=False,
                        blocking_reason=f"Deterministic verification check failed: {'; '.join(critical_failures)}",
                        failure_code="VERIFICATION_CHECK_FAILED",
                        repository_url=norm_repo_url,
                        repository_owner=owner,
                        repository_name=repo,
                        base_branch=base_branch,
                        scanned_base_sha=scan.commit_hash,
                        observed_base_sha=observed_sha or scan.commit_hash,
                    )

        except Exception as snap_exc:
            logger.error(f"Snapshot rehydration or verification failed: {snap_exc}", exc_info=True)
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
