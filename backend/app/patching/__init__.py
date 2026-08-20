"""Safe patch generation, deterministic verification, and conditional criticism package for RepoLens."""

from app.patching.agent import PatchGeneratorAgent
from app.patching.applier import (
    PatchApplyError,
    apply_patch_hunk,
    apply_unified_diff_to_directory,
    parse_unified_diff,
)
from app.patching.critic import PatchCriticAgent, should_escalate_to_critic
from app.patching.schemas import (
    CriticVerdict,
    PatchCriticReport,
    PatchProposal,
    PatchValidationReport,
    PatchValidationStatus,
    PatchVerificationResult,
    PatchWorkflowResult,
    VerificationCheckItem,
    VerificationStatus,
)
from app.patching.service import PatchService
from app.patching.validator import parse_diff_files, validate_patch_proposal
from app.patching.verification import PatchVerificationService
from app.patching.workflow import PatchWorkflowCoordinator

__all__ = [
    "CriticVerdict",
    "PatchApplyError",
    "PatchCriticAgent",
    "PatchCriticReport",
    "PatchGeneratorAgent",
    "PatchProposal",
    "PatchService",
    "PatchValidationReport",
    "PatchValidationStatus",
    "PatchVerificationResult",
    "PatchVerificationService",
    "PatchWorkflowCoordinator",
    "PatchWorkflowResult",
    "VerificationCheckItem",
    "VerificationStatus",
    "apply_patch_hunk",
    "apply_unified_diff_to_directory",
    "parse_diff_files",
    "parse_unified_diff",
    "should_escalate_to_critic",
    "validate_patch_proposal",
]

