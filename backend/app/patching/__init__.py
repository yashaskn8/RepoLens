"""Safe patch generation and deterministic verification package for RepoLens."""

from app.patching.agent import PatchGeneratorAgent
from app.patching.applier import apply_patch_hunk, apply_unified_diff_to_directory
from app.patching.schemas import (
    PatchProposal,
    PatchValidationReport,
    PatchValidationStatus,
    PatchVerificationResult,
    VerificationCheckItem,
    VerificationStatus,
)
from app.patching.service import PatchService
from app.patching.validator import parse_diff_files, validate_patch_proposal
from app.patching.verification import PatchVerificationService

__all__ = [
    "PatchGeneratorAgent",
    "PatchProposal",
    "PatchService",
    "PatchValidationReport",
    "PatchValidationStatus",
    "PatchVerificationResult",
    "PatchVerificationService",
    "VerificationCheckItem",
    "VerificationStatus",
    "apply_patch_hunk",
    "apply_unified_diff_to_directory",
    "parse_diff_files",
    "validate_patch_proposal",
]
