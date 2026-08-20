"""Safe patch generation package for RepoLens."""

from app.patching.agent import PatchGeneratorAgent
from app.patching.schemas import (
    PatchProposal,
    PatchValidationReport,
    PatchValidationStatus,
)
from app.patching.service import PatchService
from app.patching.validator import parse_diff_files, validate_patch_proposal

__all__ = [
    "PatchGeneratorAgent",
    "PatchProposal",
    "PatchService",
    "PatchValidationReport",
    "PatchValidationStatus",
    "parse_diff_files",
    "validate_patch_proposal",
]
