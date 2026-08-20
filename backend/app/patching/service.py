"""PatchService coordinating evidence retrieval and safe patch generation."""

import os
from typing import Dict, List, Optional

from app.context.engine import ContextEngine
from app.ingestion.schemas import RepositoryManifest
from app.patching.agent import PatchGeneratorAgent
from app.patching.schemas import PatchProposal
from app.planning.schemas import FixPlan
from app.schemas.finding import Finding


class PatchService:
    """Canonical service managing safe, evidence-constrained patch proposal generation.
    
    Guarantees:
    - Strictly reads repository files without mutating them.
    - Captures proposed diffs in memory without applying to disk.
    """

    def __init__(self, agent: Optional[PatchGeneratorAgent] = None):
        self.agent = agent or PatchGeneratorAgent()

    def _read_target_files(self, repo_dir: str, file_paths: List[str]) -> Dict[str, str]:
        """Safely read target file contents from the read-only cloned repository."""
        contents: Dict[str, str] = {}
        abs_repo = os.path.abspath(repo_dir)

        for rel_path in file_paths:
            clean_rel = rel_path.replace("\\", "/").lstrip("/")
            full_path = os.path.abspath(os.path.join(abs_repo, clean_rel))

            # Confinement check
            if not full_path.startswith(abs_repo):
                continue
            if os.path.exists(full_path) and os.path.isfile(full_path):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        contents[clean_rel] = f.read()
                except Exception:
                    continue

        return contents

    async def generate_patch_proposal(
        self,
        finding: Finding,
        fix_plan: FixPlan,
        context_engine: ContextEngine,
        repo_dir: str,
        manifest: Optional[RepositoryManifest] = None,
    ) -> PatchProposal:
        """Generate a validated PatchProposal for an approved FixPlan."""
        # 1. Read source files targeted by FixPlan safely
        source_files = self._read_target_files(repo_dir, fix_plan.files_expected_to_change)

        # 2. Retrieve targeted ContextBundle
        query = f"Patch remediation for {finding.title} in {', '.join(fix_plan.files_expected_to_change)}"
        context_bundle = await context_engine.build_context_bundle(
            scan_id=str(finding.scan_id),
            query=query,
            analysis_intent="patch_generation",
            context_budget=3000,
            max_chunks=4,
        )

        # 3. Generate and validate patch proposal
        return await self.agent.generate_patch(
            finding=finding,
            fix_plan=fix_plan,
            context_bundle=context_bundle,
            source_files=source_files,
            manifest=manifest,
        )
