"""PatchGeneratorAgent producing evidence-constrained unified diffs."""

import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.agents.helpers import extract_json_block
from app.context.schemas import ContextBundle
from app.ingestion.schemas import RepositoryManifest
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, TaskPolicy
from app.patching.schemas import PatchProposal
from app.patching.validator import parse_diff_files, validate_patch_proposal
from app.planning.schemas import FixPlan
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)


class PatchGeneratorAgent:
    """Specialized AI agent generating strict unified diff patches constrained by verified evidence.
    
    Guarantees:
    - Generates unified diffs only.
    - Never modifies the original repository directly.
    - Never executes code, commits, or pushes.
    - Rejects diffs modifying files outside the repository or approved FixPlan.
    """

    def __init__(self, router=None):
        self.router = router or get_llm_router()

    def _build_system_prompt(self) -> str:
        return (
            "You are the RepoLens Safe Patch Generator AI Agent.\n"
            "Your objective is to generate an accurate, minimal unified diff patch to remediate a verified finding "
            "following an approved FixPlan.\n\n"
            "STRICT RULES:\n"
            "1. Generate a standard unified diff ONLY (using --- a/file +++ b/file and @@ -line,count +line,count @@ headers).\n"
            "2. Modify ONLY the exact files approved in the FixPlan. NEVER touch unrelated files or architecture.\n"
            "3. DO NOT commit, push, execute code, or install packages.\n"
            "4. Preserve existing style, indentation, imports, and docstrings.\n"
            "5. Output MUST be valid JSON adhering exactly to the required schema.\n\n"
            "OUTPUT JSON SCHEMA:\n"
            "{\n"
            '  "unified_diff": "--- a/app/routes.py\\n+++ b/app/routes.py\\n@@ -10,4 +10,4 @@\\n-old_code()\\n+new_code()",\n'
            '  "explanation": "Technical explanation of the precise lines changed and why",\n'
            '  "expected_behavior_change": "Runtime behavior modification description",\n'
            '  "generated_tests_or_test_plan": ["pytest tests/test_routes.py -k test_endpoint"]\n'
            "}"
        )

    def _build_user_prompt(
        self,
        finding: Finding,
        fix_plan: FixPlan,
        context_bundle: ContextBundle,
        source_files: Dict[str, str],
    ) -> str:
        sections = [
            f"FINDING: {finding.title} ({finding.severity.value})",
            f"ROOT CAUSE: {fix_plan.root_cause}",
            f"OBJECTIVE: {fix_plan.objective}",
            f"APPROVED TARGET FILES: {', '.join(fix_plan.files_expected_to_change)}",
        ]

        # Add Ordered Steps from FixPlan
        steps_text = [
            f"Step {s.step_number} [{s.target_file}]: {s.description} (Rationale: {s.rationale})"
            for s in fix_plan.ordered_changes
        ]
        sections.append("APPROVED REMEDIATION STEPS:\n" + "\n".join(steps_text))

        # Add Actual Source File Content for targeted files
        for f_path in fix_plan.files_expected_to_change:
            clean_p = f_path.replace("\\", "/").lstrip("/")
            content = source_files.get(clean_p) or source_files.get(f_path)
            if content:
                sections.append(f"CURRENT SOURCE FILE [{clean_p}]:\n```\n{content}\n```")

        sections.append(
            "\nPlease generate the unified diff patch fulfilling the approved plan. Return the structured JSON."
        )

        return "\n\n".join(sections)

    async def generate_patch(
        self,
        finding: Finding,
        fix_plan: FixPlan,
        context_bundle: ContextBundle,
        source_files: Dict[str, str],
        manifest: Optional[RepositoryManifest] = None,
    ) -> PatchProposal:
        """Generate, parse, and deterministically validate a unified diff PatchProposal."""
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(finding, fix_plan, context_bundle, source_files)

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt),
        ]

        request = LLMRequest(
            messages=messages,
            task_policy=TaskPolicy.PATCH_GENERATION,
            temperature=0.0,
            json_mode=True,
        )

        response = await self.router.generate(request)
        json_str = extract_json_block(response.content)

        unified_diff = ""
        explanation = "Patch generated for finding."
        behavior_change = "Remediates identified defect."
        test_plan: List[str] = ["Run test suite"]

        try:
            data = json.loads(json_str)
            if isinstance(data, dict):
                unified_diff = data.get("unified_diff", "").strip()
                explanation = data.get("explanation", explanation)
                behavior_change = data.get("expected_behavior_change", behavior_change)
                test_plan = data.get("generated_tests_or_test_plan", test_plan)
        except Exception as exc:
            logger.warning("Failed to parse PatchProposal JSON from model response: %s", str(exc))
            unified_diff = response.content.strip()

        # Extract parsed files from diff headers
        files_modified = parse_diff_files(unified_diff)
        if not files_modified:
            files_modified = fix_plan.files_expected_to_change

        proposal = PatchProposal(
            finding_id=finding.id,
            plan_id=fix_plan.id,
            unified_diff=unified_diff,
            files_modified=files_modified,
            explanation=explanation,
            expected_behavior_change=behavior_change,
            generated_tests_or_test_plan=test_plan,
            model_metadata=response.metadata,
        )

        # Deterministic boundary validation
        validation_report = validate_patch_proposal(
            proposal=proposal,
            fix_plan=fix_plan,
            manifest=manifest,
            repo_files=set(source_files.keys()),
        )
        proposal.validation_report = validation_report

        return proposal
