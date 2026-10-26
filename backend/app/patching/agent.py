"""PatchGeneratorAgent producing evidence-constrained unified diffs."""

import json
from typing import Dict, Optional

from app.agents.helpers import extract_json_block
from app.context.schemas import ContextBundle
from app.ingestion.schemas import RepositoryManifest
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, ModelCapability, TaskPolicy
from app.llm.workflow_contracts import OBJECT_OUTPUT_SCHEMA, lineage_for_finding
from app.patching.schemas import PatchProposal
from app.patching.validator import parse_diff_files, validate_patch_proposal
from app.planning.schemas import FixPlan
from app.schemas.finding import Finding
from app.schemas.enums import VerificationVerdict

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
        if finding.verification_verdict != VerificationVerdict.CONFIRMED:
            raise ValueError("Patch generation requires a confirmed, verified finding.")
        if fix_plan.finding_id != finding.id:
            raise ValueError("Patch generation rejected: plan belongs to a different finding.")
        if fix_plan.validation_report is not None and not fix_plan.validation_report.is_valid:
            raise ValueError("Patch generation rejected: plan failed deterministic validation.")
        if set(source_files) != {path.replace("\\", "/") for path in fix_plan.files_expected_to_change}:
            raise ValueError("Patch generation rejected: approved source evidence is incomplete.")
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(finding, fix_plan, context_bundle, source_files)

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt),
        ]

        request = LLMRequest(
            messages=messages,
            task_policy=TaskPolicy.PATCH_GENERATION,
            capability=ModelCapability.PATCH_GENERATION,
            output_schema=OBJECT_OUTPUT_SCHEMA,
            lineage=lineage_for_finding(
                str(finding.id),
                prompt_template_version="patch-generator/1.0",
                output_schema_version="patch-proposal/1.0",
                evidence={"finding_id": str(finding.id), "fix_plan_id": str(fix_plan.id)},
            ),
            temperature=0.0,
            json_mode=True,
        )

        response = await self.router.generate(request)
        json_str = extract_json_block(response.content)

        try:
            data = json.loads(json_str)
            if not isinstance(data, dict):
                raise ValueError("Invalid patch payload")
            required = (
                "unified_diff",
                "explanation",
                "expected_behavior_change",
                "generated_tests_or_test_plan",
            )
            if any(key not in data for key in required):
                raise ValueError("Missing required patch fields")
            if any(
                not isinstance(data[key], str) or not data[key].strip()
                for key in required[:3]
            ):
                raise ValueError("Invalid patch text fields")
            test_plan = data["generated_tests_or_test_plan"]
            if not isinstance(test_plan, list) or any(
                not isinstance(item, str) or not item.strip() for item in test_plan
            ):
                raise ValueError("Invalid patch validation plan")
            unified_diff = data["unified_diff"].strip()
            files_modified = parse_diff_files(unified_diff)
            if not files_modified:
                raise ValueError("Patch does not name a modified repository file")

            proposal = PatchProposal(
                finding_id=finding.id,
                plan_id=fix_plan.id,
                unified_diff=unified_diff,
                files_modified=files_modified,
                explanation=data["explanation"],
                expected_behavior_change=data["expected_behavior_change"],
                generated_tests_or_test_plan=test_plan,
                model_metadata=response.metadata,
            )
        except (TypeError, ValueError):
            raise ValueError("Model returned an invalid PatchProposal; no patch was created.") from None

        # Deterministic boundary validation
        validation_report = validate_patch_proposal(
            proposal=proposal,
            fix_plan=fix_plan,
            manifest=manifest,
            repo_files=set(source_files.keys()),
        )
        proposal.validation_report = validation_report

        return proposal
