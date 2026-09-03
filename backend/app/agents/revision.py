"""Semantic revision agent performing bounded refinement of unconfirmed candidate findings."""

import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.agents.helpers import extract_json_block, safe_to_uuid
from app.agents.state import AnalysisState
from app.context.runtime import AnalysisRuntimeContext
from app.llm.budgets import REPOSITORY_ANALYSIS_BUDGET
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, ModelCapability, TaskPolicy
from app.llm.workflow_contracts import FINDINGS_OUTPUT_SCHEMA, lineage_for_scan
from app.schemas.enums import FindingStatus, Severity, VerificationVerdict
from app.schemas.finding import Finding
from app.security.redaction import redact_secrets
from langgraph.runtime import Runtime

logger = logging.getLogger(__name__)

_REVISION_SYSTEM_PROMPT = """You are RepoLens Semantic Revision Agent.
Your responsibility is to refine candidate security and quality findings that received a POSSIBLE verdict from the independent verifier.
Carefully incorporate the verifier's feedback and clarify the semantic reasoning and defect claim based strictly on the provided evidence.
Do not fabricate facts, files, or line numbers. Maintain rigorous evidence grounding."""


async def run_revision_agent(
    state: AnalysisState,
    runtime: Optional[Runtime[AnalysisRuntimeContext]] = None,
) -> Dict[str, Any]:
    """Perform one bounded semantic revision pass for findings targeted by the verifier.

    Guarantees:
    - Hard execution guard: executes at most once (revision_count < 1).
    - Only refines candidate findings explicitly targeted in revision_target_ids.
    - Preserves original finding IDs and attested evidence anchors.
    - Routes through central LLMRouter using provider-neutral DEEP_REASONING capability.
    - Never mutates or appends to candidate_findings.
    - Fails closed on provider or parsing errors.
    """
    current_revision_count = state.get("revision_count", 0)
    if current_revision_count >= 1:
        logger.warning("Revision guard tripped: revision already executed (%d >= 1)", current_revision_count)
        return {
            "revision_candidates": [],
            "revision_count": current_revision_count,
            "completed_nodes": ["revise"],
            "status": "REVISED",
        }

    target_ids = set(state.get("revision_target_ids", []))
    if not target_ids:
        return {
            "revision_candidates": [],
            "revision_count": current_revision_count + 1,
            "completed_nodes": ["revise"],
            "status": "REVISED",
        }

    all_candidates = state.get("candidate_findings", [])
    candidate_map = {str(c.id): c for c in all_candidates}
    rejection_map = {str(rf.get("finding_id")): rf for rf in state.get("rejected_findings", [])}

    scan_id = safe_to_uuid(state.get("scan_id", ""))
    router = get_llm_router()
    model_executions = []
    errors = []
    revised_findings: List[Finding] = []

    for target_id in sorted(target_ids):
        original = candidate_map.get(target_id)
        if not original:
            continue

        rejection = rejection_map.get(target_id, {})
        verifier_reason = rejection.get("reason", "Semantic claim requires clarification.")
        evidence_summary = []
        for ev in original.evidences:
            evidence_summary.append(
                f"- File: {ev.file_path} (Lines {ev.start_line}-{ev.end_line}):\n```\n{ev.code_snippet}\n```"
            )

        user_prompt = (
            f"Please revise the following candidate finding that received a POSSIBLE verifier verdict:\n\n"
            f"Title: {original.title}\n"
            f"Category: {original.category}\n"
            f"Original Description: {original.description}\n"
            f"Verifier Feedback / Defect: {verifier_reason}\n\n"
            f"Attested Evidence:\n" + "\n".join(evidence_summary) + "\n\n"
            "Provide a revised, evidence-grounded title and description addressing the feedback strictly within the attested evidence."
        )

        try:
            request = LLMRequest(
                messages=[
                    LLMMessage(role="system", content=_REVISION_SYSTEM_PROMPT),
                    LLMMessage(role="user", content=user_prompt),
                ],
                task_policy=TaskPolicy.BUG_REASONING,
                capability=ModelCapability.DEEP_REASONING,
                output_schema=FINDINGS_OUTPUT_SCHEMA,
                temperature=0.1,
                max_tokens=2000,
                confidence_threshold=0.75,
                budget=REPOSITORY_ANALYSIS_BUDGET,
                lineage=lineage_for_scan(
                    str(scan_id),
                    prompt_template_version="revision-agent/1.0",
                    output_schema_version="finding-revision/1.0",
                    evidence=[{"finding_id": target_id, "verifier_feedback": verifier_reason}],
                ),
            )
            response = await router.generate(request)
            model_executions.append(response.metadata)

            parsed_data = json.loads(extract_json_block(response.content))
            raw_findings = parsed_data.get("findings", [])
            if raw_findings:
                rf = raw_findings[0]
                revised_finding = Finding(
                    id=original.id,  # Preserve identity
                    scan_id=original.scan_id,
                    title=rf.get("title") or original.title,
                    description=rf.get("description") or original.description,
                    category=original.category,
                    severity=Severity(rf["severity"]) if rf.get("severity") in Severity._value2member_map_ else original.severity,
                    status=FindingStatus.OPEN,
                    source_tool="revision_agent",
                    rule_id=original.rule_id,
                    evidences=original.evidences,  # Retain attested repository locators
                    mitigation_guidance=rf.get("mitigation_guidance") or original.mitigation_guidance,
                )
                revised_findings.append(revised_finding)
            else:
                revised_findings.append(original)
        except Exception as exc:
            safe_err = redact_secrets(str(exc))[:2048]
            errors.append(f"Revision error for finding {target_id}: {safe_err}")
            revised_findings.append(original)

    return {
        "revision_candidates": revised_findings,
        "revision_count": current_revision_count + 1,
        "completed_nodes": ["revise"],
        "model_executions": model_executions,
        "errors": errors,
        "status": "REVISED",
    }
