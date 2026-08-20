"""FixPlannerAgent generating structured remediation plans for verified findings."""

import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.agents.helpers import extract_json_block
from app.context.schemas import ContextBundle
from app.graph.repository_graph import RepositoryGraph
from app.ingestion.schemas import RepositoryManifest
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, TaskPolicy
from app.planning.schemas import (
    FixPlan,
    FixScope,
    OrderedChangeStep,
    PlanValidationReport,
    PlanValidationStatus,
)
from app.planning.validator import validate_fix_plan
from app.research.schemas import ResearchResult
from app.schemas.enums import VerificationVerdict
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)


class FixPlannerAgent:
    """Specialized AI agent generating structured, minimal-scope remediation plans for confirmed findings.
    
    Guarantees:
    - Input must be a CONFIRMED / non-rejected finding.
    - Focuses strictly on the SMALLEST COHERENT FIX.
    - Does NOT generate raw code patches or rewrites.
    - Validates plan against repository files, symbols, and rejection rules.
    """

    def __init__(self, router=None):
        self.router = router or get_llm_router()

    def _build_system_prompt(self) -> str:
        return (
            "You are the RepoLens Root-Cause Fix Planner AI Agent.\n"
            "Your objective is to design a structured, rigorous, and minimal-scope remediation plan for a verified finding.\n\n"
            "STRICT RULES:\n"
            "1. Plan the SMALLEST COHERENT FIX that directly addresses the root cause without touching unrelated architecture.\n"
            "2. Only reference files and symbols that actually exist in the provided repository context.\n"
            "3. DO NOT generate code patches, diffs, or complete rewrites. Describe changes conceptually and step-by-step.\n"
            "4. NEVER create alias routes, proxy duplicates, or compatibility shims to hide a cross-layer contract mismatch. "
            "Fix the mismatching endpoint or client call directly.\n"
            "5. Clearly identify affected interfaces, regression risks, and concrete automated validation steps.\n"
            "6. Output MUST be valid JSON conforming exactly to the required schema.\n\n"
            "OUTPUT JSON SCHEMA:\n"
            "{\n"
            '  "root_cause": "Detailed technical analysis of the defect root cause",\n'
            '  "objective": "Concise remediation goal",\n'
            '  "files_expected_to_change": ["app/main.py"],\n'
            '  "symbols_expected_to_change": ["startup_handler"],\n'
            '  "ordered_changes": [\n'
            "    {\n"
            '      "step_number": 1,\n'
            '      "target_file": "app/main.py",\n'
            '      "target_symbol": "startup_handler",\n'
            '      "description": "Refactor the on_event startup logic into an asynccontextmanager lifespan handler",\n'
            '      "rationale": "Directly resolves deprecation while preserving startup initialization behavior"\n'
            "    }\n"
            "  ],\n"
            '  "interfaces_affected": ["FastAPI app initialization lifespan"],\n'
            '  "migration_config_impact": null,\n'
            '  "regression_risks": ["Async connection pool failure if lifespan context does not yield properly"],\n'
            '  "validation_plan": ["Run pytest tests/test_lifespan.py", "Verify clean startup and shutdown logs"],\n'
            '  "estimated_scope": "file",\n'
            '  "assumptions": ["FastAPI version supports lifespan context managers"]\n'
            "}"
        )

    def _build_user_prompt(
        self,
        finding: Finding,
        context_bundle: ContextBundle,
        repository_graph: Optional[RepositoryGraph] = None,
        research_result: Optional[ResearchResult] = None,
    ) -> str:
        sections = [
            f"FINDING TITLE: {finding.title}",
            f"SEVERITY: {finding.severity.value}",
            f"CATEGORY: {finding.category or 'general'}",
            f"DESCRIPTION: {finding.description}",
        ]

        if finding.evidences:
            ev = finding.evidences[0]
            sections.append(f"PRIMARY EVIDENCE FILE: {ev.file_path} (Lines {ev.start_line}-{ev.end_line})")
            if ev.code_snippet:
                sections.append(f"EVIDENCE SNIPPET:\n{ev.code_snippet}")

        # Add ContextBundle Chunks
        if context_bundle.relevant_chunks:
            chunk_texts = [
                f"--- File: {c.chunk.file_path} | Symbol: {c.chunk.symbol} (Lines {c.chunk.start_line}-{c.chunk.end_line}) ---\n{c.chunk.content}"
                for c in context_bundle.relevant_chunks[:3]
            ]
            sections.append("RELEVANT CODE CONTEXT:\n" + "\n\n".join(chunk_texts))

        # Add Graph Relationships
        if context_bundle.graph_relationships:
            edge_texts = [
                f"{e.source} --({e.kind.value})--> {e.target}"
                for e in context_bundle.graph_relationships[:5]
            ]
            sections.append("STRUCTURAL GRAPH RELATIONSHIPS:\n" + "\n".join(edge_texts))

        # Add Research Guidance if available
        if research_result:
            sections.append(
                f"TECHNICAL RESEARCH & UPGRADE GUIDANCE ({research_result.target_framework}):\n"
                f"- Recommended Version: {research_result.recommended_version or 'N/A'}\n"
                f"- Migration Summary: {research_result.migration_summary}\n"
                f"- Repository Impact: {research_result.repository_impact}"
            )

        sections.append(
            "\nPlease formulate the structured FixPlan. Adhere strictly to the JSON schema and planning rules."
        )

        return "\n\n".join(sections)

    async def plan(
        self,
        finding: Finding,
        context_bundle: ContextBundle,
        repository_graph: Optional[RepositoryGraph] = None,
        research_result: Optional[ResearchResult] = None,
        manifest: Optional[RepositoryManifest] = None,
    ) -> FixPlan:
        """Generate and validate a structured FixPlan for a verified finding."""
        # Guard: Check if finding was rejected by verifier
        if finding.verification_verdict == VerificationVerdict.REJECTED:
            validation_rep = PlanValidationReport(
                status=PlanValidationStatus.REJECTED,
                is_valid=False,
                rejection_reasons=[f"Cannot plan remediation for REJECTED finding '{finding.id}'."],
            )
            return FixPlan(
                finding_id=finding.id,
                root_cause="Finding rejected by independent verification.",
                objective="N/A (Rejected finding)",
                files_expected_to_change=[finding.evidences[0].file_path] if finding.evidences else ["unknown"],
                ordered_changes=[],
                validation_plan=["Verification rejection"],
                validation_report=validation_rep,
            )

        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(finding, context_bundle, repository_graph, research_result)

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt),
        ]

        request = LLMRequest(
            messages=messages,
            task_policy=TaskPolicy.FIX_PLANNING,
            temperature=0.0,
            json_mode=True,
        )

        response = await self.router.generate(request)
        json_str = extract_json_block(response.content)

        root_cause = "Analysis in progress"
        objective = f"Remediate {finding.title}"
        files_expected = [finding.evidences[0].file_path] if finding.evidences else ["app/main.py"]
        symbols_expected: List[str] = []
        ordered_changes: List[OrderedChangeStep] = []
        interfaces_affected: List[str] = []
        migration_impact: Optional[str] = None
        regression_risks: List[str] = []
        validation_plan: List[str] = ["Run existing test suite"]
        scope = FixScope.FILE
        assumptions: List[str] = []

        try:
            data = json.loads(json_str)
            if isinstance(data, dict):
                root_cause = data.get("root_cause", root_cause)
                objective = data.get("objective", objective)
                files_expected = data.get("files_expected_to_change", files_expected)
                symbols_expected = data.get("symbols_expected_to_change", symbols_expected)
                interfaces_affected = data.get("interfaces_affected", interfaces_affected)
                migration_impact = data.get("migration_config_impact")
                regression_risks = data.get("regression_risks", regression_risks)
                validation_plan = data.get("validation_plan", validation_plan)
                assumptions = data.get("assumptions", assumptions)

                raw_scope = str(data.get("estimated_scope", "file")).lower()
                scope = FixScope(raw_scope) if raw_scope in FixScope._value2member_map_ else FixScope.FILE

                for idx, step_data in enumerate(data.get("ordered_changes", []), start=1):
                    if isinstance(step_data, dict):
                        ordered_changes.append(
                            OrderedChangeStep(
                                step_number=step_data.get("step_number", idx),
                                target_file=step_data.get("target_file", files_expected[0] if files_expected else "unknown"),
                                target_symbol=step_data.get("target_symbol"),
                                description=step_data.get("description", "Apply targeted remediation"),
                                rationale=step_data.get("rationale", "Resolves root cause"),
                            )
                        )
        except Exception as exc:
            logger.warning("Failed to parse FixPlan JSON from model response: %s", str(exc))
            ordered_changes.append(
                OrderedChangeStep(
                    step_number=1,
                    target_file=files_expected[0] if files_expected else "unknown",
                    description=response.content[:200],
                    rationale="Fallback parsed description",
                )
            )

        if not ordered_changes:
            ordered_changes.append(
                OrderedChangeStep(
                    step_number=1,
                    target_file=files_expected[0] if files_expected else "unknown",
                    description=f"Resolve {finding.title}",
                    rationale="Direct root cause fix",
                )
            )

        plan_instance = FixPlan(
            finding_id=finding.id,
            root_cause=root_cause,
            objective=objective,
            files_expected_to_change=files_expected,
            symbols_expected_to_change=symbols_expected,
            ordered_changes=ordered_changes,
            interfaces_affected=interfaces_affected,
            migration_config_impact=migration_impact,
            regression_risks=regression_risks,
            validation_plan=validation_plan,
            estimated_scope=scope,
            assumptions=assumptions,
            model_metadata=response.metadata,
        )

        # Execute deterministic validation
        validation_report = validate_fix_plan(
            plan=plan_instance,
            finding=finding,
            manifest=manifest,
            context_bundle=context_bundle,
            repository_graph=repository_graph,
        )
        plan_instance.validation_report = validation_report

        return plan_instance
