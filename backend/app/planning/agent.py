"""FixPlannerAgent generating structured remediation plans for verified findings."""

import json
from typing import Optional

from app.agents.helpers import extract_json_block
from app.context.schemas import ContextBundle
from app.graph.repository_graph import RepositoryGraph
from app.ingestion.schemas import RepositoryManifest
from app.llm.router import get_llm_router
from app.llm.types import LLMMessage, LLMRequest, ModelCapability, TaskPolicy
from app.llm.workflow_contracts import OBJECT_OUTPUT_SCHEMA, lineage_for_finding
from app.planning.schemas import FixPlan
from app.planning.validator import validate_fix_plan
from app.research.schemas import ResearchResult
from app.schemas.enums import VerificationVerdict
from app.schemas.finding import Finding

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
        # Both the service and direct agent callers must fail closed.
        if finding.verification_verdict != VerificationVerdict.CONFIRMED:
            raise ValueError("Only verified, confirmed findings may receive a remediation plan.")

        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(finding, context_bundle, repository_graph, research_result)

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt),
        ]

        request = LLMRequest(
            messages=messages,
            task_policy=TaskPolicy.FIX_PLANNING,
            capability=ModelCapability.DEEP_REASONING,
            output_schema=OBJECT_OUTPUT_SCHEMA,
            lineage=lineage_for_finding(
                str(finding.id),
                prompt_template_version="fix-planner/1.0",
                output_schema_version="fix-plan/1.0",
                evidence={
                    "finding_id": str(finding.id),
                    "verification_verdict": str(finding.verification_verdict),
                    "context_chunks": [
                        {
                            "file_path": chunk.chunk.file_path,
                            "start_line": chunk.chunk.start_line,
                            "end_line": chunk.chunk.end_line,
                        }
                        for chunk in context_bundle.relevant_chunks
                    ],
                },
            ),
            temperature=0.0,
            json_mode=True,
        )

        response = await self.router.generate(request)
        json_str = extract_json_block(response.content)

        # A malformed or partial model response is NOT a remediation plan.
        # Do not silently fill required fields with model-independent defaults.
        try:
            data = json.loads(json_str)
            required = {
                "root_cause",
                "objective",
                "files_expected_to_change",
                "ordered_changes",
                "validation_plan",
            }
            if not isinstance(data, dict) or not required.issubset(data):
                raise ValueError("Missing required FixPlan fields")
            if any(
                not isinstance(data[field], str) or not data[field].strip()
                for field in ("root_cause", "objective")
            ):
                raise ValueError("Empty FixPlan explanation")
            # Never accept model-supplied record identity, approval state,
            # validation verdict or execution telemetry as authority.
            payload = {
                key: value
                for key, value in data.items()
                if key in FixPlan.model_fields
                and key not in {
                    "id",
                    "finding_id",
                    "validation_report",
                    "model_metadata",
                    "created_at",
                }
            }
            payload["finding_id"] = finding.id
            payload["model_metadata"] = response.metadata
            plan_instance = FixPlan.model_validate(payload)
        except (ValueError, TypeError):
            # Do not leak potentially sensitive model output into API errors.
            raise ValueError("Model returned an invalid FixPlan; no remediation plan was created.") from None

        validation_report = validate_fix_plan(
            plan=plan_instance,
            finding=finding,
            manifest=manifest,
            context_bundle=context_bundle,
            repository_graph=repository_graph,
        )
        plan_instance.validation_report = validation_report

        return plan_instance
