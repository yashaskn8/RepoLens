"""FixPlanningService orchestrating targeted remediation planning across findings."""

import asyncio
from typing import List, Optional

from app.context.engine import ContextEngine
from app.graph.repository_graph import RepositoryGraph
from app.ingestion.schemas import RepositoryManifest
from app.planning.agent import FixPlannerAgent
from app.planning.schemas import FixPlan
from app.research.schemas import ResearchResult
from app.schemas.finding import Finding


class FixPlanningService:
    """Canonical service coordinating evidence retrieval and fix planning for confirmed findings."""

    def __init__(self, agent: Optional[FixPlannerAgent] = None):
        self.agent = agent or FixPlannerAgent()

    async def create_fix_plan(
        self,
        finding: Finding,
        context_engine: ContextEngine,
        repository_graph: Optional[RepositoryGraph] = None,
        research_result: Optional[ResearchResult] = None,
        manifest: Optional[RepositoryManifest] = None,
    ) -> FixPlan:
        """Retrieve targeted context and generate a validated FixPlan for a finding."""
        evidence = finding.evidences[0] if finding.evidences else None
        file_path = evidence.file_path if evidence else "main"

        # 1. Retrieve independent ContextBundle for the finding
        query = f"{finding.title} {finding.description[:100]} in {file_path}"
        context_bundle = await context_engine.build_context_bundle(
            scan_id=str(finding.scan_id),
            query=query,
            analysis_intent="fix_planning",
            context_budget=2500,
            max_chunks=4,
        )

        # 2. Generate and validate plan via FixPlannerAgent
        return await self.agent.plan(
            finding=finding,
            context_bundle=context_bundle,
            repository_graph=repository_graph,
            research_result=research_result,
            manifest=manifest,
        )

    async def batch_plan_fixes(
        self,
        findings: List[Finding],
        context_engine: ContextEngine,
        repository_graph: Optional[RepositoryGraph] = None,
        manifest: Optional[RepositoryManifest] = None,
        max_concurrent: int = 3,
    ) -> List[FixPlan]:
        """Execute bounded concurrent fix planning across multiple confirmed findings."""
        sem = asyncio.Semaphore(max_concurrent)

        async def _bounded_plan(f: Finding) -> FixPlan:
            async with sem:
                return await self.create_fix_plan(
                    finding=f,
                    context_engine=context_engine,
                    repository_graph=repository_graph,
                    manifest=manifest,
                )

        tasks = [_bounded_plan(f) for f in findings]
        return await asyncio.gather(*tasks)
