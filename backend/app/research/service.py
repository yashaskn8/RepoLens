"""High-level ResearchService coordinating framework investigations and upgrade intelligence."""

import asyncio
from typing import List, Optional
from uuid import UUID

from app.ingestion.schemas import RepositoryManifest
from app.research.agent import ResearchAgent
from app.research.schemas import ResearchQuery, ResearchResult
from app.schemas.finding import Finding


class ResearchService:
    """Canonical service managing evidence-grounded research and framework upgrade investigations."""

    def __init__(self, agent: Optional[ResearchAgent] = None):
        self.agent = agent or ResearchAgent()

    def _resolve_framework_version(
        self,
        framework_name: str,
        manifest: Optional[RepositoryManifest] = None,
    ) -> Optional[str]:
        """Look up detected framework version from repository manifest."""
        if not manifest:
            return None
        fw_clean = framework_name.lower()
        for fw in manifest.frameworks:
            if fw.name.lower() == fw_clean or fw_clean in fw.name.lower():
                return fw.version
        return None

    async def research_finding(
        self,
        finding: Finding,
        manifest: Optional[RepositoryManifest] = None,
        code_snippet: Optional[str] = None,
    ) -> ResearchResult:
        """Execute targeted technical research for a verified repository finding."""
        evidence = finding.evidences[0] if finding.evidences else None
        snippet = code_snippet or (evidence.code_snippet if evidence else None)
        file_path = evidence.file_path if evidence else None

        # Infer target framework from category or title
        target_framework = "General"
        if manifest and manifest.frameworks:
            target_framework = manifest.frameworks[0].name
        if "fastapi" in finding.title.lower() or (file_path and "routes" in file_path):
            target_framework = "FastAPI"
        elif "react" in finding.title.lower() or (file_path and (".tsx" in file_path or ".jsx" in file_path)):
            target_framework = "React"
        elif "express" in finding.title.lower():
            target_framework = "Express"
        elif "pydantic" in finding.title.lower():
            target_framework = "Pydantic"

        detected_ver = self._resolve_framework_version(target_framework, manifest)

        query = ResearchQuery(
            finding_id=finding.id,
            target_framework=target_framework,
            detected_version=detected_ver,
            issue_summary=f"{finding.title}: {finding.description[:200]}",
            affected_file=file_path,
            code_snippet=snippet,
            minimal_context=f"Severity: {finding.severity.value}, Rule: {finding.rule_id or 'N/A'}",
        )

        return await self.agent.research(query)

    async def research_framework_upgrade(
        self,
        framework_name: str,
        detected_version: Optional[str] = None,
        usage_context: Optional[str] = None,
    ) -> ResearchResult:
        """Execute targeted investigation for framework upgrade and migration paths."""
        query = ResearchQuery(
            target_framework=framework_name,
            detected_version=detected_version,
            issue_summary=f"Investigate upgrade migration paths, breaking changes, and deprecations for {framework_name} {detected_version or ''}",
            minimal_context=usage_context,
        )
        return await self.agent.research(query)

    async def batch_research_findings(
        self,
        findings: List[Finding],
        manifest: Optional[RepositoryManifest] = None,
        max_concurrent: int = 3,
    ) -> List[ResearchResult]:
        """Execute bounded concurrent research across multiple verified findings."""
        sem = asyncio.Semaphore(max_concurrent)

        async def _bounded_research(f: Finding) -> ResearchResult:
            async with sem:
                return await self.research_finding(f, manifest=manifest)

        tasks = [_bounded_research(f) for f in findings]
        return await asyncio.gather(*tasks)
