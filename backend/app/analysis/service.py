"""RepositoryIntelligenceService orchestrating deterministic ingestion, parsing, and static analysis."""

import asyncio
from typing import Dict, List, Optional
from app.analysis.adapters import OSVScannerAdapter, SemgrepAdapter, TrivyAdapter
from app.analysis.base import BaseScannerAdapter
from app.analysis.schemas import ScannerResult
from app.analysis.store import EvidenceStore
from app.ingestion.manifest import build_manifest
from app.ingestion.schemas import RepositoryManifest


class RepositoryIntelligenceService:
    """Orchestrates deterministic AST parsing and security scanners to produce unified EvidenceStore."""

    def __init__(self, scanner_adapters: Optional[List[BaseScannerAdapter]] = None):
        self.scanner_adapters: List[BaseScannerAdapter] = scanner_adapters or [
            SemgrepAdapter(),
            TrivyAdapter(),
            OSVScannerAdapter(),
        ]

    async def analyze_repository(
        self,
        repo_dir: str,
        repository_url: str,
        commit_hash: str,
        branch: Optional[str] = None,
    ) -> EvidenceStore:
        """Run structural ingestion parsing and all deterministic scanner adapters in parallel.
        
        Returns an initialized, queryable EvidenceStore.
        """
        # 1. Deterministic AST parsing and manifest building (CPU-bound)
        manifest: RepositoryManifest = await asyncio.to_thread(
            build_manifest,
            repo_dir=repo_dir,
            repository_url=repository_url,
            commit_hash=commit_hash,
            branch=branch,
        )

        # 2. Run deterministic scanners concurrently
        scanner_tasks = [adapter.scan(repo_dir) for adapter in self.scanner_adapters]
        results_list = await asyncio.gather(*scanner_tasks, return_exceptions=False)

        scanner_results: Dict[str, ScannerResult] = {
            res.tool: res for res in results_list
        }

        # 3. Assemble unified EvidenceStore
        return EvidenceStore(manifest=manifest, scanner_results=scanner_results)


# Default singleton instance
_default_intelligence_service: Optional[RepositoryIntelligenceService] = None


def get_intelligence_service() -> RepositoryIntelligenceService:
    """Return singleton RepositoryIntelligenceService instance."""
    global _default_intelligence_service
    if _default_intelligence_service is None:
        _default_intelligence_service = RepositoryIntelligenceService()
    return _default_intelligence_service
