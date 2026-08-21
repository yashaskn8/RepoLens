"""RepositoryIntelligenceService orchestrating deterministic ingestion, parsing, and static analysis."""

import asyncio
import logging
from typing import Dict, List, Optional
from app.analysis.adapters import OSVScannerAdapter, SemgrepAdapter, TrivyAdapter
from app.analysis.base import BaseScannerAdapter
from app.analysis.schemas import ScannerResult, ToolStatus
from app.analysis.store import EvidenceStore
from app.ingestion.manifest import build_manifest
from app.ingestion.schemas import RepositoryManifest

logger = logging.getLogger(__name__)


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
        requested_branch: Optional[str] = None,
        resolved_branch_or_ref: Optional[str] = None,
    ) -> EvidenceStore:
        """Run structural ingestion parsing and all deterministic scanner adapters in parallel.

        Returns an initialized, queryable EvidenceStore.
        One scanner failure is recorded per-tool without falsely reporting a clean result.
        """
        # 1. Deterministic AST parsing and manifest building (CPU-bound)
        manifest: RepositoryManifest = await asyncio.to_thread(
            build_manifest,
            repo_dir=repo_dir,
            repository_url=repository_url,
            commit_hash=commit_hash,
            branch=branch,
            requested_branch=requested_branch,
            resolved_branch_or_ref=resolved_branch_or_ref,
        )

        # 2. Run deterministic scanners concurrently — use return_exceptions=True
        #    so one scanner failure does not cancel the others.
        scanner_tasks = [adapter.scan(repo_dir) for adapter in self.scanner_adapters]
        raw_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)

        scanner_results: Dict[str, ScannerResult] = {}
        for adapter, result_or_exc in zip(self.scanner_adapters, raw_results):
            if isinstance(result_or_exc, BaseException):
                # Unhandled exception from a scanner — record as FAILED, not clean.
                logger.error(
                    "Scanner %s raised unhandled exception: %s",
                    adapter.tool_name,
                    result_or_exc,
                    exc_info=result_or_exc,
                )
                scanner_results[adapter.tool_name] = ScannerResult(
                    tool=adapter.tool_name,
                    status=ToolStatus.FAILED,
                    error_message=f"Unhandled exception in {adapter.tool_name}: {result_or_exc}",
                )
            else:
                scanner_results[result_or_exc.tool] = result_or_exc

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
