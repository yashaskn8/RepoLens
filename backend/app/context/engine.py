"""Evidence-grounded Context Engine building bounded ContextBundles for specialist agents."""

from typing import Any, Dict, List, Optional, Set

from app.analysis.schemas import StaticFinding
from app.analysis.store import EvidenceStore
from app.context.schemas import ContextBundle
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import GraphEdge, RouteContractMatch
from app.retrieval.schemas import RetrievalQuery, RetrievalResult
from app.retrieval.service import RetrievalService


class ContextEngine:
    """Canonical Context Engine coordinating EvidenceStore, RepositoryGraph, and RetrievalService.
    
    Produces targeted, bounded ContextBundles for specialist reasoning and independent verification.
    """

    def __init__(
        self,
        evidence_store: EvidenceStore,
        repository_graph: Optional[RepositoryGraph] = None,
        retrieval_service: Optional[RetrievalService] = None,
    ):
        self.evidence_store = evidence_store
        self.repository_graph = repository_graph
        self.retrieval_service = retrieval_service

    async def build_context_bundle(
        self,
        scan_id: str,
        query: str,
        analysis_intent: str = "general",
        context_budget: int = 4000,
        max_chunks: int = 5,
    ) -> ContextBundle:
        """Assemble a bounded, evidence-grounded ContextBundle for a specific query and intent."""
        relevant_chunks: List[RetrievalResult] = []
        retrieval_scores: Dict[str, float] = {}

        # 1. Retrieve code chunks via RetrievalService
        if self.retrieval_service:
            retrieval_query = RetrievalQuery(
                query=query,
                top_k=max_chunks,
                use_reranker=True,
            )
            raw_results = await self.retrieval_service.retrieve(retrieval_query)
            
            # Enforce context budget (approx 4 chars per token)
            current_chars = 0
            max_chars = context_budget * 4

            for res in raw_results:
                chunk_len = len(res.chunk.content)
                if current_chars + chunk_len > max_chars and relevant_chunks:
                    break
                relevant_chunks.append(res)
                retrieval_scores[res.chunk_id] = res.score
                current_chars += chunk_len

        # Gather target files and symbol names from retrieved chunks
        target_files: Set[str] = set()
        target_symbols: Set[str] = set()
        for res in relevant_chunks:
            target_files.add(res.chunk.file_path)
            target_symbols.add(res.chunk.symbol)

        # 2. Extract relevant graph relationships
        graph_relationships: List[GraphEdge] = []
        if self.repository_graph:
            # Collect edges touching any of our target files
            all_edges = self.repository_graph.get_edges()
            for edge in all_edges:
                src_node = self.repository_graph.get_node(edge.source)
                tgt_node = self.repository_graph.get_node(edge.target)
                src_file = src_node.file_path if src_node else None
                tgt_file = tgt_node.file_path if tgt_node else None

                if (src_file and src_file in target_files) or (tgt_file and tgt_file in target_files):
                    graph_relationships.append(edge)
                    if len(graph_relationships) >= 20:  # Bound graph edges
                        break

        # 3. Extract relevant routes and contracts
        routes_and_contracts: List[RouteContractMatch] = []
        if self.repository_graph:
            report = self.repository_graph.evaluate_route_contracts()
            for match in report.matches:
                # Include if match involves any retrieved file
                if match.frontend_file in target_files:
                    routes_and_contracts.append(match)
                elif any(rf in match.matched_backend_paths for rf in target_files):
                    routes_and_contracts.append(match)
                if len(routes_and_contracts) >= 10:
                    break

        # 4. Extract relevant static scanner findings
        static_findings: List[StaticFinding] = []
        for file_path in target_files:
            file_findings = self.evidence_store.get_findings(file_path=file_path)
            static_findings.extend(file_findings)
            if len(static_findings) >= 15:
                break

        # 5. Estimate token usage
        total_text_len = sum(len(r.chunk.content) for r in relevant_chunks)
        total_text_len += sum(len(str(f.description)) for f in static_findings)
        estimated_tokens = max(1, total_text_len // 4)

        provenance = {
            "scan_id": scan_id,
            "query": query,
            "analysis_intent": analysis_intent,
            "total_chunks": len(relevant_chunks),
            "total_graph_edges": len(graph_relationships),
            "total_contracts": len(routes_and_contracts),
            "total_static_findings": len(static_findings),
            "context_budget": context_budget,
            "estimated_tokens": estimated_tokens,
        }

        return ContextBundle(
            scan_id=scan_id,
            query=query,
            analysis_intent=analysis_intent,
            relevant_chunks=relevant_chunks,
            graph_relationships=graph_relationships,
            routes_and_contracts=routes_and_contracts,
            static_findings=static_findings,
            provenance=provenance,
            retrieval_scores=retrieval_scores,
            estimated_tokens=estimated_tokens,
        )
