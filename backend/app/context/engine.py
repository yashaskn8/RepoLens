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
        use_neural_reranker: bool = False,
        required_chunk_ids: Optional[List[str]] = None,
    ) -> ContextBundle:
        """Assemble a bounded, evidence-grounded ContextBundle for a specific query and intent."""
        relevant_chunks: List[RetrievalResult] = []
        retrieval_scores: Dict[str, float] = {}

        # 1. Retrieve code chunks via RetrievalService
        if self.retrieval_service:
            retrieval_query = RetrievalQuery(
                query=query,
                top_k=max_chunks,
                use_reranker=use_neural_reranker,
                analysis_intent=analysis_intent,
            )
            raw_results = await self.retrieval_service.retrieve(retrieval_query)
            candidate_verification = analysis_intent == "verification" or bool(required_chunk_ids) and analysis_intent in {
                "verification", "bug", "security", "architecture", "integration"
            }
            if not raw_results and not candidate_verification:
                # Exact/lexical/dense retrieval may legitimately yield no
                # match (or the free embedding provider may be unavailable).
                # A deterministic structural sample preserves scan coverage
                # without consuming another model call or fabricating context.
                fallback_chunks = sorted(
                    self.retrieval_service.chunks_by_id.values(),
                    key=lambda chunk: (chunk.file_path, chunk.start_line, chunk.chunk_id),
                )[:max_chunks]
                raw_results = [
                    RetrievalResult(
                        chunk_id=chunk.chunk_id,
                        score=0.0,
                        source_channels=[],
                        chunk=chunk,
                        provenance={
                            "commit_sha": chunk.commit_sha,
                            "file_path": chunk.file_path,
                            "symbol": chunk.symbol,
                            "symbol_kind": chunk.symbol_kind.value,
                            "start_line": chunk.start_line,
                            "end_line": chunk.end_line,
                            "content_hash": chunk.content_hash,
                            "selection": "deterministic_structural_fallback",
                        },
                    )
                    for chunk in fallback_chunks
                ]

            # Hypothesis anchors are deterministic requirements, not ranking
            # suggestions. Put them first so a weak lexical score cannot evict
            # the source fact that created the candidate.
            required_results: List[RetrievalResult] = []
            for chunk_id in dict.fromkeys(required_chunk_ids or []):
                chunk = self.retrieval_service.chunks_by_id.get(chunk_id)
                if chunk is None and chunk_id.startswith("chunk:"):
                    chunk = self.retrieval_service.chunks_by_id.get(chunk_id[len("chunk:"):])
                if chunk is None:
                    continue
                required_results.append(
                    RetrievalResult(
                        chunk_id=chunk.chunk_id,
                        score=1.0,
                        source_channels=[],
                        chunk=chunk,
                        provenance={
                            "commit_sha": chunk.commit_sha,
                            "file_path": chunk.file_path,
                            "symbol": chunk.symbol,
                            "symbol_kind": chunk.symbol_kind.value,
                            "start_line": chunk.start_line,
                            "end_line": chunk.end_line,
                            "content_hash": chunk.content_hash,
                            "selection": "deterministic_candidate_anchor",
                        },
                    )
                )
            required_ids = {result.chunk_id for result in required_results}
            raw_results = required_results + [
                result for result in raw_results if result.chunk_id not in required_ids
            ]
            
            # Enforce context budget (approx 4 chars per token)
            current_chars = 0
            max_chars = context_budget * 4

            for res in raw_results:
                if len(relevant_chunks) >= max_chunks:
                    break
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
            ranked_matches: List[tuple[int, int, str, RouteContractMatch]] = []
            for match in report.matches:
                backend_files = {
                    node.file_path
                    for route_id in match.matched_route_ids
                    if (node := self.repository_graph.get_node(route_id)) is not None
                    and node.file_path
                }
                touches_retrieved_code = (
                    match.frontend_file in target_files
                    or bool(backend_files.intersection(target_files))
                )
                is_mismatch = str(getattr(match.status, "value", match.status)) != "MATCHED"
                # Integration analysis must see every deterministic mismatch
                # before spending context on already-matched or merely nearby routes.
                if analysis_intent != "integration" and not touches_retrieved_code:
                    continue
                ranked_matches.append(
                    (
                        0 if is_mismatch else 1,
                        0 if touches_retrieved_code else 1,
                        match.frontend_request_id,
                        match,
                    )
                )
            for _, _, _, match in sorted(ranked_matches, key=lambda item: item[:3]):
                routes_and_contracts.append(match)
                if len(routes_and_contracts) >= 20:
                    break

        # 4. Extract relevant static scanner findings
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        if analysis_intent in {"security", "verification"}:
            static_pool = list(self.evidence_store.all_findings)
        else:
            static_pool = [
                finding
                for file_path in sorted(target_files)
                for finding in self.evidence_store.get_findings(file_path=file_path)
            ]
        static_findings = sorted(
            static_pool,
            key=lambda finding: (
                severity_rank.get(str(getattr(finding.severity, "value", finding.severity)), 5),
                -float(finding.confidence or 0.0),
                finding.evidence.file_path,
                finding.evidence.start_line or 0,
                finding.tool,
                finding.rule_id or "",
            ),
        )[:25]

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
            "neural_reranker_used": use_neural_reranker,
            "independent_context_available": any(
                result.provenance.get("selection") != "deterministic_candidate_anchor"
                for result in relevant_chunks
            ),
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
