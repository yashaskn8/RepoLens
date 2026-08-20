"""Hybrid repository retrieval service fusing exact, lexical, dense, and graph channels."""

import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.graph.repository_graph import RepositoryGraph
from app.indexing.embeddings import EmbeddingProvider
from app.indexing.schemas import CodeChunk, EmbeddingRequest
from app.retrieval.fusion import reciprocal_rank_fusion
from app.retrieval.reranker import QwenReranker
from app.retrieval.schemas import (
    RerankCandidate,
    RetrievalChannel,
    RetrievalQuery,
    RetrievalResult,
)
from app.retrieval.vector_index import InMemoryVectorIndex, VectorIndex


class RetrievalService:
    """Canonical hybrid retrieval service combining multi-channel search and neural reranking."""

    def __init__(
        self,
        chunks: List[CodeChunk],
        vector_index: Optional[VectorIndex] = None,
        embedding_provider: Optional[EmbeddingProvider] = None,
        repository_graph: Optional[RepositoryGraph] = None,
        reranker: Optional[QwenReranker] = None,
    ):
        self.chunks_by_id: Dict[str, CodeChunk] = {c.chunk_id: c for c in chunks}
        self.vector_index = vector_index or InMemoryVectorIndex()
        self.embedding_provider = embedding_provider
        self.repository_graph = repository_graph
        self.reranker = reranker or QwenReranker()

    # =========================================================================
    # Channel 1: Exact Symbol / Path Match
    # =========================================================================
    def _search_exact(self, query: str) -> List[Tuple[str, float]]:
        """Find exact or prefix matches against symbol names and file paths."""
        q_clean = query.strip().lower()
        scored: List[Tuple[str, float]] = []

        for chunk_id, chunk in self.chunks_by_id.items():
            sym = (chunk.symbol or "").lower()
            f_path = (chunk.file_path or "").lower()

            if sym == q_clean:
                scored.append((chunk_id, 1.0))
            elif q_clean in sym:
                scored.append((chunk_id, 0.8))
            elif f_path.endswith(q_clean) or q_clean in f_path:
                scored.append((chunk_id, 0.6))

        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored

    # =========================================================================
    # Channel 2: Lexical BM25 / Term Overlap Search
    # =========================================================================
    def _search_lexical(self, query: str) -> List[Tuple[str, float]]:
        """Compute lexical similarity score based on term matching and frequency."""
        q_tokens = [t.lower() for t in re.findall(r"\w+", query) if len(t) > 1]
        if not q_tokens:
            return []

        num_docs = len(self.chunks_by_id)
        if num_docs == 0:
            return []

        # Count document frequencies
        doc_freq: Dict[str, int] = {}
        for token in set(q_tokens):
            cnt = sum(1 for c in self.chunks_by_id.values() if token in c.content.lower() or token in c.symbol.lower())
            doc_freq[token] = cnt

        scored: List[Tuple[str, float]] = []
        for chunk_id, chunk in self.chunks_by_id.items():
            content_lower = chunk.content.lower()
            sym_lower = chunk.symbol.lower()
            score = 0.0

            for token in q_tokens:
                df = doc_freq.get(token, 0)
                idf = math.log((num_docs + 1.0) / (df + 1.0)) + 1.0

                # Term frequency in content and symbol
                tf_content = content_lower.count(token)
                tf_sym = sym_lower.count(token) * 3.0  # Symbol match boost
                total_tf = tf_content + tf_sym

                if total_tf > 0:
                    score += idf * (total_tf / (total_tf + 1.2))

            if score > 0.0:
                scored.append((chunk_id, score))

        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored

    # =========================================================================
    # Channel 3: Dense Semantic Retrieval
    # =========================================================================
    async def _search_dense(self, query: str, top_k: int) -> List[Tuple[str, float]]:
        """Query vector index using neural query embedding."""
        if not self.embedding_provider or self.vector_index.count() == 0:
            return []

        try:
            req = EmbeddingRequest(
                texts=[query],
                input_type="query",
                model=self.embedding_provider.default_model,
            )
            resp = await self.embedding_provider.embed(req)
            if not resp.embeddings:
                return []

            query_vec = resp.embeddings[0].vector
            return self.vector_index.query(query_vec, top_k=top_k)
        except Exception:
            return []

    # =========================================================================
    # Channel 4: RepositoryGraph Neighborhood Expansion
    # =========================================================================
    def _search_graph(self, exact_matches: List[Tuple[str, float]]) -> List[Tuple[str, float]]:
        """Traverse relationship graph neighbors for matched symbols and files."""
        if not self.repository_graph or not exact_matches:
            return []

        neighbor_chunks: Dict[str, float] = {}
        top_exact_ids = {cid for cid, _ in exact_matches[:5]}

        # Map exact match chunks to file paths and symbol names
        seed_files: Set[str] = set()
        seed_symbols: Set[str] = set()
        for cid in top_exact_ids:
            chunk = self.chunks_by_id.get(cid)
            if chunk:
                seed_files.add(chunk.file_path)
                seed_symbols.add(chunk.symbol)

        # Find nodes in graph matching seed files or symbols
        seed_node_ids: Set[str] = set()
        for f in seed_files:
            seed_node_ids.add(f"file:{f}")
            seed_node_ids.add(f"test:{f}")

        # Traverse outgoing and incoming edges for each seed node
        for seed_id in seed_node_ids:
            # Outgoing neighbors (imports, calls, exposes_route, depends_on, tests)
            for edge in self.repository_graph.get_outgoing_edges(seed_id):
                target_node = self.repository_graph.get_node(edge.target)
                if target_node and target_node.file_path:
                    # Find chunks in target file
                    for c_id, c in self.chunks_by_id.items():
                        if c.file_path == target_node.file_path and c_id not in top_exact_ids:
                            neighbor_chunks[c_id] = max(neighbor_chunks.get(c_id, 0.0), 0.7)

            # Incoming neighbors (callers, importers, tests)
            for edge in self.repository_graph.get_incoming_edges(seed_id):
                src_node = self.repository_graph.get_node(edge.source)
                if src_node and src_node.file_path:
                    for c_id, c in self.chunks_by_id.items():
                        if c.file_path == src_node.file_path and c_id not in top_exact_ids:
                            neighbor_chunks[c_id] = max(neighbor_chunks.get(c_id, 0.0), 0.6)

        scored = list(neighbor_chunks.items())
        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored

    # =========================================================================
    # Hybrid Retrieval Execution
    # =========================================================================
    async def retrieve(self, query: RetrievalQuery) -> List[RetrievalResult]:
        """Execute multi-channel retrieval, RRF fusion, and optional neural reranking."""
        channel_rankings: Dict[RetrievalChannel, List[Tuple[str, float]]] = {}

        # 1. Exact match channel
        exact_results = self._search_exact(query.query)
        if exact_results:
            channel_rankings[RetrievalChannel.EXACT] = exact_results

        # 2. Lexical search channel
        lexical_results = self._search_lexical(query.query)
        if lexical_results:
            channel_rankings[RetrievalChannel.LEXICAL] = lexical_results

        # 3. Dense semantic retrieval channel
        dense_results = await self._search_dense(query.query, top_k=query.top_k * 2)
        if dense_results:
            channel_rankings[RetrievalChannel.DENSE] = dense_results

        # 4. Graph neighborhood channel
        graph_results = self._search_graph(exact_results)
        if graph_results:
            channel_rankings[RetrievalChannel.GRAPH] = graph_results

        # Reciprocal Rank Fusion
        fused = reciprocal_rank_fusion(channel_rankings, k=60)

        # Apply optional filters
        filtered_fused = []
        for chunk_id, rrf_score, channels in fused:
            chunk = self.chunks_by_id.get(chunk_id)
            if not chunk:
                continue

            if query.file_path_filter and query.file_path_filter not in chunk.file_path:
                continue
            if query.symbol_kind_filter and chunk.symbol_kind.value != query.symbol_kind_filter:
                continue

            filtered_fused.append((chunk, rrf_score, channels))

        candidate_slice = filtered_fused[: query.top_k]
        if not candidate_slice:
            return []

        # Optional Neural Reranking with Qwen3-Reranker
        rerank_map: Dict[str, Optional[float]] = {}
        if query.use_reranker and self.reranker:
            rerank_candidates = [
                RerankCandidate(
                    chunk_id=chunk.chunk_id,
                    content=chunk.content,
                    initial_score=rrf_score,
                )
                for chunk, rrf_score, _ in candidate_slice
            ]
            rerank_results = await self.reranker.rerank(query.query, rerank_candidates)
            rerank_map = dict(rerank_results)

        # Build final RetrievalResults
        final_results: List[RetrievalResult] = []
        for chunk, rrf_score, channels in candidate_slice:
            rerank_score = rerank_map.get(chunk.chunk_id)
            provenance = {
                "commit_sha": chunk.commit_sha,
                "file_path": chunk.file_path,
                "symbol": chunk.symbol,
                "symbol_kind": chunk.symbol_kind.value,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
                "language": chunk.language,
                "content_hash": chunk.content_hash,
            }
            final_results.append(
                RetrievalResult(
                    chunk_id=chunk.chunk_id,
                    score=rerank_score if rerank_score is not None else rrf_score,
                    source_channels=channels,
                    chunk=chunk,
                    reranked_score=rerank_score,
                    provenance=provenance,
                )
            )

        # Sort final results by effective score descending
        final_results.sort(key=lambda r: (-r.score, r.chunk_id))
        return final_results
