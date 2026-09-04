"""Hybrid repository retrieval service fusing exact, lexical, dense, and graph channels."""

import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.config import get_settings
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind
from app.indexing.embeddings import CohereEmbeddingAdapter, EmbeddingProvider
from app.indexing.schemas import CodeChunk, EmbeddingRequest
from app.retrieval.fusion import reciprocal_rank_fusion
from app.retrieval.reranker import CohereReranker, QwenReranker
from app.retrieval.schemas import (
    RerankCandidate,
    RetrievalChannel,
    RetrievalQuery,
    RetrievalResult,
)
from app.retrieval.vector_index import InMemoryVectorIndex, VectorIndex


class RetrievalService:
    """Canonical hybrid retrieval service combining multi-channel search and neural reranking."""

    RERANK_CANDIDATE_MULTIPLIER = 4
    MAX_RERANK_CANDIDATES = 100
    MAX_GRAPH_SEEDS = 8
    MAX_GRAPH_NODES_PER_SEED = 8
    MAX_GRAPH_EDGES_PER_NODE = 40
    MAX_GRAPH_RESULTS = 100

    _GRAPH_EDGE_WEIGHTS: Dict[str, Dict[EdgeKind, float]] = {
        "general": {
            EdgeKind.CALLS: 0.90,
            EdgeKind.IMPORTS: 0.80,
            EdgeKind.DEPENDS_ON: 0.80,
            EdgeKind.TESTS: 0.75,
            EdgeKind.CONTAINS: 0.60,
        },
        "bug": {
            EdgeKind.CALLS: 1.00,
            EdgeKind.TESTS: 0.90,
            EdgeKind.CONTAINS: 0.70,
            EdgeKind.IMPORTS: 0.60,
            EdgeKind.DEPENDS_ON: 0.55,
        },
        "security": {
            EdgeKind.CALLS: 1.00,
            EdgeKind.EXPOSES_ROUTE: 0.95,
            EdgeKind.REQUESTS_ROUTE: 0.95,
            EdgeKind.MATCHES_ROUTE: 0.90,
            EdgeKind.DEPENDS_ON: 0.75,
            EdgeKind.IMPORTS: 0.65,
            EdgeKind.CONTAINS: 0.60,
        },
        "architecture": {
            EdgeKind.DEPENDS_ON: 1.00,
            EdgeKind.IMPORTS: 0.95,
            EdgeKind.CALLS: 0.75,
            EdgeKind.CONTAINS: 0.60,
            EdgeKind.TESTS: 0.45,
        },
        "integration": {
            EdgeKind.MATCHES_ROUTE: 1.00,
            EdgeKind.REQUESTS_ROUTE: 1.00,
            EdgeKind.EXPOSES_ROUTE: 1.00,
            EdgeKind.CALLS: 0.80,
            EdgeKind.DEPENDS_ON: 0.70,
            EdgeKind.IMPORTS: 0.60,
        },
    }

    def __init__(
        self,
        chunks: List[CodeChunk],
        vector_index: Optional[VectorIndex] = None,
        embedding_provider: Optional[EmbeddingProvider] = None,
        repository_graph: Optional[RepositoryGraph] = None,
        reranker: Optional[Any] = None,
    ):
        settings = get_settings()
        self.chunks_by_id: Dict[str, CodeChunk] = {c.chunk_id: c for c in chunks}
        self.chunk_ids_by_file: Dict[str, List[str]] = {}
        for chunk in sorted(chunks, key=lambda item: item.chunk_id):
            self.chunk_ids_by_file.setdefault(chunk.file_path, []).append(chunk.chunk_id)
        self.vector_index = vector_index or InMemoryVectorIndex()

        if embedding_provider is None:
            if getattr(settings, "LOCAL_EMBEDDING_ENABLED", False):
                from app.embeddings.adapter import LocalEmbeddingAdapter
                self.embedding_provider = LocalEmbeddingAdapter()
            elif settings.COHERE_API_KEY:
                self.embedding_provider = CohereEmbeddingAdapter()
            else:
                self.embedding_provider = None
        else:
            self.embedding_provider = embedding_provider

        self.repository_graph = repository_graph

        if reranker is None:
            if settings.COHERE_API_KEY:
                self.reranker = CohereReranker()
            else:
                self.reranker = QwenReranker()
        else:
            self.reranker = reranker

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
    def _graph_seeds(
        self,
        rankings: List[Tuple[RetrievalChannel, List[Tuple[str, float]]]],
    ) -> List[Tuple[str, RetrievalChannel]]:
        """Build a stable, bounded union of exact, lexical, and dense seeds."""
        seeds: List[Tuple[str, RetrievalChannel]] = []
        seen: Set[str] = set()
        # Round-robin prevents a long exact list from starving lexical or dense
        # evidence while retaining deterministic channel/rank ordering.
        for rank_index in range(self.MAX_GRAPH_SEEDS):
            for channel, ranking in rankings:
                if rank_index >= len(ranking):
                    continue
                chunk_id, _ = ranking[rank_index]
                if chunk_id in self.chunks_by_id and chunk_id not in seen:
                    seeds.append((chunk_id, channel))
                    seen.add(chunk_id)
                if len(seeds) >= self.MAX_GRAPH_SEEDS:
                    return seeds
        return seeds

    def _graph_weight(self, intent: str, edge_kind: EdgeKind) -> float:
        profile = self._GRAPH_EDGE_WEIGHTS.get(intent.lower(), self._GRAPH_EDGE_WEIGHTS["general"])
        return profile.get(edge_kind, 0.40)

    def _search_graph(
        self,
        seeds: List[Tuple[str, RetrievalChannel]],
        *,
        analysis_intent: str,
    ) -> Tuple[List[Tuple[str, float]], Dict[str, Dict[str, Any]]]:
        """Expand one graph hop from bounded multi-channel seeds with intent-aware weights."""
        if not self.repository_graph or not seeds:
            return [], {}

        seed_ids = {chunk_id for chunk_id, _ in seeds}
        seed_channel = {chunk_id: channel for chunk_id, channel in seeds}
        nodes = self.repository_graph.get_nodes()
        nodes_by_file: Dict[str, List[str]] = {}
        nodes_by_file_symbol: Dict[Tuple[str, str], List[str]] = {}
        for node in sorted(nodes, key=lambda item: item.id):
            if not node.file_path:
                continue
            nodes_by_file.setdefault(node.file_path, []).append(node.id)
            nodes_by_file_symbol.setdefault((node.file_path, node.label), []).append(node.id)

        neighbor_chunks: Dict[str, float] = {}
        graph_provenance: Dict[str, Dict[str, Any]] = {}
        for chunk_id, channel in seeds:
            chunk = self.chunks_by_id[chunk_id]
            symbol_nodes = nodes_by_file_symbol.get((chunk.file_path, chunk.symbol), [])
            seed_node_ids = (symbol_nodes or nodes_by_file.get(chunk.file_path, []))[
                : self.MAX_GRAPH_NODES_PER_SEED
            ]
            for seed_node_id in seed_node_ids:
                adjacent = [
                    (edge, edge.target, "outgoing")
                    for edge in self.repository_graph.get_outgoing_edges(seed_node_id)
                ] + [
                    (edge, edge.source, "incoming")
                    for edge in self.repository_graph.get_incoming_edges(seed_node_id)
                ]
                for edge, neighbor_id, direction in sorted(
                    adjacent,
                    key=lambda item: (item[0].kind.value, item[1], item[2]),
                )[: self.MAX_GRAPH_EDGES_PER_NODE]:
                    neighbor = self.repository_graph.get_node(neighbor_id)
                    if not neighbor or not neighbor.file_path:
                        continue
                    direction_factor = 1.0 if direction == "outgoing" else 0.95
                    score = self._graph_weight(analysis_intent, edge.kind) * direction_factor
                    for candidate_id in self.chunk_ids_by_file.get(neighbor.file_path, []):
                        if candidate_id in seed_ids:
                            continue
                        existing = neighbor_chunks.get(candidate_id, -1.0)
                        candidate_provenance = {
                            "seed_chunk_id": chunk_id,
                            "seed_reason": channel.value,
                            "graph_distance": 1,
                            "graph_edge_type": edge.kind.value,
                            "effective_graph_weight": score,
                            "graph_direction": direction,
                        }
                        current = graph_provenance.get(candidate_id)
                        if score > existing or (
                            score == existing
                            and tuple(candidate_provenance.values()) < tuple((current or {}).values())
                        ):
                            neighbor_chunks[candidate_id] = score
                            graph_provenance[candidate_id] = candidate_provenance

        scored = sorted(neighbor_chunks.items(), key=lambda item: (-item[1], item[0]))[
            : self.MAX_GRAPH_RESULTS
        ]
        retained = {chunk_id for chunk_id, _ in scored}
        return scored, {
            chunk_id: provenance
            for chunk_id, provenance in graph_provenance.items()
            if chunk_id in retained
        }

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
        dense_results = await self._search_dense(
            query.query,
            top_k=min(self.MAX_RERANK_CANDIDATES, query.top_k * 2),
        )
        if dense_results:
            channel_rankings[RetrievalChannel.DENSE] = dense_results

        # 4. Graph neighborhood channel
        graph_seeds = self._graph_seeds([
            (RetrievalChannel.EXACT, exact_results),
            (RetrievalChannel.LEXICAL, lexical_results),
            (RetrievalChannel.DENSE, dense_results),
        ])
        graph_results, graph_provenance = self._search_graph(
            graph_seeds,
            analysis_intent=query.analysis_intent,
        )
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

        rerank_pool_size = min(
            len(filtered_fused),
            max(
                query.top_k,
                min(self.MAX_RERANK_CANDIDATES, query.top_k * self.RERANK_CANDIDATE_MULTIPLIER),
            ),
        )
        candidate_slice = filtered_fused[:rerank_pool_size]
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
            try:
                rerank_results = await self.reranker.rerank(query.query, rerank_candidates)
                rerank_map = dict(rerank_results)
            except Exception:
                rerank_map = {}

        # Build final RetrievalResults
        final_results: List[RetrievalResult] = []
        for initial_position, (chunk, rrf_score, channels) in enumerate(candidate_slice, start=1):
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
                "reranked_from_position": initial_position,
            }
            provenance.update(graph_provenance.get(chunk.chunk_id, {}))
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
        final_results = final_results[: query.top_k]
        for final_position, result in enumerate(final_results, start=1):
            result.provenance["final_position"] = final_position
        return final_results
