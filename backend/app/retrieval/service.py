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
from app.retrieval.tokens import lexical_tokens


class RetrievalService:
    """Canonical hybrid retrieval service combining multi-channel search and neural reranking."""

    RERANK_CANDIDATE_MULTIPLIER = 4
    MAX_RERANK_CANDIDATES = 100
    MAX_GRAPH_SEEDS = 8
    MAX_GRAPH_NODES_PER_SEED = 8
    MAX_GRAPH_EDGES_PER_NODE = 40
    MAX_GRAPH_RESULTS = 100
    MAX_RESULT_SOURCE_BYTES = 4_194_304

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
        persistent_index=None,
    ):
        settings = get_settings()
        self.persistent_index = persistent_index
        self.last_query_coverage: Dict[str, Any] = {}
        self.chunks_by_id: Dict[str, CodeChunk] = {c.chunk_id: c for c in chunks}
        self.chunk_ids_by_file: Dict[str, List[str]] = {}
        self.chunk_ids_by_symbol: Dict[str, List[str]] = {}
        self._content_lower: Dict[str, str] = {}
        self._symbol_lower: Dict[str, str] = {}
        self._path_lower: Dict[str, str] = {}
        self._token_postings: Dict[str, Set[str]] = {}
        for chunk in sorted(chunks, key=lambda item: item.chunk_id):
            self.chunk_ids_by_file.setdefault(chunk.file_path, []).append(chunk.chunk_id)
            symbol = (chunk.symbol or "").lower()
            content = chunk.content.lower()
            self.chunk_ids_by_symbol.setdefault(symbol, []).append(chunk.chunk_id)
            self._content_lower[chunk.chunk_id] = content
            self._symbol_lower[chunk.chunk_id] = symbol
            self._path_lower[chunk.chunk_id] = (chunk.file_path or "").lower()
            for token in lexical_tokens(f"{symbol} {content}"):
                if len(token) > 1:
                    self._token_postings.setdefault(token, set()).add(chunk.chunk_id)
        self.vector_index = vector_index or InMemoryVectorIndex()
        self._token_postings = {token: tuple(sorted(ids)) for token, ids in self._token_postings.items()}

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
        self._graph_nodes_by_file: Dict[str, List[str]] = {}
        self._graph_nodes_by_file_symbol: Dict[Tuple[str, str], List[str]] = {}
        if repository_graph is not None and persistent_index is None:
            for node in sorted(repository_graph.get_nodes(), key=lambda item: item.id):
                if not node.file_path:
                    continue
                self._graph_nodes_by_file.setdefault(node.file_path, []).append(node.id)
                self._graph_nodes_by_file_symbol.setdefault(
                    (node.file_path, node.label), []
                ).append(node.id)

        if reranker is None:
            if settings.COHERE_API_KEY:
                self.reranker = CohereReranker()
            else:
                self.reranker = QwenReranker()
        else:
            self.reranker = reranker
        if persistent_index is not None:
            from app.retrieval.lazy_chunks import LazyChunks
            self.chunks_by_id = LazyChunks(persistent_index)

    # =========================================================================
    # Channel 1: Exact Symbol / Path Match
    # =========================================================================
    def _search_exact(self, query: str) -> List[Tuple[str, float]]:
        """Find exact or prefix matches against symbol names and file paths."""
        q_clean = query.strip().lower()
        if self.persistent_index is not None:
            from app.indexing.facts import chunk_id
            from app.models.intelligence import IndexFactModel
            from sqlalchemy import select
            index = self.persistent_index
            if index.file_entry(query.strip()):
                return [(chunk_id(index, row.projection_id, row.fact_id), 1.0)
                    for row in index.file_facts(query.strip(), "CHUNK", limit=64)]
            paths = index.db.execute(select(IndexFactModel.path).where(
                IndexFactModel.tenant_id == index.tenant_id,
                IndexFactModel.repository_id == index.repository_id,
                IndexFactModel.kind == "CHUNK", IndexFactModel.lookup == q_clean,
            ).distinct().order_by(IndexFactModel.path).limit(32)).scalars().all()
            results = []
            for path in paths:
                for fact in index.file_facts(path, "CHUNK", limit=128):
                    if fact.lookup == q_clean:
                        results.append((chunk_id(index, fact.projection_id, fact.fact_id), 1.0))
                        if len(results) >= 64:
                            return results
            return results
        scored: List[Tuple[str, float]] = []

        exact_symbol_ids = set(self.chunk_ids_by_symbol.get(q_clean, []))
        for chunk_id in self.chunks_by_id:
            sym = self._symbol_lower[chunk_id]
            f_path = self._path_lower[chunk_id]

            if chunk_id in exact_symbol_ids:
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
        if self.persistent_index is not None:
            from app.indexing.facts import search_postings
            results = search_postings(self.persistent_index, query)
            self.last_query_coverage = dict(self.persistent_index.query_coverage)
            return results
        q_tokens = list(lexical_tokens(query))[:12]
        if not q_tokens:
            return []

        num_docs = len(self.chunks_by_id)
        if num_docs == 0:
            return []

        postings_by_query: Dict[str, Set[str]] = {}
        examined = 0
        for token in q_tokens:
            from itertools import islice
            allowance = max(0, 512 - examined)
            postings = set(islice(iter(self._token_postings.get(token, ())), allowance))
            examined += len(postings)
            postings_by_query[token] = postings
        self.last_query_coverage = {"postings_examined": examined, "postings_budget": 512, "exhaustive": False}
        candidate_ids = set().union(*postings_by_query.values()) if postings_by_query else set()

        scored: List[Tuple[str, float]] = []
        for chunk_id in sorted(candidate_ids):
            content_lower = self._content_lower[chunk_id]
            sym_lower = self._symbol_lower[chunk_id]
            score = 0.0

            for token in q_tokens:
                df = len(postings_by_query.get(token, ()))
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
        neighbor_chunks: Dict[str, float] = {}
        graph_provenance: Dict[str, Dict[str, Any]] = {}
        for chunk_id, channel in seeds:
            chunk = self.chunks_by_id[chunk_id]
            symbol_nodes = self._graph_nodes_by_file_symbol.get((chunk.file_path, chunk.symbol), [])
            seed_node_ids = (symbol_nodes or self._graph_nodes_by_file.get(chunk.file_path, []))[
                : self.MAX_GRAPH_NODES_PER_SEED
            ]
            if self.persistent_index is not None:
                nodes = self.repository_graph.nodes_for_file(chunk.file_path)
                matching = [node for node in nodes if node.label == chunk.symbol]
                seed_node_ids = [node.id for node in (matching or nodes)[:self.MAX_GRAPH_NODES_PER_SEED]]
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
                    candidate_ids = self.chunk_ids_by_file.get(neighbor.file_path, [])
                    if self.persistent_index is not None:
                        from app.indexing.facts import chunk_id as persistent_chunk_id
                        facts = self.persistent_index.file_facts(neighbor.file_path, "CHUNK", limit=128)
                        matching = [fact for fact in facts if fact.payload["symbol"] == neighbor.label]
                        candidate_ids = [persistent_chunk_id(self.persistent_index, fact.projection_id, fact.fact_id)
                            for fact in (matching or facts)[:4]]
                    for candidate_id in candidate_ids:
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
        source_bytes = 0
        for chunk_id, rrf_score, channels in fused:
            chunk = self.chunks_by_id.get(chunk_id)
            if not chunk:
                continue

            if query.file_path_filter and query.file_path_filter not in chunk.file_path:
                continue
            if query.symbol_kind_filter and chunk.symbol_kind.value != query.symbol_kind_filter:
                continue

            size = len(chunk.content.encode("utf-8"))
            if source_bytes + size > self.MAX_RESULT_SOURCE_BYTES:
                self.last_query_coverage["source_byte_budget_reached"] = True
                continue
            source_bytes += size

            filtered_fused.append((chunk, rrf_score, channels))
        self.last_query_coverage["source_bytes_loaded"] = source_bytes

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
            provenance["retrieval_coverage"] = dict(self.last_query_coverage)
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
