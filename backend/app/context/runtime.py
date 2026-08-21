"""Canonical ScanIntelligenceRuntime assembling full Phase 2 repository intelligence from EvidenceStore."""

import logging
import os
from typing import Dict, List, Optional

from app.analysis.store import EvidenceStore
from app.context.engine import ContextEngine
from app.core.config import get_settings
from app.graph.builder import build_repository_graph
from app.graph.repository_graph import RepositoryGraph
from app.indexing.chunker import chunk_manifest
from app.indexing.embeddings import (
    EmbeddingProvider,
    HuggingFaceEmbeddingAdapter,
    NvidiaEmbeddingAdapter,
)
from app.indexing.schemas import CodeChunk, EmbeddingRequest
from app.ingestion.schemas import RepositoryManifest
from app.retrieval.reranker import QwenReranker
from app.retrieval.service import RetrievalService
from app.retrieval.vector_index import InMemoryVectorIndex, VectorIndex

logger = logging.getLogger(__name__)


def _read_file_contents_from_workspace(manifest: RepositoryManifest, repo_dir: str) -> Dict[str, str]:
    """Safely read non-binary source file contents from a repository workspace."""
    file_contents: Dict[str, str] = {}
    if not repo_dir or not os.path.exists(repo_dir):
        return file_contents

    abs_root = os.path.abspath(repo_dir)

    for file_entry in manifest.files:
        if file_entry.is_binary:
            continue

        clean_path = file_entry.path.replace("\\", "/").lstrip("/")
        full_path = os.path.abspath(os.path.join(abs_root, clean_path))

        # Path traversal boundary confinement
        if not full_path.startswith(abs_root):
            continue

        if os.path.exists(full_path) and os.path.isfile(full_path):
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    file_contents[file_entry.path] = content
                    file_contents[clean_path] = content
            except Exception as exc:
                logger.warning("Failed to read file '%s' for indexing: %s", file_entry.path, str(exc))

    return file_contents


class ScanIntelligenceRuntime:
    """Canonical repository intelligence runtime assembled from an EvidenceStore.
    
    Constructs the end-to-end intelligence hierarchy:
    RepositoryManifest
        ↓
    RepositoryGraph
        ↓
    symbol-aware CodeChunks (using exact commit SHA)
        ↓
    EmbeddingProvider + VectorIndex
        ↓
    RetrievalService (exact + lexical + dense + graph + RRF reranker fallback)
        ↓
    ContextEngine
    """

    def __init__(
        self,
        evidence_store: EvidenceStore,
        repository_graph: RepositoryGraph,
        chunks: List[CodeChunk],
        vector_index: VectorIndex,
        embedding_provider: Optional[EmbeddingProvider],
        retrieval_service: RetrievalService,
        context_engine: ContextEngine,
        repo_dir: Optional[str] = None,
    ):
        self.evidence_store = evidence_store
        self.manifest = evidence_store.manifest
        self.repository_graph = repository_graph
        self.chunks = chunks
        self.vector_index = vector_index
        self.embedding_provider = embedding_provider
        self.retrieval_service = retrieval_service
        self.context_engine = context_engine
        self.repo_dir = repo_dir

    @classmethod
    async def build(
        cls,
        evidence_store: EvidenceStore,
        repo_dir: Optional[str] = None,
        file_contents: Optional[Dict[str, str]] = None,
        embedding_provider: Optional[EmbeddingProvider] = None,
        vector_index: Optional[VectorIndex] = None,
        reranker: Optional[QwenReranker] = None,
    ) -> "ScanIntelligenceRuntime":
        """Asynchronously assemble the complete repository intelligence runtime from EvidenceStore."""
        manifest = evidence_store.manifest

        # 1. Build RepositoryGraph
        repository_graph = build_repository_graph(manifest, evidence_store)

        # 2. Extract file contents if not already provided
        contents = file_contents or {}
        if not contents and repo_dir:
            contents = _read_file_contents_from_workspace(manifest, repo_dir)

        # 3. Generate symbol-aware CodeChunks using exact commit SHA
        chunks = chunk_manifest(manifest, contents)

        # 4. Resolve EmbeddingProvider
        settings = get_settings()
        provider = embedding_provider
        if provider is None:
            if getattr(settings, "NVIDIA_API_KEY", None):
                provider = NvidiaEmbeddingAdapter()
            elif getattr(settings, "HUGGINGFACE_API_KEY", None):
                provider = HuggingFaceEmbeddingAdapter()

        # 5. Initialize VectorIndex and populate embeddings if provider available
        dim = provider.dimensions if provider else 1536
        v_index = vector_index or InMemoryVectorIndex(dimensions=dim)

        if provider and chunks:
            try:
                # Embed chunks in batches
                batch_size = 32
                for i in range(0, len(chunks), batch_size):
                    batch = chunks[i:i + batch_size]
                    req = EmbeddingRequest(
                        texts=[c.content for c in batch],
                        input_type="passage",
                        model=provider.default_model,
                    )
                    resp = await provider.embed(req)
                    for emb_res, chunk in zip(resp.embeddings, batch):
                        v_index.upsert(chunk.chunk_id, emb_res.vector)
            except Exception as exc:
                logger.warning(
                    "Embedding generation encountered an issue: %s. "
                    "Gracefully degraded to exact + lexical + graph multi-channel retrieval.",
                    str(exc),
                )

        # 6. Initialize RetrievalService
        retrieval_service = RetrievalService(
            chunks=chunks,
            vector_index=v_index,
            embedding_provider=provider,
            repository_graph=repository_graph,
            reranker=reranker or QwenReranker(),
        )

        # 7. Initialize ContextEngine
        context_engine = ContextEngine(
            evidence_store=evidence_store,
            repository_graph=repository_graph,
            retrieval_service=retrieval_service,
        )

        return cls(
            evidence_store=evidence_store,
            repository_graph=repository_graph,
            chunks=chunks,
            vector_index=v_index,
            embedding_provider=provider,
            retrieval_service=retrieval_service,
            context_engine=context_engine,
            repo_dir=repo_dir,
        )


# Global runtime registry for active scans to avoid putting non-msgpack types into checkpointer state
_active_scan_runtimes: Dict[str, ScanIntelligenceRuntime] = {}


def register_scan_runtime(scan_id: str, runtime: ScanIntelligenceRuntime) -> None:
    """Register an active scan runtime by scan_id."""
    _active_scan_runtimes[str(scan_id)] = runtime


def unregister_scan_runtime(scan_id: str) -> None:
    """Unregister an active scan runtime."""
    _active_scan_runtimes.pop(str(scan_id), None)


def get_scan_runtime(scan_id: str) -> Optional[ScanIntelligenceRuntime]:
    """Retrieve active ScanIntelligenceRuntime for a scan."""
    return _active_scan_runtimes.get(str(scan_id))


def get_scan_context_engine(scan_id: str) -> Optional[ContextEngine]:
    """Retrieve ContextEngine for an active scan."""
    rt = get_scan_runtime(scan_id)
    return rt.context_engine if rt else None

