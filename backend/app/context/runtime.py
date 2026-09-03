"""Canonical ScanIntelligenceRuntime assembling full Phase 2 repository intelligence from EvidenceStore."""

from dataclasses import dataclass
import logging
import os
from typing import Any, Dict, List, Optional

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


def _vector_is_current(
    entry: Optional[Dict[str, Any]],
    chunk: CodeChunk,
    *,
    model_name: str,
    dimensions: int,
    vector_index_version: str,
) -> bool:
    """Return whether a stored vector is safe to reuse for this exact chunk."""
    if not entry:
        return False

    metadata = entry.get("metadata")
    if not isinstance(metadata, dict):
        return False

    vector = entry.get("vector")
    try:
        stored_dimensions = len(vector)
    except TypeError:
        return False

    stored_dimensions_metadata = metadata.get("dimensions")
    stored_vector_index_version = metadata.get(
        "vector_index_version",
        entry.get("index_version"),
    )
    return (
        stored_dimensions == dimensions
        and metadata.get("content_hash") == chunk.content_hash
        and metadata.get("model") == model_name
        and (stored_dimensions_metadata is None or stored_dimensions_metadata == dimensions)
        and metadata.get("index_version") == chunk.index_version
        and (
            stored_vector_index_version is None
            or str(stored_vector_index_version) == vector_index_version
        )
    )


def _embedding_provenance(
    chunk: CodeChunk,
    *,
    provider_name: str,
    model_name: str,
    response_provider: str,
    response_model: str,
    dimensions: int,
    vector_index: VectorIndex,
) -> Dict[str, Any]:
    """Build durable provenance needed to validate incremental vector reuse."""
    return {
        "content_hash": chunk.content_hash,
        "commit_sha": chunk.commit_sha,
        "file_path": chunk.file_path,
        "symbol": chunk.symbol,
        "symbol_kind": chunk.symbol_kind.value,
        "start_line": chunk.start_line,
        "end_line": chunk.end_line,
        "provider": provider_name,
        "model": model_name,
        "response_provider": response_provider,
        "response_model": response_model,
        "dimensions": dimensions,
        "index_version": chunk.index_version,
        "vector_index_version": str(getattr(vector_index, "index_version", "v1")),
        "vector_namespace": str(getattr(vector_index, "namespace", "default")),
    }


def _read_file_contents_from_workspace(manifest: RepositoryManifest, repo_dir: str) -> Dict[str, str]:
    """Safely read non-binary source file contents from a repository workspace."""
    from app.core.path_confinement import PathTraversalError, resolve_safe_path

    file_contents: Dict[str, str] = {}
    if not repo_dir or not os.path.exists(repo_dir):
        return file_contents

    for file_entry in manifest.files:
        if file_entry.is_binary:
            continue

        clean_path = file_entry.path.replace("\\", "/").lstrip("/")
        try:
            full_path_obj = resolve_safe_path(repo_dir, clean_path)
            full_path = str(full_path_obj)
        except PathTraversalError:
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

        # 5. Initialize VectorIndex via canonical factory and populate embeddings if provider available
        dim = provider.dimensions if provider else 1536
        model_name = getattr(provider, "default_model", "text-embedding-3-large") if provider else "text-embedding-3-large"
        namespace = f"scan:{manifest.commit_sha or 'default'}"
        from app.retrieval.vector_index import create_vector_index
        v_index = vector_index or create_vector_index(
            db_url=getattr(settings, "DATABASE_URL", None),
            dimensions=dim,
            namespace=namespace,
            model_name=model_name,
            enable_pgvector=getattr(settings, "ENABLE_PGVECTOR", False),
        )

        if provider and chunks:
            try:
                provider_name = str(provider.provider_name)
                vector_index_version = str(getattr(v_index, "index_version", "v1"))
                chunks_to_embed = [
                    chunk
                    for chunk in chunks
                    if not _vector_is_current(
                        v_index.get(chunk.chunk_id),
                        chunk,
                        model_name=model_name,
                        dimensions=dim,
                        vector_index_version=vector_index_version,
                    )
                ]

                # Only missing or stale chunks consume embedding-provider quota.
                batch_size = 32
                for i in range(0, len(chunks_to_embed), batch_size):
                    batch = chunks_to_embed[i:i + batch_size]
                    req = EmbeddingRequest(
                        texts=[c.content for c in batch],
                        input_type="passage",
                        model=model_name,
                    )
                    resp = await provider.embed(req)
                    embeddings_by_index = {result.index: result for result in resp.embeddings}
                    upserts = []
                    for position, chunk in enumerate(batch):
                        emb_res = embeddings_by_index.get(position)
                        if emb_res is None:
                            logger.warning(
                                "Embedding provider omitted result %d for chunk '%s'; lexical retrieval remains available.",
                                position,
                                chunk.chunk_id,
                            )
                            continue
                        upserts.append(
                            (
                                chunk.chunk_id,
                                emb_res.vector,
                                _embedding_provenance(
                                    chunk,
                                    provider_name=provider_name,
                                    model_name=model_name,
                                    response_provider=resp.provider,
                                    response_model=resp.model,
                                    dimensions=emb_res.dimensions,
                                    vector_index=v_index,
                                ),
                            )
                        )
                    v_index.upsert_batch(upserts)
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


@dataclass(frozen=True)
class AnalysisRuntimeContext:
    """Transient repository intelligence runtime context. Never checkpointed."""

    scan_runtime: ScanIntelligenceRuntime

    @property
    def context_engine(self) -> ContextEngine:
        return self.scan_runtime.context_engine

    @property
    def repository_graph(self) -> RepositoryGraph:
        return self.scan_runtime.repository_graph

    @property
    def evidence_store(self) -> EvidenceStore:
        return self.scan_runtime.evidence_store

