"""Projection-owned facts and bounded candidate/retrieval queries."""

from collections import defaultdict
import hashlib
import json

from sqlalchemy import select

from app.analysis.store import EvidenceStore
from app.graph.builder import build_repository_graph
from app.indexing.chunker import chunk_file
from app.models.intelligence import IndexFactModel, IndexPostingModel, IndexSignalModel
from app.ingestion.schemas import RepositoryManifest
from app.retrieval.tokens import lexical_tokens

FACT_VERSION = "projection-facts/1"
MAX_FILE_CHUNKS = 128
MAX_FILE_POSTINGS = 8192
MAX_FILE_FACTS = 2048
ZERO_REVISION = "0" * 40


def _digest(*values):
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def persist_facts(index, projection, file, source: bytes) -> dict:
    """Runs once per compatible projection, with bounded amplification."""
    from app.specialist_candidates import build_bug_candidates, build_security_flow_candidates
    from app.indexing.persistent import redact_projection
    from app.security.redaction import redact_secrets
    manifest = RepositoryManifest(repository_url=index.repository_url, commit_hash=ZERO_REVISION, files=[file])
    chunks = chunk_file(file, ZERO_REVISION, source.decode("utf-8", errors="ignore"),
        max_chunks=MAX_FILE_CHUNKS + 1, max_content_bytes=index.limits.max_projection_bytes)
    from app.indexing.chunker import _CHUNKABLE_KINDS
    truncated = len(chunks) > MAX_FILE_CHUNKS or sum(s.kind in _CHUNKABLE_KINDS for s in file.symbols) > len(chunks)
    retained_chunks = [chunk for chunk in chunks[:MAX_FILE_CHUNKS] if len(chunk.symbol.encode("utf-8")) <= 512]
    truncated |= len(retained_chunks) < len(chunks)
    chunks = retained_chunks
    from app.semantics import build_semantic_program
    semantic_program = build_semantic_program(manifest, chunks)
    semantic_payload = redact_projection(semantic_program.model_dump(mode="json"))
    if len(json.dumps(semantic_payload).encode()) <= index.limits.max_projection_bytes:
        index.db.add(IndexFactModel(projection_id=projection.id, tenant_id=index.tenant_id,
            repository_id=index.repository_id, path=file.path, fact_id="semantic-summary",
            kind="SEMANTIC", lookup=file.path, target="", payload=semantic_payload))
    else:
        truncated = True
    component = (file.path.split("/", 1)[0] if "/" in file.path else ".")[:128]
    common = dict(projection_id=projection.id, tenant_id=index.tenant_id,
                  repository_id=index.repository_id, path=file.path)
    evidence_keys = {}
    postings = 0
    for chunk in chunks:
        key = _digest(chunk.symbol, chunk.symbol_kind.value, chunk.start_line, chunk.end_line)
        evidence_keys[f"chunk:{chunk.chunk_id}"] = key
        index.db.add(IndexFactModel(**common, fact_id=key, kind="CHUNK", lookup=redact_secrets(chunk.symbol.lower()),
            target="", payload=redact_projection(chunk.model_dump(mode="json", exclude={"content", "commit_sha", "chunk_id"}))))
        for token, frequency in lexical_tokens(redact_secrets(chunk.symbol + " " + chunk.content)).items():
            if postings >= MAX_FILE_POSTINGS:
                truncated = True
                break
            index.db.add(IndexPostingModel(**common, token=token, chunk_key=key,
                component=component, frequency=frequency))
            postings += 1
    graph = build_repository_graph(manifest, EvidenceStore(manifest))
    from app.graph.imports import import_paths
    for target in import_paths(file):
        index.db.add(IndexFactModel(**common, fact_id=_digest("import", target), kind="IMPORT_REF",
            lookup=file.path, target=redact_secrets(target), payload=redact_projection({"source_path": file.path, "target_path": target})))
    nodes = graph.get_nodes()
    edges = graph.get_edges()
    # Identical endpoint strings in different services are distinct authorities.
    route_ids = {node.id: f"{node.id}:{file.path}:{node.start_line}" for node in nodes if node.kind.value == "ROUTE"}
    nodes = [node.model_copy(update={"id": route_ids.get(node.id, node.id)}) for node in nodes]
    edges = [edge.model_copy(update={"source": route_ids.get(edge.source, edge.source),
        "target": route_ids.get(edge.target, edge.target)}) for edge in edges]
    for node in nodes[:MAX_FILE_FACTS]:
        if len(node.id.encode("utf-8")) > 1024:
            truncated = True
            continue
        index.db.add(IndexFactModel(**common, fact_id=_digest("node", node.id), kind="NODE", lookup=redact_secrets(node.id),
            target=node.kind.value, payload=redact_projection(node.model_dump(mode="json"))))
    for edge in edges[:MAX_FILE_FACTS]:
        if max(len(edge.source.encode("utf-8")), len(edge.target.encode("utf-8"))) > 1024:
            truncated = True
            continue
        index.db.add(IndexFactModel(**common, fact_id=_digest("edge", edge.source, edge.target, edge.kind.value),
            kind="EDGE", lookup=redact_secrets(edge.source), target=redact_secrets(edge.target), payload=redact_projection(edge.model_dump(mode="json"))))
    truncated |= len(nodes) > MAX_FILE_FACTS or len(edges) > MAX_FILE_FACTS
    counts = {}
    for intent, candidates in (
        ("bug", build_bug_candidates(chunks, manifest=manifest, limit=64, semantic_program=semantic_program)),
        ("security", build_security_flow_candidates(manifest, chunks, limit=64, semantic_program=semantic_program)),
    ):
        unique = {}
        for candidate in candidates:
            keys = [evidence_keys[ref] for ref in candidate.evidence_refs if ref in evidence_keys]
            if not keys or len(keys) != len(candidate.evidence_refs):
                continue
            issue = _digest(candidate.candidate_kind, file.path, candidate.related_symbol,
                candidate.metadata.get("source_line"), candidate.metadata.get("sink"), candidate.metadata.get("callee"))
            payload = redact_projection(candidate.model_dump(mode="json"))
            payload["metadata"]["issue_fingerprint"] = issue
            payload["metadata"]["projection_id"] = projection.id
            payload["metadata"]["evidence_keys"] = keys
            payload["metadata"]["dependency_certificate"] = {
                "source_sha256": projection.content_hash, "producer_digest": projection.producer_digest,
                "scope": "FILE_LOCAL", "cross_file_resolution": "UNKNOWN",
            }
            unique[issue] = payload
        for issue, payload in unique.items():
            index.db.add(IndexSignalModel(**common, issue_id=issue, intent=intent, component=component,
                priority=100 if payload["strength"] == "STRONG" else 50, payload=payload))
        counts[intent] = len(unique)
    return {"status": "PARTIAL" if truncated else "FILE_LOCAL", "postings": postings,
            "chunks": len(chunks), "signals": counts, "cross_file_resolution": "UNKNOWN"}


def _current(index, row) -> bool:
    entry = index.file_entry(row.path)
    return bool(entry and entry.projection_id == row.projection_id)


def chunk_id(index, projection_id, key):
    return f"idx:{index.snapshot_id}:{projection_id}:{key}"


def select_candidates(index, intent: str, *, limit: int = 12, examined_limit: int = 192):
    """Bounded deterministic component-diverse queue view, pinned to snapshot."""
    from app.specialist_candidates import AnalysisCandidate
    statement = select(IndexSignalModel.component, IndexSignalModel.path, IndexSignalModel.issue_id).where(
        IndexSignalModel.tenant_id == index.tenant_id,
        IndexSignalModel.repository_id == index.repository_id,
        IndexSignalModel.intent == intent,
    )
    # Select logical signals, not historical projection versions. Repeated
    # commits cannot consume the queue with duplicates of one old candidate.
    rows = index.db.execute(statement.distinct().order_by(IndexSignalModel.component,
        IndexSignalModel.path, IndexSignalModel.issue_id).limit(examined_limit + 1)).all()
    queues = defaultdict(list)
    seen = set()
    for logical in rows[:examined_limit]:
        projection = index.file_projection(logical.path)
        row = index.db.get(IndexSignalModel, (projection.id, logical.issue_id)) if projection else None
        if row is None or row.issue_id in seen or row.intent != intent:
            continue
        seen.add(row.issue_id)
        value = json.loads(json.dumps(row.payload))
        references = ["chunk:" + chunk_id(index, row.projection_id, key)
                      for key in value["metadata"]["evidence_keys"]]
        mapping = dict(zip(value["evidence_refs"], references))
        value["candidate_id"] = "candidate:" + row.issue_id
        value["evidence_refs"] = references
        for key, items in list(value["metadata"].items()):
            if key.endswith("evidence_refs") and isinstance(items, list):
                value["metadata"][key] = [mapping[item] for item in items if item in mapping]
        queues[row.component].append(AnalysisCandidate.model_validate(value))
    for queue in queues.values():
        queue.sort(key=lambda candidate: (candidate.strength.value != "STRONG", candidate.candidate_id))
    selected = []
    for rank in range(limit):
        for component in sorted(queues):
            if rank < len(queues[component]):
                selected.append(queues[component][rank])
                if len(selected) >= limit:
                    break
        if len(selected) >= limit:
            break
    index.query_coverage = {"signals_examined": min(len(rows), examined_limit),
        "candidate_selection_partial": len(rows) > examined_limit or len(seen) > len(selected),
        "selected": len(selected)}
    return selected


def search_postings(index, query: str, *, limit: int = 64, examined_limit: int = 512):
    tokens = list(lexical_tokens(query))[:12]
    scores = defaultdict(float)
    examined = 0
    for token in tokens:
        allowance = min(64, examined_limit - examined)
        if allowance <= 0:
            break
        rows = index.db.execute(select(IndexPostingModel.component, IndexPostingModel.path, IndexPostingModel.chunk_key).where(
            IndexPostingModel.tenant_id == index.tenant_id,
            IndexPostingModel.repository_id == index.repository_id,
            IndexPostingModel.token == token,
        ).distinct().order_by(IndexPostingModel.component, IndexPostingModel.path, IndexPostingModel.chunk_key).limit(allowance)).all()
        examined += len(rows)
        for logical in rows:
            projection = index.file_projection(logical.path)
            row = index.db.get(IndexPostingModel, (projection.id, token, logical.chunk_key)) if projection else None
            if row is not None:
                scores[chunk_id(index, row.projection_id, row.chunk_key)] += row.frequency / (row.frequency + 1.2)
    index.query_coverage = {"postings_examined": examined, "exhaustive": False,
                            "postings_budget": examined_limit}
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:limit]
