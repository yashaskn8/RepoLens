"""Offline production-path regressions for immutable indexing and recovery."""

import subprocess
from dataclasses import replace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.indexing.persistent import IndexLimits, PersistentIndex
from app.ingestion.classification import FileClass, classify_file
from app.models.base import Base
from app.models.intelligence import IndexEntryModel, IndexProjectionModel


@pytest.fixture
def indexed_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args], cwd=repo).decode().strip()
    git("init", "-q")
    (repo / "a.py").write_text("def load(value):\n    return value\n", encoding="utf-8")
    (repo / "b.py").write_text("async def refresh():\n    time.sleep(1)\n", encoding="utf-8")
    (repo / "vendor").mkdir()
    (repo / "vendor" / "unsafe.py").write_text("raise RuntimeError('never execute')", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "fixture")
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        def index(*, tenant="tenant-a", limits=IndexLimits()):
            return PersistentIndex(db, tenant_id=tenant, repository_url="https://github.com/fixture/repo", repo_dir=str(repo), commit_sha=git("rev-parse", "HEAD"), limits=limits)
        yield repo, git, db, index
    engine.dispose()


def test_warm_projection_reuse_does_not_parse_or_read_source(indexed_repository):
    _, _, db, factory = indexed_repository
    index = factory()
    first = index.build_manifest()
    assert len(first.files) == 2
    assert index.stats["excluded_subtrees"] == {"vendored_directory": 1}
    assert index.stats["inventory_complete"]
    count = db.scalar(select(func.count()).select_from(IndexProjectionModel))
    warm = factory()
    with patch("app.indexing.persistent.parse_file_with_calls", side_effect=AssertionError("warm parse")), patch.object(warm.inventory, "read_object", side_effect=AssertionError("warm blob read")):
        assert len(warm.build_manifest().files) == 2
    assert warm.stats["parsed_files"] == 0
    assert warm.stats["reused_files"] == 2
    assert db.scalar(select(func.count()).select_from(IndexProjectionModel)) == count


def test_partial_projection_stays_partial_when_reused_in_changed_tree(indexed_repository):
    repo, git, _, factory = indexed_repository
    (repo / "a.py").write_text("def one():\n    return 1\ndef two():\n    return 2\n", encoding="utf-8")
    git("add", "a.py")
    git("commit", "-qm", "multiple symbols")
    first = factory()
    with patch("app.indexing.facts.MAX_FILE_CHUNKS", 1):
        first.build_manifest()
    assert first.stats["partial_files"] == 1
    (repo / "b.py").write_text("def changed():\n    return 3\n", encoding="utf-8")
    git("add", "b.py")
    git("commit", "-qm", "new root tree")
    changed = factory()
    manifest = changed.build_manifest()
    assert changed.stats["reused_files"] == 1
    assert changed.stats["partial_files"] == 1
    assert manifest.analysis_scope.truncated


def test_storage_backpressure_also_stops_excluded_inventory_growth(indexed_repository):
    repo, git, db, factory = indexed_repository
    (repo / "000.bin").write_bytes(b"\x00untrusted binary")
    git("add", "000.bin")
    git("commit", "-qm", "excluded metadata")
    index = factory(limits=replace(IndexLimits(), max_database_bytes=1))
    with patch.object(index.inventory, "read_object", side_effect=AssertionError("unnecessary blob read")):
        manifest = index.build_manifest()
    assert manifest.analysis_scope.truncated
    assert index.stats["stop_reason"] == "index_database_byte_budget"
    assert db.scalar(select(func.count()).select_from(IndexEntryModel)) == 0


@pytest.mark.asyncio
async def test_verifier_cannot_disable_independent_retrieval(indexed_repository):
    from unittest.mock import AsyncMock
    from app.analysis.store import EvidenceStore
    from app.context.runtime import ScanIntelligenceRuntime
    _, _, _, factory = indexed_repository
    index = factory()
    store = EvidenceStore(index.build_manifest())
    store.persistent_index = index
    runtime = await ScanIntelligenceRuntime.build(store)
    with patch.object(runtime.retrieval_service, "retrieve", new=AsyncMock(return_value=[])) as retrieve:
        bundle = await runtime.context_engine.build_context_bundle(
            scan_id="scan", query="refresh", analysis_intent="verification", anchor_only=True)
    retrieve.assert_awaited_once()
    assert bundle.provenance["retrieval_mode"] == "HYBRID"


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", [None, "missing", "snapshot_id", "tenant_id", "producer_digest"])
@pytest.mark.parametrize("pending", [False, True])
async def test_checkpoint_requires_same_evidence_authority(indexed_repository, mismatch, pending):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from app.agents.graph import run_analysis_workflow
    from app.analysis.store import EvidenceStore
    from app.context.runtime import ScanIntelligenceRuntime
    repo, _, _, factory = indexed_repository
    index = factory()
    store = EvidenceStore(index.build_manifest())
    store.persistent_index = index
    runtime = await ScanIntelligenceRuntime.build(store)
    authority = {"snapshot_id": index.snapshot_id, "producer_digest": index.producer,
        "tenant_id": index.tenant_id, "repository_id": index.repository_id, "commit_sha": index.commit_sha}
    if mismatch == "missing":
        authority = None
    elif mismatch:
        authority[mismatch] = "other-generation"
    state = {"scan_id": "scan", "status": "COMPLETED", "manifest_summary": {"index_authority": authority},
        "verified_findings": [{"id": "old-evidence"}]}
    app = SimpleNamespace(aget_state=AsyncMock(return_value=SimpleNamespace(values=state, next=("bug",) if pending else ())),
        ainvoke=AsyncMock(return_value=state))
    with patch("app.agents.graph.build_analysis_graph", return_value=app):
        result = await run_analysis_workflow(store, "scan", str(repo), checkpointer=object(),
            context_engine=runtime.context_engine, repository_graph=runtime.repository_graph)
    if mismatch:
        assert result["status"] == "FAILED"
        assert "generation is incompatible" in result["errors"][0]
        assert not result.get("verified_findings")
        app.ainvoke.assert_not_awaited()
    else:
        assert result["status"] == "COMPLETED"
        assert app.ainvoke.await_count == int(pending)


@pytest.mark.asyncio
async def test_fresh_workflow_checkpoints_current_index_authority(indexed_repository):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from app.agents.graph import run_analysis_workflow
    from app.analysis.store import EvidenceStore
    from app.context.runtime import ScanIntelligenceRuntime
    repo, _, _, factory = indexed_repository
    index = factory()
    store = EvidenceStore(index.build_manifest())
    store.persistent_index = index
    runtime = await ScanIntelligenceRuntime.build(store)
    app = SimpleNamespace(ainvoke=AsyncMock(side_effect=lambda payload, **kwargs: payload))
    with patch("app.agents.graph.build_analysis_graph", return_value=app):
        result = await run_analysis_workflow(store, "scan", str(repo),
            context_engine=runtime.context_engine, repository_graph=runtime.repository_graph)
    assert result["manifest_summary"]["index_authority"]["snapshot_id"] == index.snapshot_id
    assert result["manifest_summary"]["index_authority"]["tenant_id"] == index.tenant_id
    assert not result["manifest_summary"]["graph_coverage"]["complete"]
    assert "candidate_selection_coverage" in result["manifest_summary"]


def test_partial_discovery_resumes_without_losing_completed_projection(indexed_repository):
    _, _, db, factory = indexed_repository
    partial = factory(limits=replace(IndexLimits(), max_files=1))
    manifest = partial.build_manifest()
    assert manifest.analysis_scope.truncated
    assert not partial.stats["inventory_complete"]
    before = db.scalar(select(func.count()).select_from(IndexProjectionModel))
    resumed = factory()
    resumed.build_manifest()
    assert resumed.stats["inventory_complete"]
    assert resumed.stats["parsed_files"] == 1
    assert db.scalar(select(func.count()).select_from(IndexProjectionModel)) == before + 1


def test_new_commit_reuses_unchanged_bytes_but_rebinds_evidence(indexed_repository):
    repo, git, _, factory = indexed_repository
    first = factory()
    first.build_manifest()
    old_commit = first.commit_sha
    (repo / "b.py").write_text("async def refresh():\n    await asyncio.sleep(1)\n", encoding="utf-8")
    git("add", "b.py")
    git("commit", "-qm", "change")
    second = factory()
    second.build_manifest()
    assert second.stats["parsed_files"] == 1
    assert second.stats["reused_files"] == 1
    chunks = second.load_chunks("a.py")
    assert chunks and chunks[0].commit_sha == second.commit_sha != old_commit
    assert second.file_entry("../a.py") is None


def test_tenant_scope_and_excluded_source_cannot_be_bypassed(indexed_repository):
    _, _, db, factory = indexed_repository
    first = factory()
    first.build_manifest()
    assert first.load_chunks("vendor/unsafe.py") == []
    second = factory(tenant="tenant-b")
    second.build_manifest()
    assert second.snapshot_id != first.snapshot_id
    assert second.stats["parsed_files"] == 2
    assert db.scalar(select(func.count()).select_from(IndexEntryModel)) == 6


def test_classification_keeps_hidden_configuration_and_rejects_external_links():
    assert classify_file(".github/workflows/ci.yml", language="yaml").eligible
    assert classify_file("node_modules/a/index.js", language="javascript").classification == FileClass.VENDORED
    assert not classify_file("linked.py", language="python", mode="120000").eligible


def test_partial_snapshot_is_immutable_after_resume_and_reopen(indexed_repository):
    _, _, _, factory = indexed_repository
    partial = factory(limits=replace(IndexLimits(), max_files=1))
    partial.build_manifest()
    partial.pin("scan-partial")
    old_id = partial.snapshot_id
    assert partial.file_entry("b.py") is None
    resumed = factory()
    resumed.build_manifest()
    assert resumed.snapshot_id != old_id and resumed.file_entry("b.py")
    assert partial.file_entry("b.py") is None
    reopened = factory()
    reopened.open_snapshot(old_id)
    assert reopened.file_entry("a.py") and reopened.file_entry("b.py") is None
    from app.ingestion.git_inventory import InventoryBound
    with pytest.raises(InventoryBound, match="snapshot_not_in_scope"):
        factory(tenant="other").open_snapshot(old_id)


@pytest.mark.asyncio
async def test_persistent_runtime_retrieves_cross_file_calls_without_embeddings(indexed_repository):
    from app.analysis.store import EvidenceStore
    from app.context.runtime import ScanIntelligenceRuntime
    from app.retrieval.schemas import RetrievalQuery, RetrievalChannel
    from app.graph.schemas import EdgeKind
    from unittest.mock import AsyncMock
    repo, git, _, factory = indexed_repository
    (repo / "b.py").write_text("from a import load\ndef refresh(value):\n    return load(value)\n", encoding="utf-8")
    git("add", "b.py")
    git("commit", "-qm", "explicit import")
    index = factory()
    store = EvidenceStore(index.build_manifest())
    store.persistent_index = index
    embeddings = AsyncMock()
    runtime = await ScanIntelligenceRuntime.build(store, embedding_provider=embeddings)
    assert runtime.chunks == [] and len(runtime.retrieval_service.chunks_by_id) == 0
    results = await runtime.retrieval_service.retrieve(RetrievalQuery(query="refresh", use_reranker=False, analysis_intent="bug"))
    assert {item.chunk.file_path for item in results} == {"a.py", "b.py"}
    assert any(RetrievalChannel.GRAPH in item.source_channels and item.chunk.file_path == "a.py" for item in results)
    embeddings.embed.assert_not_called()
    edges = runtime.repository_graph.get_outgoing_edges("symbol:b.py:FUNCTION:refresh:2")
    edge = next(edge for edge in edges if edge.kind == EdgeKind.CALLS)
    assert edge.metadata["dependency_certificate"]["snapshot_id"] == index.snapshot_id
    old_target = edge.metadata["dependency_certificate"]["target_sha256"]
    (repo / "a.py").write_text("def load(value):\n    return value + 1\n", encoding="utf-8")
    git("add", "a.py")
    git("commit", "-qm", "callee behavior change")
    changed = factory()
    changed.build_manifest()
    from app.graph.persistent import PersistentRepositoryGraph
    new_edge = next(edge for edge in PersistentRepositoryGraph(changed).get_outgoing_edges("symbol:b.py:FUNCTION:refresh:2") if edge.kind == EdgeKind.CALLS)
    assert changed.stats["parsed_files"] == 1
    assert new_edge.metadata["dependency_certificate"]["target_sha256"] != old_target


@pytest.mark.asyncio
async def test_candidate_batch_is_deduplicated_anchored_and_byte_bounded(indexed_repository):
    import json
    from app.analysis.store import EvidenceStore
    from app.context.runtime import ScanIntelligenceRuntime
    from app.context.slices import build_specialist_context
    from app.indexing.facts import select_candidates
    _, _, _, factory = indexed_repository
    index = factory()
    store = EvidenceStore(index.build_manifest())
    store.persistent_index = index
    candidates = select_candidates(index, "bug")
    assert len(candidates) == 1
    runtime = await ScanIntelligenceRuntime.build(store)
    with patch.object(runtime.retrieval_service, "retrieve", side_effect=AssertionError("unnecessary specialist search")), \
         patch.object(runtime.repository_graph, "get_edges", side_effect=AssertionError("unnecessary graph scan")), \
         patch.object(runtime.repository_graph, "evaluate_route_contracts", side_effect=AssertionError("unnecessary contract scan")):
        pack = await build_specialist_context(context_engine=runtime.context_engine, scan_id="scan",
            commit_sha=index.commit_sha, analysis_intent="bug", candidates=candidates * 5, token_budget=2048)
    payload = json.loads(pack.text)
    assert len(payload["hypotheses"]) == 1 and len(pack.slices) == 1
    assert set(candidates[0].evidence_refs).issubset(pack.evidence_index)
    assert pack.packed_bytes <= 2048 * 4
    assert not any("vendor" in str(fact) for fact in pack.evidence_index.values())


def test_byte_budget_allows_small_files_without_reserving_maximum_file_size(indexed_repository):
    _, _, _, factory = indexed_repository
    index = factory(limits=replace(IndexLimits(), max_source_bytes=128))
    index.build_manifest()
    assert index.stats["inventory_complete"]
    assert 0 < index.stats["source_bytes_read"] <= 128


def test_active_manifest_is_byte_bounded_without_losing_reusable_inventory(indexed_repository):
    _, _, _, factory = indexed_repository
    bounded = factory(limits=replace(IndexLimits(), manifest_bytes=1))
    manifest = bounded.build_manifest()
    assert not manifest.files and manifest.analysis_scope.truncated
    assert bounded.stats["inventory_complete"] and bounded.stats["indexed_files"] == 2
    warm = factory()
    assert len(warm.build_manifest().files) == 2
    assert not warm.stats["manifest_truncated"] and warm.stats["parsed_files"] == 0


def test_historical_versions_do_not_starve_current_candidate_and_postings(indexed_repository):
    from app.indexing.facts import select_candidates, search_postings
    from app.models.intelligence import IndexSignalModel, IndexPostingModel
    _, _, db, factory = indexed_repository
    index = factory()
    index.build_manifest()
    entry = index.file_entry("b.py")
    projection = index.file_projection("b.py")
    signal = db.execute(select(IndexSignalModel).where(IndexSignalModel.projection_id == projection.id)).scalars().first()
    posting = db.execute(select(IndexPostingModel).where(IndexPostingModel.projection_id == projection.id,
        IndexPostingModel.token == "refresh")).scalars().first()
    for number in range(8):
        stale = f"{number:064x}"
        db.add(IndexProjectionModel(id=stale, tenant_id=index.tenant_id, repository_id=index.repository_id,
            content_hash=projection.content_hash, producer_digest=index.producer, payload=projection.payload, payload_bytes=projection.payload_bytes))
        db.flush()
        db.add(IndexSignalModel(projection_id=stale, issue_id=signal.issue_id, tenant_id=index.tenant_id,
            repository_id=index.repository_id, intent=signal.intent, component=signal.component,
            path=signal.path, priority=signal.priority, payload=signal.payload))
        db.add(IndexPostingModel(projection_id=stale, token=posting.token, chunk_key=posting.chunk_key,
            tenant_id=index.tenant_id, repository_id=index.repository_id, component=posting.component,
            path=posting.path, frequency=posting.frequency))
    db.commit()
    assert len(select_candidates(index, "bug", examined_limit=2)) == 1
    results = search_postings(index, "refresh", examined_limit=2)
    assert len(results) == 1 and entry.projection_id in results[0][0]


def test_catalog_writer_is_exclusive_and_stale_writer_cannot_publish(indexed_repository):
    from app.ingestion.git_inventory import InventoryBound
    from app.models.intelligence import IndexWriterModel
    from sqlalchemy import update
    _, _, db, factory = indexed_repository
    first, contender = factory(), factory()
    first._acquire_writer()
    with pytest.raises(InventoryBound, match="index_writer_busy"):
        contender._acquire_writer()
    db.execute(update(IndexWriterModel).where(IndexWriterModel.id == first.writer_id).values(expires_at=0))
    db.commit()
    contender._acquire_writer()
    with pytest.raises(InventoryBound, match="index_writer_lease_lost"):
        first._commit(force=True)
    first._release_writer()
    assert db.get(IndexWriterModel, first.writer_id).token == contender.writer_token
    contender._release_writer()


def test_checkpoint_survives_interrupted_projection(indexed_repository):
    _, _, db, factory = indexed_repository
    interrupted = factory(limits=replace(IndexLimits(), page_size=1))
    project = interrupted._project
    def crash(entry, path):
        if path == "b.py":
            raise RuntimeError("simulated process interruption")
        return project(entry, path)
    with patch.object(interrupted, "_project", side_effect=crash), pytest.raises(RuntimeError):
        interrupted.build_manifest()
    db.rollback()
    resumed = factory()
    resumed.build_manifest()
    assert resumed.stats["inventory_complete"] and resumed.stats["parsed_files"] == 1


def test_disk_backpressure_stops_without_fabricating_clean_scope(indexed_repository):
    from collections import namedtuple
    _, _, _, factory = indexed_repository
    index = factory()
    usage = namedtuple("usage", "total used free")(100, 99, 1)
    with patch("app.indexing.persistent.shutil.disk_usage", return_value=usage):
        manifest = index.build_manifest()
    assert manifest.analysis_scope.truncated and not index.stats["inventory_complete"]
    assert index.stats["stop_reason"] == "index_disk_backpressure"
    resumed = factory()
    resumed.build_manifest()
    assert resumed.stats["inventory_complete"]


def test_raw_secret_literals_are_not_persisted_in_facts_or_postings(indexed_repository):
    import json
    from app.models.intelligence import IndexFactModel, IndexPostingModel
    repo, git, db, factory = indexed_repository
    secret = "gsk_" + "x" * 32
    (repo / "a.py").write_text(f"def load(password='{secret}'):\n    return connect(password='{secret}')\n", encoding="utf-8")
    git("add", "a.py")
    git("commit", "-qm", "redaction fixture")
    index = factory()
    index.build_manifest()
    projection = index.file_projection("a.py")
    assert secret not in json.dumps(projection.payload)
    facts = db.execute(select(IndexFactModel).where(IndexFactModel.projection_id == projection.id)).scalars().all()
    assert all(secret not in json.dumps(fact.payload) for fact in facts)
    tokens = db.execute(select(IndexPostingModel.token).where(IndexPostingModel.projection_id == projection.id)).scalars().all()
    assert secret not in tokens and "x" * 32 not in tokens


def test_known_async_calls_returned_or_scheduled_are_not_unawaited_defects(indexed_repository):
    from app.indexing.facts import select_candidates
    repo, git, _, factory = indexed_repository
    (repo / "a.py").write_text("async def fetch():\n    return 1\ndef forwarded():\n    return fetch()\ndef scheduled():\n    asyncio.create_task(fetch())\ndef discarded():\n    fetch()\n", encoding="utf-8")
    git("add", "a.py")
    git("commit", "-qm", "coroutine ownership")
    index = factory()
    index.build_manifest()
    candidates = [item for item in select_candidates(index, "bug") if item.candidate_kind == "UNAWAITED_ASYNC_CALL"]
    assert len(candidates) == 1
    assert "discarded" in candidates[0].related_symbol
    assert len(candidates[0].evidence_refs) == 2


def test_import_package_module_ambiguity_remains_unknown(indexed_repository):
    from app.graph.persistent import PersistentRepositoryGraph
    from app.graph.schemas import EdgeKind
    repo, git, _, factory = indexed_repository
    (repo / "a").mkdir()
    (repo / "a" / "__init__.py").write_text("def load(value):\n    return 0\n", encoding="utf-8")
    (repo / "b.py").write_text("from a import load\ndef refresh(value):\n    return load(value)\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "ambiguous import")
    index = factory()
    index.build_manifest()
    graph = PersistentRepositoryGraph(index)
    assert not any(edge.kind == EdgeKind.CALLS for edge in graph.get_outgoing_edges("symbol:b.py:FUNCTION:refresh:2"))
    assert graph.query_truncated


def test_persistent_architecture_cycle_requires_explicit_import_anchors(indexed_repository):
    from app.indexing.facts import select_architecture_candidates
    from app.graph.persistent import PersistentRepositoryGraph
    repo, git, _, factory = indexed_repository
    (repo / "a.py").write_text("from b import value\ndef a(value):\n    return value\n", encoding="utf-8")
    (repo / "b.py").write_text("from a import a\ndef value(value):\n    return a(value)\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "cycle")
    index = factory()
    index.build_manifest()
    graph = PersistentRepositoryGraph(index)
    candidates = select_architecture_candidates(index, graph)
    assert candidates and candidates[0].candidate_kind == "DEPENDENCY_CYCLE"
    assert all(ref.startswith("chunk:idx:") for ref in candidates[0].evidence_refs)
    assert candidates[0].metadata["coverage_complete"] is False


def test_same_line_imports_share_one_source_anchor(indexed_repository):
    repo, git, _, factory = indexed_repository
    (repo / "a.py").write_text("import b; import os\ndef load():\n    return 1\n", encoding="utf-8")
    git("add", "a.py")
    git("commit", "-qm", "same line imports")
    index = factory()
    index.build_manifest()
    spans = [fact for fact in index.file_facts("a.py", "CHUNK") if fact.payload.get("import_targets")]
    assert len(spans) == 1
    assert {"b.py", "os.py"}.issubset(spans[0].payload["import_targets"])


def test_database_pressure_preserves_resume_and_warm_reuse(indexed_repository):
    _, _, _, factory = indexed_repository
    blocked = factory(limits=replace(IndexLimits(), max_database_bytes=1))
    manifest = blocked.build_manifest()
    assert manifest.analysis_scope.truncated
    assert blocked.stats["stop_reason"] == "index_database_byte_budget"
    assert blocked.stats["parsed_files"] == 0
    factory().build_manifest()
    warm = factory(limits=replace(IndexLimits(), max_database_bytes=1))
    assert len(warm.build_manifest().files) == 2
    assert warm.stats["parsed_files"] == 0


def test_retention_reclaims_only_unpinned_unreachable_projections(indexed_repository):
    from app.indexing.retention import collect_catalog
    from app.models.intelligence import IndexSnapshotModel, IndexTreeModel
    from sqlalchemy import update
    repo, git, db, factory = indexed_repository
    pinned = factory()
    pinned.build_manifest()
    pinned.pin("retained-report")
    pinned_a = pinned.file_projection("a.py").id
    for number in (1, 2):
        (repo / "a.py").write_text(f"def load(value):\n    return value + {number}\n", encoding="utf-8")
        git("add", "a.py")
        git("commit", "-qm", "change")
        current = factory()
        current.build_manifest()
        if number == 1:
            expired_snapshot, expired_projection = current.snapshot_id, current.file_projection("a.py").id
    other = factory(tenant="other")
    other.build_manifest()
    other_projection = other.file_projection("a.py").id
    db.execute(update(IndexSnapshotModel).values(accessed_at=1))
    db.commit()
    shared_b = current.file_projection("b.py").id
    current.limits = replace(current.limits, gc_rows=5)
    # Small maintenance pages prove deletion can resume in the middle of facts.
    for _ in range(60):
        current._acquire_writer()
        try:
            report = collect_catalog(current)
            assert report["deleted_rows"] <= 5
        finally:
            current._release_writer()
        if db.get(IndexProjectionModel, expired_projection) is None:
            break
    assert db.get(IndexSnapshotModel, pinned.snapshot_id) is not None
    assert db.get(IndexProjectionModel, pinned_a) is not None
    assert db.get(IndexProjectionModel, shared_b) is not None
    assert db.get(IndexProjectionModel, other_projection) is not None
    assert db.get(IndexSnapshotModel, expired_snapshot) is None
    assert db.get(IndexProjectionModel, expired_projection) is None
    assert current.file_projection("a.py") is not None
    assert db.scalar(select(func.count()).select_from(IndexTreeModel)) > 0


def test_retention_requires_fence_and_refreshes_accessed_generation(indexed_repository):
    import time
    from app.indexing.retention import collect_catalog
    from app.ingestion.git_inventory import InventoryBound
    from app.models.intelligence import IndexSnapshotModel
    _, _, db, factory = indexed_repository
    index = factory()
    index.build_manifest()
    with pytest.raises(InventoryBound, match="catalog_gc_requires_writer"):
        collect_catalog(index)
    snapshot = index.snapshot()
    snapshot.accessed_at = 1
    db.commit()
    reopened = factory()
    reopened.open_snapshot(snapshot.id)
    assert db.get(IndexSnapshotModel, snapshot.id).accessed_at > time.time() - 10


def test_catalog_retention_migration_round_trip(tmp_path):
    from alembic import command
    from sqlalchemy import inspect
    from tests.test_alembic_migrations import _get_alembic_config
    url = "sqlite:///" + (tmp_path / "retention.db").as_posix()
    config = _get_alembic_config(url)
    command.upgrade(config, "head")
    engine = create_engine(url)
    try:
        assert "accessed_at" in {item["name"] for item in inspect(engine).get_columns("index_snapshots")}
        command.downgrade(config, "14c381b62a10")
        assert "accessed_at" not in {item["name"] for item in inspect(engine).get_columns("index_snapshots")}
        command.upgrade(config, "head")
        assert "gc_state" in {item["name"] for item in inspect(engine).get_columns("index_writers")}
    finally:
        engine.dispose()


def test_query_work_budget_interrupts_sql_and_preserves_next_query(indexed_repository):
    from sqlalchemy import text
    _, _, _, factory = indexed_repository
    index = factory(limits=replace(IndexLimits(), query_vm_steps=1000))
    index.build_manifest()
    rows = index.query_rows(text("WITH RECURSIVE series(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM series WHERE n<1000000) SELECT sum(n) FROM series"))
    assert rows == [] and index.query_coverage["query_budget_exhausted"]
    assert index.query_rows(text("SELECT 1"))[0][0] == 1
    assert index.stats["query_budget_exhaustions"] == 1


def test_projection_amplification_rolls_back_incomplete_facts(indexed_repository):
    from app.models.intelligence import IndexFactModel
    _, _, db, factory = indexed_repository
    index = factory(limits=replace(IndexLimits(), max_projection_bytes=1024))
    manifest = index.build_manifest()
    assert index.stats["excluded_by_reason"].get("projection_fact_byte_limit", 0) > 0
    assert db.scalar(select(func.count()).select_from(IndexFactModel)) == 0
    assert db.scalar(select(func.count()).select_from(IndexProjectionModel)) == 0
    assert manifest.analysis_scope.truncated
