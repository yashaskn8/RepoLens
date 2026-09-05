"""Immutable Git-tree projections, checkpointed extraction and lazy source spans.

Unchanged directories share inventory rows across commits. Database transactions
publish one file at a time; a completed directory is an immutable reuse boundary.
"""

from collections.abc import Iterator
from dataclasses import dataclass
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import shutil
import time
from uuid import uuid4

from sqlalchemy import select, update, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.analysis.authority import source_fingerprint
from app.ingestion.classification import CLASSIFICATION_VERSION, classify_file
from app.ingestion.detector import detect_language
from app.ingestion.git_inventory import GitInventory, InventoryBound
from app.ingestion.parser import parse_file_with_calls
from app.ingestion.schemas import AnalysisScope, FileEntry, RepositoryManifest
from app.indexing.chunker import chunk_file
from app.indexing.schemas import CodeChunk
from app.models.intelligence import IndexEntryModel, IndexPinModel, IndexProjectionModel, IndexSnapshotModel, IndexTreeModel, IndexWriterModel
from app.security.redaction import contains_secrets, redact_secrets


def identity(*values: str) -> str:
    return hashlib.sha256(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def redact_projection(value):
    """Keep structured authority fields while redacting literal repository data."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {redact_secrets(str(key)): redact_projection(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_projection(item) for item in value]
    return value


@dataclass(frozen=True)
class IndexLimits:
    max_files: int = 100_000
    max_source_bytes: int = 52_428_800
    max_file_bytes: int = 1_048_576
    max_projection_bytes: int = 2_097_152
    max_seconds: float = 240
    max_depth: int = 64
    max_path_bytes: int = 512
    page_size: int = 64
    manifest_files: int = 512
    manifest_bytes: int = 4_194_304
    min_free_disk_bytes: int = 67_108_864
    max_database_bytes: int = 2_147_483_648
    retention_seconds: int = 604_800
    gc_rows: int = 256
    gc_seconds: float = 2
    query_vm_steps: int = 200_000
    query_seconds: float = 0.25

    def __post_init__(self):
        if any(value <= 0 for value in vars(self).values()):
            raise ValueError("index bounds must be positive")


class PersistentIndex:
    """A tenant/repository-scoped view; snapshot membership is never inferred."""

    def __init__(self, db: Session, *, tenant_id: str, repository_url: str,
                 repo_dir: str, commit_sha: str, limits: IndexLimits = IndexLimits()):
        if not tenant_id or len(tenant_id.encode("utf-8")) > 128:
            raise ValueError("index tenant is required")
        self.db = db
        self.tenant_id = tenant_id
        self.repository_url = repository_url
        self.repository_id = identity(repository_url)
        self.repo_dir = repo_dir
        self.commit_sha = GitInventory.validate_oid(commit_sha)
        self.limits = limits
        root = Path(__file__).resolve().parents[1]
        producer = source_fingerprint(
            str(root / "ingestion" / "parser.py"),
            str(root / "ingestion" / "classification.py"),
            str(root / "indexing" / "persistent.py"),
            str(root / "indexing" / "chunker.py"),
            str(root / "indexing" / "facts.py"),
            str(root / "indexing" / "components.py"),
            str(root / "retrieval" / "tokens.py"),
            str(root / "semantics" / "builder.py"),
            str(root / "semantics" / "flow.py"),
            str(root / "semantics" / "schemas.py"),
            str(root / "specialist_candidates.py"),
            str(root / "graph" / "builder.py"),
            str(root / "graph" / "repository_graph.py"),
            str(root / "graph" / "persistent.py"),
            str(root / "graph" / "imports.py"),
            str(root / "graph" / "module_resolution.py"),
            str(root / "security" / "redaction.py"),
        )
        if not producer:
            raise InventoryBound("extraction_authority_unavailable")
        try:
            parser_versions = [version(name) for name in ("tree-sitter", "tree-sitter-python", "tree-sitter-javascript", "tree-sitter-typescript")]
        except PackageNotFoundError as exc:
            raise InventoryBound("parser_version_authority_unavailable") from exc
        self.producer = identity(producer, CLASSIFICATION_VERSION, *parser_versions, str(limits.max_file_bytes), str(limits.max_projection_bytes), str(limits.max_path_bytes))
        self.inventory = GitInventory(repo_dir)
        self._component_resolver = None
        self.snapshot_id = identity(tenant_id, self.repository_id, commit_sha, self.producer)
        self.base_snapshot_id = self.snapshot_id
        self.entry_limits = {}
        self.building = True
        self.stats = {"discovered_files": 0, "indexed_files": 0, "reused_files": 0,
                      "parsed_files": 0, "source_bytes_read": 0, "excluded_by_reason": {},
                      "inventory_complete": False, "manifest_truncated": False}
        self.query_coverage = {}
        self.pending_entries = 0
        self.writer_id = identity(self.tenant_id, self.repository_id, "catalog-writer")
        self.writer_token = uuid4().hex
        self.writer_owned = False

    def _acquire_writer(self):
        now = time.time()
        try:
            if self.db.get_bind().dialect.name == "postgresql":
                self.db.execute(text("SELECT set_config('lock_timeout', :budget, true)"),
                    {"budget": str(max(1, int(self.limits.query_seconds * 1000))) + "ms"})
            changed = self.db.execute(update(IndexWriterModel).where(IndexWriterModel.id == self.writer_id,
                IndexWriterModel.expires_at <= now).values(token=self.writer_token, expires_at=now + 300)).rowcount
        except DBAPIError as exc:
            self.db.rollback()
            code = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
            if code in {"55P03", "57014"}:
                raise InventoryBound("index_writer_busy") from exc
            raise
        if not changed:
            try:
                with self.db.begin_nested():
                    self.db.add(IndexWriterModel(id=self.writer_id, token=self.writer_token, expires_at=now + 300))
                    self.db.flush()
            except IntegrityError as exc:
                self.db.rollback()
                raise InventoryBound("index_writer_busy") from exc
        self.db.commit()
        self.writer_owned = True

    def _release_writer(self):
        if self.writer_owned:
            self.db.rollback()
            self.db.execute(update(IndexWriterModel).where(IndexWriterModel.id == self.writer_id,
                IndexWriterModel.token == self.writer_token).values(expires_at=0))
            self.db.commit()
            self.writer_owned = False

    def _fence_writer(self) -> None:
        if self.writer_owned:
            now = time.time()
            # Lock/fence the catalog writer before flushing projection rows.
            with self.db.no_autoflush:
                owned = self.db.execute(update(IndexWriterModel).where(IndexWriterModel.id == self.writer_id,
                    IndexWriterModel.token == self.writer_token, IndexWriterModel.expires_at > now)
                    .values(expires_at=now + 300)).rowcount
            if not owned:
                self.db.rollback()
                raise InventoryBound("index_writer_lease_lost")

    def _commit(self, *, force: bool = False) -> None:
        if not force and self.pending_entries < self.limits.page_size:
            return
        self._fence_writer()
        from app.execution.context import current_claim
        claim = current_claim()
        if claim is not None:
            if claim.tenant_id != self.tenant_id:
                raise InventoryBound("execution_tenant_mismatch")
            from app.execution.engine import DurableExecutionEngine
            result = DurableExecutionEngine(self.db, auto_commit=False).heartbeat(claim.work_item_id, claim.lease_token)
            if not result.active or result.cancel_requested or result.budget_exhausted:
                self.db.rollback()
                raise InventoryBound("execution_admission_stopped")
        self.db.commit()
        self.pending_entries = 0

    def _tree_id(self, object_id: str, path: str) -> str:
        component = self._component_identity((path + "/" if path else "") + "__component_probe__.py")
        return identity(self.tenant_id, self.repository_id, self.producer, object_id, path, json.dumps(component, sort_keys=True))

    def _component_identity(self, path):
        if self._component_resolver is None:
            from app.indexing.components import ComponentResolver
            self._component_resolver = ComponentResolver(self.inventory, self.commit_sha)
        return self._component_resolver.file_identity(path)

    def _tree(self, object_id: str, path: str) -> IndexTreeModel:
        tree_id = self._tree_id(object_id, path)
        tree = self.db.get(IndexTreeModel, tree_id)
        if tree is None:
            tree = IndexTreeModel(id=tree_id, tenant_id=self.tenant_id, repository_id=self.repository_id,
                                  object_id=object_id, path=path, cursor="", complete=False, coverage={}, entry_count=0)
            self.db.add(tree)
            self.db.flush()
        elif tree.tenant_id != self.tenant_id or tree.repository_id != self.repository_id:
            raise InventoryBound("index_scope_mismatch")
        return tree

    def snapshot(self) -> IndexSnapshotModel:
        value = self.db.get(IndexSnapshotModel, self.snapshot_id)
        if value is None or value.tenant_id != self.tenant_id or value.repository_id != self.repository_id:
            raise InventoryBound("snapshot_not_in_scope")
        return value

    def _check_budget(self):
        if time.monotonic() >= self.deadline:
            raise InventoryBound("index_time_budget")
        if self.new_entries >= self.limits.max_files:
            raise InventoryBound("inventory_file_budget")
        database = self.db.get_bind().url.database
        storage_path = Path(database).resolve().parent if self.db.get_bind().dialect.name == "sqlite" and database and database != ":memory:" else Path(self.repo_dir)
        if shutil.disk_usage(storage_path).free < self.limits.min_free_disk_bytes:
            raise InventoryBound("index_disk_backpressure")

    def _check_storage_capacity(self, *, reserve_bytes: int | None = None):
        dialect = self.db.get_bind().dialect.name
        if dialect == "sqlite":
            pages = self.db.scalar(text("PRAGMA page_count"))
            reusable = self.db.scalar(text("PRAGMA freelist_count"))
            size = self.db.scalar(text("PRAGMA page_size"))
            used = (pages - reusable) * size
        elif dialect == "postgresql":
            # Bound RepoLens catalog amplification, not unrelated schemas in a
            # shared production database.
            used = self.db.scalar(text("""
                SELECT COALESCE(SUM(pg_total_relation_size(relation)), 0)
                FROM unnest(ARRAY[
                    to_regclass('index_writers'), to_regclass('index_snapshots'),
                    to_regclass('index_trees'), to_regclass('index_entries'),
                    to_regclass('index_projections'), to_regclass('index_facts'),
                    to_regclass('index_postings'), to_regclass('index_signals'),
                    to_regclass('index_pins')
                ]) AS relations(relation)
                WHERE relation IS NOT NULL
            """))
        else:
            raise InventoryBound("database_size_authority_unavailable")
        self.stats["database_used_bytes"] = used
        self.stats["database_byte_limit"] = self.limits.max_database_bytes
        # Reserve a bounded file projection plus its facts before extraction.
        # SQLite free pages are reusable; no blocking VACUUM is necessary.
        reservation = self.limits.max_projection_bytes * 4 if reserve_bytes is None else reserve_bytes
        if used + reservation > self.limits.max_database_bytes:
            raise InventoryBound("index_database_byte_budget")

    def query_rows(self, statement, *, scalars: bool = False):
        """Bound database work as well as returned rows; interruptions are unknown."""
        dialect = self.db.get_bind().dialect.name
        connection = None
        started = time.monotonic()
        steps = 0

        def stop():
            nonlocal steps
            steps += 1000
            return int(steps >= self.limits.query_vm_steps or time.monotonic() - started >= self.limits.query_seconds)

        try:
            if dialect == "sqlite":
                connection = self.db.connection().connection.driver_connection
                connection.set_progress_handler(stop, 1000)
                result = self.db.execute(statement)
                return result.scalars().all() if scalars else result.all()
            if dialect == "postgresql":
                with self.db.begin_nested():
                    prior = self.db.scalar(text("SHOW statement_timeout"))
                    self.db.execute(text("SELECT set_config('statement_timeout', :budget, true)"),
                        {"budget": str(max(1, int(self.limits.query_seconds * 1000))) + "ms"})
                    result = self.db.execute(statement)
                    rows = result.scalars().all() if scalars else result.all()
                    self.db.execute(text("SELECT set_config('statement_timeout', :prior, true)"), {"prior": prior})
                    return rows
            raise InventoryBound("query_budget_authority_unavailable")
        except DBAPIError as exc:
            code = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
            if str(exc.orig).lower() != "interrupted" and code != "57014":
                raise
            self.stats["query_budget_exhaustions"] = self.stats.get("query_budget_exhaustions", 0) + 1
            self.query_coverage["query_budget_exhausted"] = True
            return []
        finally:
            if connection is not None:
                connection.set_progress_handler(None, 0)

    def _entries(self, tree_id: str) -> Iterator[IndexEntryModel]:
        cursor = ""
        while True:
            statement = select(IndexEntryModel).where(
                IndexEntryModel.tree_id == tree_id, IndexEntryModel.name > cursor,
            )
            if not self.building and tree_id in self.entry_limits:
                statement = statement.where(IndexEntryModel.ordinal <= self.entry_limits[tree_id])
            page = self.db.execute(statement.order_by(IndexEntryModel.name).limit(self.limits.page_size)).scalars().all()
            if not page:
                return
            for entry in page:
                yield entry
            cursor = page[-1].name

    def _project(self, entry, path: str) -> tuple[str | None, str, str, int]:
        language = detect_language(entry.name)
        disposition = classify_file(path, language=language, mode=entry.mode)
        if not disposition.eligible:
            return None, disposition.classification.value, disposition.reason, 0
        component = self._component_identity(path)
        projection_id = identity(self.tenant_id, self.repository_id, self.producer, path, entry.object_id,
            json.dumps(component, sort_keys=True))
        prior = self.db.get(IndexProjectionModel, projection_id)
        if prior is not None:
            self.stats["reused_files"] += 1
            reason = "indexed_partial" if prior.payload.get("facts_coverage", {}).get("status") == "PARTIAL" else "indexed"
            return prior.id, disposition.classification.value, reason, prior.payload["file"]["size_bytes"]
        self._check_storage_capacity()
        remaining = self.limits.max_source_bytes - self.stats["source_bytes_read"]
        if remaining <= 0:
            raise InventoryBound("index_source_byte_budget")
        try:
            source = self.inventory.read_object(entry.object_id, kind="blob", max_bytes=min(remaining, self.limits.max_file_bytes))
        except InventoryBound as exc:
            if str(exc) != "object_byte_limit":
                raise
            if remaining < self.limits.max_file_bytes:
                raise InventoryBound("index_source_byte_budget") from exc
            return None, disposition.classification.value, "exceeds_max_size", 0
        self.stats["source_bytes_read"] += len(source)
        disposition = classify_file(path, language=language, sample=source[:4096], mode=entry.mode)
        if not disposition.eligible:
            return None, disposition.classification.value, disposition.reason, len(source)
        try:
            symbols, calls = parse_file_with_calls(path, language, source) if language in {"python", "javascript", "typescript", "tsx"} else ([], [])
        except RecursionError:
            return None, disposition.classification.value, "parser_depth_budget", len(source)
        file = FileEntry(path=path, language=language, size_bytes=len(source),
                         lines_count=len(source.splitlines()), symbols=symbols, calls=calls)
        digest = hashlib.sha256(source).hexdigest()
        payload = {"file": redact_projection(file.model_dump(mode="json")), "source_sha256": digest, "component": component}
        payload_size = len(json.dumps(payload, ensure_ascii=False).encode())
        if payload_size > self.limits.max_projection_bytes:
            return None, disposition.classification.value, "projection_byte_limit", len(source)
        projection = IndexProjectionModel(id=projection_id, tenant_id=self.tenant_id,
                    repository_id=self.repository_id, content_hash=digest,
                    producer_digest=self.producer, payload=payload, payload_bytes=payload_size)
        try:
            with self.db.begin_nested():
                self.db.add(projection)
                self.db.flush()
                from app.indexing.facts import persist_facts
                facts_coverage = persist_facts(self, projection, file, source)
                projection.payload = {**payload, "facts_coverage": facts_coverage}
        except InventoryBound as exc:
            if str(exc) != "projection_fact_byte_limit":
                raise
            return None, disposition.classification.value, "projection_fact_byte_limit", len(source)
        self.stats["parsed_files"] += 1
        return projection_id, disposition.classification.value, "indexed_partial" if facts_coverage["status"] == "PARTIAL" else "indexed", len(source)

    def _walk(self, object_id: str, path: str = "", depth: int = 0) -> Iterator[IndexEntryModel]:
        if depth > self.limits.max_depth:
            raise InventoryBound("inventory_depth_budget")
        tree = self._tree(object_id, path)
        if tree.complete:
            return
        # Git output is streamed. Already committed entries are skipped by
        # primary-key lookup; no extraction or counters are replayed twice.
        reached_cursor = not bool(tree.cursor)
        for item in self.inventory.entries(object_id):
            if not reached_cursor:
                reached_cursor = item.name == tree.cursor
                continue
            self._check_budget()
            item_path = f"{path}/{item.name}" if path else item.name
            if contains_secrets(item_path):
                raise InventoryBound("sensitive_path_excluded")
            if len(item_path.encode("utf-8")) > self.limits.max_path_bytes:
                raise InventoryBound("inventory_path_limit")
            entry = self.db.get(IndexEntryModel, (tree.id, item.name))
            if entry is None:
                # Excluded files and directory-only trees also consume catalog
                # space. Bound their pending page before creating metadata.
                self._check_storage_capacity(reserve_bytes=max(16_384,
                    self.limits.max_path_bytes * self.limits.page_size * 4))
            if item.kind == "tree":
                child = self._tree(item.object_id, item_path)
                if entry is None:
                    tree.entry_count += 1
                    entry = IndexEntryModel(tree_id=tree.id, name=item.name, path=item_path,
                        object_id=item.object_id, mode=item.mode, child_tree_id=child.id,
                        classification="DIRECTORY", reason="inventory", size_bytes=0, ordinal=tree.entry_count)
                    self.db.add(entry)
                    self.new_entries += 1
                    self._commit(force=True)
                disposition = classify_file(item_path + "/__inventory__.py", language="python")
                if not disposition.eligible:
                    child.complete = True
                    child.coverage = {"discovered_files": 0, "indexed_files": 0, "total_bytes": 0,
                        "excluded_by_reason": {}, "excluded_subtrees": {disposition.reason: 1}}
                else:
                    yield from self._walk(item.object_id, item_path, depth + 1)
                tree.cursor = item.name
                self._commit(force=True)
                continue
            if entry is None:
                projection, category, reason, size = self._project(item, item_path)
                tree.entry_count += 1
                entry = IndexEntryModel(tree_id=tree.id, name=item.name, path=item_path,
                    object_id=item.object_id, mode=item.mode, projection_id=projection,
                    classification=category, reason=reason, size_bytes=size, ordinal=tree.entry_count)
                self.db.add(entry)
                tree.cursor = item.name
                self.pending_entries += 1
                self._commit()
                self.new_entries += 1
            elif entry.projection_id:
                self.stats["reused_files"] += 1
            self.stats["discovered_files"] += 1
            yield entry
        tree.complete = True
        self._summarize_tree(tree)
        self._commit(force=True)

    def _summarize_tree(self, tree: IndexTreeModel) -> dict:
        if not tree.complete:
            self.entry_limits[tree.id] = tree.entry_count
        counts = {"discovered_files": 0, "indexed_files": 0, "total_bytes": 0, "partial_files": 0, "excluded_by_reason": {}, "excluded_subtrees": {}}
        for entry in self._entries(tree.id):
            if entry.child_tree_id:
                child = self.db.get(IndexTreeModel, entry.child_tree_id)
                child_counts = child.coverage if child.complete else self._summarize_tree(child)
                for field in ("discovered_files", "indexed_files", "total_bytes", "partial_files"):
                    counts[field] += child_counts.get(field, 0)
                for reason, count in child_counts.get("excluded_by_reason", {}).items():
                    counts["excluded_by_reason"][reason] = counts["excluded_by_reason"].get(reason, 0) + count
                for reason, count in child_counts.get("excluded_subtrees", {}).items():
                    counts["excluded_subtrees"][reason] = counts["excluded_subtrees"].get(reason, 0) + count
            else:
                counts["discovered_files"] += 1
                counts["total_bytes"] += entry.size_bytes
                if entry.projection_id:
                    counts["indexed_files"] += 1
                    counts["partial_files"] += entry.reason == "indexed_partial"
                else:
                    counts["excluded_by_reason"][entry.reason] = counts["excluded_by_reason"].get(entry.reason, 0) + 1
        tree.coverage = counts
        return counts

    def iter_files(self, tree_id: str | None = None, *, depth: int = 0) -> Iterator[IndexEntryModel]:
        if depth > self.limits.max_depth:
            raise InventoryBound("inventory_depth_budget")
        tree_id = tree_id or self.snapshot().root_tree_id
        for entry in self._entries(tree_id):
            if entry.child_tree_id:
                yield from self.iter_files(entry.child_tree_id, depth=depth + 1)
            else:
                yield entry

    def build_manifest(self, *, branch: str | None = None) -> RepositoryManifest:
        self._acquire_writer()
        try:
            from app.indexing.retention import collect_catalog
            self.stats["retention"] = collect_catalog(self)
            return self._build_manifest(branch=branch)
        finally:
            self._release_writer()

    def _build_manifest(self, *, branch: str | None = None) -> RepositoryManifest:
        self.building = True
        self.entry_limits = {}
        self.deadline = time.monotonic() + self.limits.max_seconds
        self.new_entries = 0
        root_oid = self.inventory.root_tree(self.commit_sha)
        root = self._tree(root_oid, "")
        snapshot = self.db.get(IndexSnapshotModel, self.snapshot_id)
        if snapshot is None:
            snapshot = IndexSnapshotModel(id=self.snapshot_id, tenant_id=self.tenant_id,
                repository_id=self.repository_id, commit_sha=self.commit_sha,
                policy_digest=self.producer, root_tree_id=root.id, status="BUILDING", coverage={})
            self.db.add(snapshot)
            self._commit(force=True)
        else:
            snapshot.accessed_at = time.time()
        files: list[FileEntry] = []
        active_bytes = 0
        languages: dict[str, int] = {}
        reason = None
        try:
            for _ in self._walk(root_oid):
                pass
            self.stats["inventory_complete"] = True
        except (InventoryBound, UnicodeError) as exc:
            self._commit(force=True)
            reason = str(exc) if isinstance(exc, InventoryBound) else "unsupported_path_encoding"
        root = self.db.get(IndexTreeModel, root.id)
        self.stats.update(root.coverage if root.complete else self._summarize_tree(root))
        self.stats["reused_files"] = max(0, self.stats["indexed_files"] - self.stats["parsed_files"])
        for entry in self.iter_files():
            if entry.projection_id:
                projection = self.db.get(IndexProjectionModel, entry.projection_id)
                if active_bytes + projection.payload_bytes > self.limits.manifest_bytes:
                    break
                active_bytes += projection.payload_bytes
                file = FileEntry.model_validate(projection.payload["file"])
                files.append(file)
                if file.language:
                    languages[file.language] = languages.get(file.language, 0) + 1
                if len(files) >= self.limits.manifest_files:
                    break
        self.stats["manifest_truncated"] = self.stats["indexed_files"] > len(files)
        partial_reasons = {"projection_fact_byte_limit", "projection_byte_limit", "exceeds_max_size", "parser_depth_budget"}
        self.stats["extraction_partial"] = bool(self.stats.get("partial_files") or partial_reasons.intersection(self.stats["excluded_by_reason"]))
        self.stats["stop_reason"] = reason
        self.snapshot_id = identity(self.base_snapshot_id, json.dumps(self.entry_limits, sort_keys=True))
        snapshot = self.db.get(IndexSnapshotModel, self.snapshot_id)
        if snapshot is None:
            snapshot = IndexSnapshotModel(id=self.snapshot_id, tenant_id=self.tenant_id,
                repository_id=self.repository_id, commit_sha=self.commit_sha,
                policy_digest=self.producer, root_tree_id=root.id, status="SEALED",
                coverage={**self.stats, "entry_limits": dict(self.entry_limits)})
            self.db.add(snapshot)
        else:
            snapshot.accessed_at = time.time()
        self._commit(force=True)
        self.building = False
        from app.ingestion.detector import detect_frameworks
        return RepositoryManifest(repository_url=self.repository_url, commit_hash=self.commit_sha,
            commit_sha=self.commit_sha, branch=branch, files=files,
            total_files=self.stats["discovered_files"], total_size_bytes=self.stats["total_bytes"],
            languages=languages, frameworks=detect_frameworks(self.repo_dir),
            analysis_scope=AnalysisScope(
                truncated=bool(reason or self.stats["manifest_truncated"] or self.stats["extraction_partial"]),
                reason=reason or ("bounded_active_manifest" if self.stats["manifest_truncated"] else "partial_file_extraction" if self.stats["extraction_partial"] else None),
                files_processed=len(files), source_bytes_processed=sum(file.size_bytes for file in files),
                total_observed_files=self.stats["discovered_files"],
                total_observed_bytes=self.stats["total_bytes"],
            ))

    def pin(self, referrer_id: str, *, owner_kind: str = "scan") -> None:
        if owner_kind not in {"scan", "work", "change", "report", "evidence"} or len(referrer_id) > 90:
            raise ValueError("Invalid snapshot pin owner")
        referrer_id = f"{owner_kind}:{referrer_id}"
        self._acquire_writer()
        try:
            self._fence_writer()
            self.snapshot().accessed_at = time.time()
            key = (self.tenant_id, referrer_id, self.snapshot_id)
            if self.db.get(IndexPinModel, key) is None:
                self.db.add(IndexPinModel(tenant_id=self.tenant_id, referrer_id=referrer_id, snapshot_id=self.snapshot_id))
            self._commit(force=True)
        finally:
            self._release_writer()

    def release_pin(self, referrer_id: str, *, owner_kind: str = "scan") -> int:
        """Release all generations owned by one completed domain resource."""
        if owner_kind not in {"scan", "work", "change", "report", "evidence"} or len(referrer_id) > 90:
            raise ValueError("Invalid snapshot pin owner")
        owner = f"{owner_kind}:{referrer_id}"
        self._acquire_writer()
        try:
            self._fence_writer()
            count = self.db.query(IndexPinModel).filter(
                IndexPinModel.tenant_id == self.tenant_id,
                IndexPinModel.referrer_id == owner,
            ).delete(synchronize_session=False)
            self._commit(force=True)
            return int(count or 0)
        finally:
            self._release_writer()

    def open_snapshot(self, snapshot_id: str) -> None:
        """Restore only an immutable generation belonging to this authority."""
        self._acquire_writer()
        try:
            self._fence_writer()
            snapshot = self.db.get(IndexSnapshotModel, snapshot_id, populate_existing=True)
            if (snapshot is None or snapshot.status != "SEALED" or
                    snapshot.tenant_id != self.tenant_id or snapshot.repository_id != self.repository_id or
                    snapshot.commit_sha != self.commit_sha or snapshot.policy_digest != self.producer):
                raise InventoryBound("snapshot_not_in_scope")
            snapshot.accessed_at = time.time()
            self.snapshot_id = snapshot.id
            self.entry_limits = dict(snapshot.coverage.get("entry_limits", {}))
            self.stats = dict(snapshot.coverage)
            self.building = False
            self._commit(force=True)
        finally:
            self._release_writer()

    def file_projection(self, path: str):
        entry = self.file_entry(path)
        if entry is None or not entry.projection_id:
            return None
        projection = self.db.get(IndexProjectionModel, entry.projection_id)
        if (projection is None or projection.tenant_id != self.tenant_id or
                projection.repository_id != self.repository_id or projection.producer_digest != self.producer):
            raise InventoryBound("projection_not_in_scope")
        return projection

    def file_facts(self, path: str, kind: str, *, limit: int = 128):
        from app.models.intelligence import IndexFactModel
        projection = self.file_projection(path)
        if projection is None:
            return []
        return self.db.execute(select(IndexFactModel).where(
            IndexFactModel.projection_id == projection.id, IndexFactModel.kind == kind,
        ).order_by(IndexFactModel.fact_id).limit(limit)).scalars().all()

    def file_entry(self, path: str) -> IndexEntryModel | None:
        parts = path.split("/")
        if len(parts) > self.limits.max_depth or any(part in {"", ".", ".."} for part in parts):
            return None
        tree_id = self.snapshot().root_tree_id
        for position, part in enumerate(parts):
            entry = self.db.get(IndexEntryModel, (tree_id, part))
            if entry is None:
                return None
            if not self.building and tree_id in self.entry_limits and entry.ordinal > self.entry_limits[tree_id]:
                return None
            if position == len(parts) - 1:
                return entry
            if not entry.child_tree_id:
                return None
            tree_id = entry.child_tree_id
        return None

    def load_chunks(self, path: str) -> list[CodeChunk]:
        entry = self.file_entry(path)
        if entry is None or not entry.projection_id:
            return []
        projection = self.db.get(IndexProjectionModel, entry.projection_id)
        if projection is None or projection.tenant_id != self.tenant_id:
            raise InventoryBound("projection_not_in_scope")
        payload = self.inventory.read_object(entry.object_id, kind="blob", max_bytes=self.limits.max_file_bytes)
        if hashlib.sha256(payload).hexdigest() != projection.content_hash:
            raise InventoryBound("source_projection_digest_mismatch")
        return chunk_file(FileEntry.model_validate(projection.payload["file"]), self.commit_sha,
                          payload.decode("utf-8", errors="ignore"))

    def load_chunk(self, chunk_id: str) -> CodeChunk | None:
        from app.models.intelligence import IndexFactModel
        parts = chunk_id.split(":")
        if len(parts) != 4 or parts[0] != "idx" or parts[1] != self.snapshot_id:
            return None
        projection_id, key = parts[2:]
        fact = self.db.get(IndexFactModel, (projection_id, key))
        if fact is None or fact.kind != "CHUNK" or fact.tenant_id != self.tenant_id or fact.repository_id != self.repository_id:
            return None
        entry = self.file_entry(fact.path)
        if entry is None or entry.projection_id != projection_id:
            return None
        projection = self.db.get(IndexProjectionModel, projection_id)
        source = self.inventory.read_object(entry.object_id, kind="blob", max_bytes=self.limits.max_file_bytes)
        if hashlib.sha256(source).hexdigest() != projection.content_hash:
            raise InventoryBound("source_projection_digest_mismatch")
        payload = fact.payload
        lines = source.decode("utf-8", errors="ignore").split("\n")
        content = "\n".join(lines[payload["start_line"] - 1:payload["end_line"]])
        from app.indexing.schemas import content_hash
        if content_hash(content) != payload["content_hash"]:
            raise InventoryBound("chunk_projection_digest_mismatch")
        return CodeChunk.model_validate({**payload, "content": content,
            "chunk_id": chunk_id, "commit_sha": self.commit_sha})
