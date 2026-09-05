"""Tenant-scoped durable tree inventory and immutable extraction projections."""

from sqlalchemy import Boolean, Column, Float, ForeignKey, Index, Integer, JSON, String
import time

from app.models.base import Base


class IndexWriterModel(Base):
    __tablename__ = "index_writers"
    id = Column(String(64), primary_key=True)
    token = Column(String(64), nullable=False)
    expires_at = Column(Float, nullable=False)
    gc_state = Column(JSON, nullable=False, default=dict, server_default="{}")


class IndexSnapshotModel(Base):
    __tablename__ = "index_snapshots"
    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    repository_id = Column(String(64), nullable=False)
    commit_sha = Column(String(64), nullable=False)
    policy_digest = Column(String(64), nullable=False)
    root_tree_id = Column(String(64), nullable=False)
    status = Column(String(16), nullable=False, default="BUILDING")
    coverage = Column(JSON, nullable=False, default=dict)
    accessed_at = Column(Float, nullable=False, default=time.time)
    __table_args__ = (
        Index("ix_index_snapshot_owner", "tenant_id", "repository_id", "commit_sha", "policy_digest"),
        Index("ix_index_snapshot_scope", "tenant_id", "repository_id", "id"),
        Index("ix_index_snapshot_root", "root_tree_id"),
    )


class IndexTreeModel(Base):
    __tablename__ = "index_trees"
    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    repository_id = Column(String(64), nullable=False)
    object_id = Column(String(64), nullable=False)
    path = Column(String(2048), nullable=False)
    cursor = Column(String(1024), nullable=False, default="")
    complete = Column(Boolean, nullable=False, default=False)
    coverage = Column(JSON, nullable=False, default=dict)
    entry_count = Column(Integer, nullable=False, default=0)
    __table_args__ = (Index("ix_index_tree_scope", "tenant_id", "repository_id", "id"),)


class IndexProjectionModel(Base):
    __tablename__ = "index_projections"
    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    repository_id = Column(String(64), nullable=False)
    content_hash = Column(String(64), nullable=False)
    producer_digest = Column(String(64), nullable=False)
    payload = Column(JSON, nullable=False)
    payload_bytes = Column(Integer, nullable=False)
    __table_args__ = (Index("ix_index_projection_scope", "tenant_id", "repository_id", "id"),)


class IndexEntryModel(Base):
    __tablename__ = "index_entries"
    tree_id = Column(String(64), ForeignKey("index_trees.id", ondelete="RESTRICT"), primary_key=True)
    name = Column(String(1024), primary_key=True)
    path = Column(String(2048), nullable=False)
    object_id = Column(String(64), nullable=False)
    mode = Column(String(8), nullable=False)
    ordinal = Column(Integer, nullable=False)
    child_tree_id = Column(String(64), ForeignKey("index_trees.id", ondelete="RESTRICT"), nullable=True)
    projection_id = Column(String(64), ForeignKey("index_projections.id", ondelete="RESTRICT"), nullable=True)
    classification = Column(String(32), nullable=False)
    reason = Column(String(128), nullable=False)
    size_bytes = Column(Integer, nullable=False, default=0)
    __table_args__ = (Index("ix_index_entry_projection", "projection_id"), Index("ix_index_entry_child", "child_tree_id"))


class IndexPinModel(Base):
    __tablename__ = "index_pins"
    tenant_id = Column(String(128), primary_key=True)
    referrer_id = Column(String(128), primary_key=True)
    snapshot_id = Column(String(64), ForeignKey("index_snapshots.id", ondelete="RESTRICT"), primary_key=True)
    __table_args__ = (Index("ix_index_pin_snapshot", "snapshot_id"),)


class IndexFactModel(Base):
    __tablename__ = "index_facts"
    projection_id = Column(String(64), ForeignKey("index_projections.id", ondelete="RESTRICT"), primary_key=True)
    fact_id = Column(String(128), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    repository_id = Column(String(64), nullable=False)
    kind = Column(String(32), nullable=False)
    lookup = Column(String(2048), nullable=False)
    target = Column(String(2048), nullable=False, default="")
    path = Column(String(2048), nullable=False)
    payload = Column(JSON, nullable=False)
    __table_args__ = (
        Index("ix_index_fact_lookup", "tenant_id", "repository_id", "kind", "lookup", "path", "fact_id"),
        Index("ix_index_fact_target", "tenant_id", "repository_id", "kind", "target", "path", "fact_id"),
    )


class IndexPostingModel(Base):
    __tablename__ = "index_postings"
    projection_id = Column(String(64), ForeignKey("index_projections.id", ondelete="RESTRICT"), primary_key=True)
    token = Column(String(128), primary_key=True)
    chunk_key = Column(String(128), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    repository_id = Column(String(64), nullable=False)
    component = Column(String(256), nullable=False)
    path = Column(String(2048), nullable=False)
    frequency = Column(Integer, nullable=False)
    __table_args__ = (Index("ix_index_posting_seek", "tenant_id", "repository_id", "token", "component", "path", "chunk_key"),)


class IndexSignalModel(Base):
    __tablename__ = "index_signals"
    projection_id = Column(String(64), ForeignKey("index_projections.id", ondelete="RESTRICT"), primary_key=True)
    issue_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False)
    repository_id = Column(String(64), nullable=False)
    intent = Column(String(32), nullable=False)
    component = Column(String(256), nullable=False)
    path = Column(String(2048), nullable=False)
    priority = Column(Integer, nullable=False)
    payload = Column(JSON, nullable=False)
    __table_args__ = (Index("ix_index_signal_priority", "tenant_id", "repository_id", "intent", "component", "path", "issue_id"),)
