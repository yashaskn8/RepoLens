"""Persistent tenant-scoped extraction projections and Git inventory."""

from alembic import op
import sqlalchemy as sa

revision = "14c381b62a10"
down_revision = "13b2e4a19d70"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("index_writers", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("token", sa.String(64), nullable=False), sa.Column("expires_at", sa.Float(), nullable=False))
    op.create_table("index_snapshots",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("repository_id", sa.String(64), nullable=False),
        sa.Column("commit_sha", sa.String(64), nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("root_tree_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("coverage", sa.JSON(), nullable=False))
    op.create_index("ix_index_snapshot_owner", "index_snapshots", ["tenant_id", "repository_id", "commit_sha", "policy_digest"])
    op.create_table("index_trees",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("repository_id", sa.String(64), nullable=False),
        sa.Column("object_id", sa.String(64), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("cursor", sa.String(1024), nullable=False),
        sa.Column("complete", sa.Boolean(), nullable=False),
        sa.Column("coverage", sa.JSON(), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False))
    op.create_table("index_projections",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("repository_id", sa.String(64), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("producer_digest", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_bytes", sa.Integer(), nullable=False))
    op.create_table("index_entries",
        sa.Column("tree_id", sa.String(64), sa.ForeignKey("index_trees.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("name", sa.String(1024), primary_key=True),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("object_id", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("child_tree_id", sa.String(64), sa.ForeignKey("index_trees.id", ondelete="RESTRICT")),
        sa.Column("projection_id", sa.String(64), sa.ForeignKey("index_projections.id", ondelete="RESTRICT")),
        sa.Column("classification", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(128), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False))
    op.create_index("ix_index_entry_projection", "index_entries", ["projection_id"])
    op.create_table("index_pins",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("referrer_id", sa.String(128), primary_key=True),
        sa.Column("snapshot_id", sa.String(64), sa.ForeignKey("index_snapshots.id", ondelete="RESTRICT"), primary_key=True))
    op.create_table("index_facts",
        sa.Column("projection_id", sa.String(64), sa.ForeignKey("index_projections.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("fact_id", sa.String(128), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("repository_id", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("lookup", sa.String(2048), nullable=False),
        sa.Column("target", sa.String(2048), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False))
    for column in ("lookup", "target"):
        op.create_index("ix_index_fact_" + column, "index_facts", ["tenant_id", "repository_id", "kind", column, "path", "fact_id"])
    op.create_table("index_postings",
        sa.Column("projection_id", sa.String(64), sa.ForeignKey("index_projections.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("token", sa.String(128), primary_key=True),
        sa.Column("chunk_key", sa.String(128), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("repository_id", sa.String(64), nullable=False),
        sa.Column("component", sa.String(256), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("frequency", sa.Integer(), nullable=False))
    op.create_index("ix_index_posting_seek", "index_postings", ["tenant_id", "repository_id", "token", "component", "path", "chunk_key"])
    op.create_table("index_signals",
        sa.Column("projection_id", sa.String(64), sa.ForeignKey("index_projections.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("issue_id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("repository_id", sa.String(64), nullable=False),
        sa.Column("intent", sa.String(32), nullable=False),
        sa.Column("component", sa.String(256), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False))
    op.create_index("ix_index_signal_priority", "index_signals", ["tenant_id", "repository_id", "intent", "component", "path", "issue_id"])


def downgrade():
    op.drop_table("index_writers")
    for table in ("index_signals", "index_postings", "index_facts", "index_pins", "index_entries", "index_projections", "index_trees", "index_snapshots"):
        op.drop_table(table)
