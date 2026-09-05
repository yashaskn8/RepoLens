"""Bounded catalog reclamation and snapshot retention authority."""

import time
from alembic import op
import sqlalchemy as sa

revision = "15e7d4a3b820"
down_revision = "14c381b62a10"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("index_writers", sa.Column("gc_state", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("index_snapshots", sa.Column("accessed_at", sa.Float(), nullable=False, server_default="0"))
    # Give existing snapshots a full retention window following the migration.
    table = sa.table("index_snapshots", sa.column("accessed_at", sa.Float()))
    op.execute(table.update().values(accessed_at=time.time()))
    for name, table_name, columns in (
        ("ix_index_snapshot_scope", "index_snapshots", ["tenant_id", "repository_id", "id"]),
        ("ix_index_snapshot_root", "index_snapshots", ["root_tree_id"]),
        ("ix_index_tree_scope", "index_trees", ["tenant_id", "repository_id", "id"]),
        ("ix_index_projection_scope", "index_projections", ["tenant_id", "repository_id", "id"]),
        ("ix_index_entry_child", "index_entries", ["child_tree_id"]),
        ("ix_index_pin_snapshot", "index_pins", ["snapshot_id"]),
    ):
        op.create_index(name, table_name, columns)


def downgrade():
    for name, table in (
        ("ix_index_pin_snapshot", "index_pins"), ("ix_index_entry_child", "index_entries"),
        ("ix_index_projection_scope", "index_projections"), ("ix_index_tree_scope", "index_trees"),
        ("ix_index_snapshot_root", "index_snapshots"), ("ix_index_snapshot_scope", "index_snapshots"),
    ):
        op.drop_index(name, table_name=table)
    with op.batch_alter_table("index_snapshots") as batch:
        batch.drop_column("accessed_at")
    with op.batch_alter_table("index_writers") as batch:
        batch.drop_column("gc_state")
