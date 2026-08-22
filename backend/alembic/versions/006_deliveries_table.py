"""Add deliveries table and workflow_events delivery_id column for Safe GitHub Delivery.

Revision ID: 006_deliveries_table
Revises: 005_workflow_events_table
Create Date: 2026-08-22 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "006_deliveries_table"
down_revision: Union[str, None] = "005_workflow_events_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create deliveries table
    op.create_table(
        "deliveries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("patch_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("repository_url", sa.String(length=512), nullable=False),
        sa.Column("repository_owner", sa.String(length=256), nullable=False),
        sa.Column("repository_name", sa.String(length=256), nullable=False),
        sa.Column("base_branch", sa.String(length=128), nullable=False),
        sa.Column("scanned_base_sha", sa.String(length=64), nullable=False),
        sa.Column("observed_base_sha", sa.String(length=64), nullable=True),
        sa.Column("head_branch", sa.String(length=256), nullable=True),
        sa.Column("head_sha", sa.String(length=64), nullable=True),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("pr_url", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_message", sa.String(length=512), nullable=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["patch_id"], ["patches.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_deliveries_idempotency_key"),
    )
    with op.batch_alter_table("deliveries", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_deliveries_id"), ["id"], unique=False)
        batch_op.create_index(batch_op.f("ix_deliveries_finding_id"), ["finding_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_deliveries_patch_id"), ["patch_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_deliveries_scan_id"), ["scan_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_deliveries_status"), ["status"], unique=False)
        batch_op.create_index(batch_op.f("ix_deliveries_idempotency_key"), ["idempotency_key"], unique=True)

    # 2. Add delivery_id column to workflow_events
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("delivery_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_workflow_events_delivery_id",
            "deliveries",
            ["delivery_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(batch_op.f("ix_workflow_events_delivery_id"), ["delivery_id"], unique=False)


def downgrade() -> None:
    # 1. Remove delivery_id from workflow_events
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workflow_events_delivery_id"))
        batch_op.drop_constraint("fk_workflow_events_delivery_id", type_="foreignkey")
        batch_op.drop_column("delivery_id")

    # 2. Drop deliveries table
    with op.batch_alter_table("deliveries", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_deliveries_idempotency_key"))
        batch_op.drop_index(batch_op.f("ix_deliveries_status"))
        batch_op.drop_index(batch_op.f("ix_deliveries_scan_id"))
        batch_op.drop_index(batch_op.f("ix_deliveries_patch_id"))
        batch_op.drop_index(batch_op.f("ix_deliveries_finding_id"))
        batch_op.drop_index(batch_op.f("ix_deliveries_id"))
    op.drop_table("deliveries")
