"""Add workflow_events table for durable workflow events and audit trail.

Revision ID: 005_workflow_events_table
Revises: 004_patch_machine_verdict
Create Date: 2026-08-21 14:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "005_workflow_events_table"
down_revision: Union[str, None] = "004_patch_machine_verdict"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "workflow_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=True),
        sa.Column("patch_id", sa.String(length=36), nullable=True),
        sa.Column("thread_id", sa.String(length=128), nullable=True),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("stage", sa.String(length=64), nullable=True),
        sa.Column("tool_name", sa.String(length=64), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column("model_name", sa.String(length=128), nullable=True),
        sa.Column("message", sa.String(length=1024), nullable=True),
        sa.Column("metadata_payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["patch_id"], ["patches.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_workflow_events_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_workflow_events_event_type"), ["event_type"], unique=False)
        batch_op.create_index(batch_op.f("ix_workflow_events_finding_id"), ["finding_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_workflow_events_patch_id"), ["patch_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_workflow_events_scan_id"), ["scan_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workflow_events_scan_id"))
        batch_op.drop_index(batch_op.f("ix_workflow_events_patch_id"))
        batch_op.drop_index(batch_op.f("ix_workflow_events_finding_id"))
        batch_op.drop_index(batch_op.f("ix_workflow_events_event_type"))
        batch_op.drop_index(batch_op.f("ix_workflow_events_created_at"))
    op.drop_table("workflow_events")
