"""Add patches table matching PatchModel with foreign keys, indexes, review fields, and metadata.

Revision ID: 002_patches_table
Revises: 001_initial_schema
Create Date: 2026-08-20 22:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "002_patches_table"
down_revision: Union[str, None] = "001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patches",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=True),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("thread_id", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("unified_diff", sa.Text(), nullable=False),
        sa.Column("files_modified", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("expected_behavior_change", sa.Text(), nullable=False),
        sa.Column("generated_tests_or_test_plan", sa.JSON(), nullable=True),
        sa.Column("verification_report", sa.JSON(), nullable=True),
        sa.Column("critic_report", sa.JSON(), nullable=True),
        sa.Column("user_feedback", sa.Text(), nullable=True),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_reason", sa.Text(), nullable=True),
        sa.Column("model_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_patches_id"), "patches", ["id"], unique=False)
    op.create_index(op.f("ix_patches_finding_id"), "patches", ["finding_id"], unique=False)
    op.create_index(op.f("ix_patches_scan_id"), "patches", ["scan_id"], unique=False)
    op.create_index(op.f("ix_patches_thread_id"), "patches", ["thread_id"], unique=False)
    op.create_index(op.f("ix_patches_status"), "patches", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_patches_status"), table_name="patches")
    op.drop_index(op.f("ix_patches_thread_id"), table_name="patches")
    op.drop_index(op.f("ix_patches_scan_id"), table_name="patches")
    op.drop_index(op.f("ix_patches_finding_id"), table_name="patches")
    op.drop_index(op.f("ix_patches_id"), table_name="patches")
    op.drop_table("patches")
