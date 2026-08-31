"""Add change_analyses and change_impacts tables, and workflow_events change_analysis_id column.

Revision ID: 008_change_analysis_domain
Revises: 007_patch_fix_plan_snapshot
Create Date: 2026-08-27 20:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "008_change_analysis_domain"
down_revision: Union[str, None] = "007_patch_fix_plan_snapshot"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create change_analyses table
    op.create_table(
        "change_analyses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("repository_url", sa.String(length=512), nullable=False),
        sa.Column("repository_owner", sa.String(length=256), nullable=False),
        sa.Column("repository_name", sa.String(length=256), nullable=False),
        sa.Column("base_ref", sa.String(length=128), nullable=True),
        sa.Column("base_commit_sha", sa.String(length=40), nullable=False),
        sa.Column("head_ref", sa.String(length=128), nullable=True),
        sa.Column("head_commit_sha", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("changed_files_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("changed_symbols_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("impacted_symbols_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_level", sa.String(length=32), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_message", sa.String(length=512), nullable=True),
        sa.Column("model_metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("change_analyses", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_change_analyses_id"), ["id"], unique=False)
        batch_op.create_index(batch_op.f("ix_change_analyses_base_commit_sha"), ["base_commit_sha"], unique=False)
        batch_op.create_index(batch_op.f("ix_change_analyses_head_commit_sha"), ["head_commit_sha"], unique=False)
        batch_op.create_index(batch_op.f("ix_change_analyses_status"), ["status"], unique=False)
        batch_op.create_index(batch_op.f("ix_change_analyses_created_at"), ["created_at"], unique=False)

    # 2. Create change_impacts table
    op.create_table(
        "change_impacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("impact_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("description", sa.String(length=2048), nullable=False),
        sa.Column("source_file", sa.String(length=512), nullable=True),
        sa.Column("source_symbol", sa.String(length=256), nullable=True),
        sa.Column("affected_file", sa.String(length=512), nullable=True),
        sa.Column("affected_symbol", sa.String(length=256), nullable=True),
        sa.Column("evidence_payload", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("verification_status", sa.String(length=32), nullable=False, server_default="FACT"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["change_analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("change_impacts", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_change_impacts_id"), ["id"], unique=False)
        batch_op.create_index(batch_op.f("ix_change_impacts_analysis_id"), ["analysis_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_change_impacts_impact_type"), ["impact_type"], unique=False)

    # 3. Alter workflow_events table: add change_analysis_id and make scan_id nullable
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("change_analysis_id", sa.String(length=36), nullable=True))
        batch_op.alter_column("scan_id", existing_type=sa.String(length=36), nullable=True)
        batch_op.create_foreign_key(
            "fk_workflow_events_change_analysis_id",
            "change_analyses",
            ["change_analysis_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(batch_op.f("ix_workflow_events_change_analysis_id"), ["change_analysis_id"], unique=False)


def downgrade() -> None:
    # 1. Clean up Phase 6 change-analysis-only events before restoring scan_id NOT NULL
    op.execute("DELETE FROM workflow_events WHERE scan_id IS NULL")

    # Revert workflow_events changes
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workflow_events_change_analysis_id"))
        batch_op.drop_constraint("fk_workflow_events_change_analysis_id", type_="foreignkey")
        batch_op.drop_column("change_analysis_id")
        batch_op.alter_column("scan_id", existing_type=sa.String(length=36), nullable=False)

    # 2. Drop change_impacts table
    with op.batch_alter_table("change_impacts", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_change_impacts_impact_type"))
        batch_op.drop_index(batch_op.f("ix_change_impacts_analysis_id"))
        batch_op.drop_index(batch_op.f("ix_change_impacts_id"))
    op.drop_table("change_impacts")

    # 3. Drop change_analyses table
    with op.batch_alter_table("change_analyses", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_change_analyses_created_at"))
        batch_op.drop_index(batch_op.f("ix_change_analyses_status"))
        batch_op.drop_index(batch_op.f("ix_change_analyses_head_commit_sha"))
        batch_op.drop_index(batch_op.f("ix_change_analyses_base_commit_sha"))
        batch_op.drop_index(batch_op.f("ix_change_analyses_id"))
    op.drop_table("change_analyses")
