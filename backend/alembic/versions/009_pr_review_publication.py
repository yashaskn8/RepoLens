"""Add pr_review_publications table and workflow_events pr_review_publication_id column.

Revision ID: 009_pr_review_publication
Revises: 008_change_analysis_domain
Create Date: 2026-08-31 15:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "009_pr_review_publication"
down_revision: Union[str, None] = "008_change_analysis_domain"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create pr_review_publications table
    op.create_table(
        "pr_review_publications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("repository_owner", sa.String(length=256), nullable=False),
        sa.Column("repository_name", sa.String(length=256), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("base_commit_sha", sa.String(length=40), nullable=False),
        sa.Column("head_commit_sha", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("preview_body", sa.Text(), nullable=True),
        sa.Column("preview_digest", sa.String(length=64), nullable=True),
        sa.Column("inline_comments_payload", sa.JSON(), nullable=True),
        sa.Column("is_truncated", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("truncation_reason", sa.String(length=256), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("github_review_id", sa.BigInteger(), nullable=True),
        sa.Column("github_review_url", sa.String(length=1024), nullable=True),
        sa.Column("reconciliation_occurred", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["change_analyses.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("pr_review_publications", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_pr_review_publications_id"), ["id"], unique=False)
        batch_op.create_index(batch_op.f("ix_pr_review_publications_analysis_id"), ["analysis_id"], unique=True)
        batch_op.create_index(batch_op.f("ix_pr_review_publications_status"), ["status"], unique=False)
        batch_op.create_index(batch_op.f("ix_pr_review_publications_preview_digest"), ["preview_digest"], unique=False)
        batch_op.create_index(batch_op.f("ix_pr_review_publications_created_at"), ["created_at"], unique=False)

    # 2. Alter workflow_events table: add pr_review_publication_id column and foreign key
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("pr_review_publication_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_workflow_events_pr_review_publication_id",
            "pr_review_publications",
            ["pr_review_publication_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            batch_op.f("ix_workflow_events_pr_review_publication_id"),
            ["pr_review_publication_id"],
            unique=False,
        )


def downgrade() -> None:
    # 1. Clean up Phase 7 specific event linkages before dropping foreign key
    op.execute("UPDATE workflow_events SET pr_review_publication_id = NULL WHERE pr_review_publication_id IS NOT NULL")

    # 2. Revert workflow_events changes
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workflow_events_pr_review_publication_id"))
        batch_op.drop_constraint("fk_workflow_events_pr_review_publication_id", type_="foreignkey")
        batch_op.drop_column("pr_review_publication_id")

    # 3. Drop pr_review_publications table
    op.drop_table("pr_review_publications")
