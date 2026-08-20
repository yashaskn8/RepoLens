"""Initial schema for scans, findings, and evidences.

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-08-20 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create scans table
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("repository_url", sa.String(length=512), nullable=False),
        sa.Column("branch", sa.String(length=128), nullable=True),
        sa.Column("commit_hash", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("model_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scans_id"), "scans", ["id"], unique=False)
    op.create_index(op.f("ix_scans_repository_url"), "scans", ["repository_url"], unique=False)
    op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)

    # Create findings table
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=True),
        sa.Column("category", sa.String(length=128), nullable=True),
        sa.Column("mitigation_guidance", sa.Text(), nullable=True),
        sa.Column("verification_verdict", sa.String(length=32), nullable=True),
        sa.Column("verification_reason", sa.Text(), nullable=True),
        sa.Column("model_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_id"), "findings", ["id"], unique=False)
    op.create_index(op.f("ix_findings_scan_id"), "findings", ["scan_id"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
    op.create_index(op.f("ix_findings_rule_id"), "findings", ["rule_id"], unique=False)
    op.create_index(op.f("ix_findings_category"), "findings", ["category"], unique=False)

    # Create evidences table
    op.create_table(
        "evidences",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("file_path", sa.String(length=512), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("context_notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_evidences_id"), "evidences", ["id"], unique=False)
    op.create_index(op.f("ix_evidences_finding_id"), "evidences", ["finding_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_evidences_finding_id"), table_name="evidences")
    op.drop_index(op.f("ix_evidences_id"), table_name="evidences")
    op.drop_table("evidences")

    op.drop_index(op.f("ix_findings_category"), table_name="findings")
    op.drop_index(op.f("ix_findings_rule_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_scan_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_id"), table_name="findings")
    op.drop_table("findings")

    op.drop_index(op.f("ix_scans_status"), table_name="scans")
    op.drop_index(op.f("ix_scans_repository_url"), table_name="scans")
    op.drop_index(op.f("ix_scans_id"), table_name="scans")
    op.drop_table("scans")
