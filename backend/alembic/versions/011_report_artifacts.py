"""Add immutable PDF report resources and durable execution leases.

Revision ID: 011_report_artifacts
Revises: 010_multi_user_security
Create Date: 2026-09-01 10:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "011_report_artifacts"
down_revision: Union[str, None] = "010_multi_user_security"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("evidence_digest", sa.String(length=64), nullable=False),
        sa.Column("coverage_digest", sa.String(length=64), nullable=False),
        sa.Column("document_digest", sa.String(length=64), nullable=False),
        sa.Column("document_locator", sa.String(length=1024), nullable=False),
        sa.Column("pdf_digest", sa.String(length=64), nullable=True),
        sa.Column("payload_locator", sa.String(length=1024), nullable=True),
        sa.Column("payload_size_bytes", sa.Integer(), nullable=True),
        sa.Column("page_count", sa.Integer(), nullable=True),
        sa.Column("repository_url", sa.String(length=512), nullable=False),
        sa.Column("branch", sa.String(length=128), nullable=True),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("report_schema_version", sa.String(length=32), nullable=False),
        sa.Column("renderer_version", sa.String(length=128), nullable=False),
        sa.Column("analysis_policy_version", sa.String(length=128), nullable=False),
        sa.Column("application_version", sa.String(length=32), nullable=False),
        sa.Column("coverage_artifact_id", sa.String(length=128), nullable=True),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("artifact_lineage", sa.JSON(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retryable", sa.Boolean(), nullable=False),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_message", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('REQUESTED','ASSEMBLING','RENDERING','READY','FAILED')",
            name="ck_reports_status",
        ),
        sa.CheckConstraint(
            "status != 'READY' OR (pdf_digest IS NOT NULL AND payload_locator IS NOT NULL AND generated_at IS NOT NULL)",
            name="ck_reports_ready_artifact",
        ),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "owner_user_id", "scan_id", "input_digest", "report_schema_version", "renderer_version",
            name="uq_report_canonical_input",
        ),
    )
    for name, columns in (
        ("ix_reports_id", ["id"]),
        ("ix_reports_owner_user_id", ["owner_user_id"]),
        ("ix_reports_scan_id", ["scan_id"]),
        ("ix_reports_status", ["status"]),
        ("ix_reports_input_digest", ["input_digest"]),
        ("ix_reports_lease_owner", ["lease_owner"]),
        ("ix_reports_lease_expires_at", ["lease_expires_at"]),
    ):
        op.create_index(name, "reports", columns, unique=False)


def downgrade() -> None:
    op.drop_table("reports")
