"""Make canonical report artifacts the durable serving authority."""

from alembic import op
import sqlalchemy as sa


revision = "21d8a4f36c10"
down_revision = "20c1d4a7f922"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Batch DDL keeps this migration executable on SQLite test databases while
    # producing the same nullable references/check constraint on PostgreSQL.
    with op.batch_alter_table("reports") as batch:
        batch.add_column(sa.Column("document_artifact_id", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("pdf_artifact_id", sa.String(length=128), nullable=True))
        batch.create_foreign_key(
            "fk_reports_document_artifact_id_artifacts",
            "artifacts",
            ["document_artifact_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_reports_pdf_artifact_id_artifacts",
            "artifacts",
            ["pdf_artifact_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.alter_column(
            "document_locator",
            existing_type=sa.String(length=1024),
            nullable=True,
        )
    op.create_index("ix_reports_document_artifact_id", "reports", ["document_artifact_id"])
    op.create_index("ix_reports_pdf_artifact_id", "reports", ["pdf_artifact_id"])

    # A legacy READY row without a canonical PDF cannot truthfully remain READY.
    # Keep its local locator/digest for operator-controlled reconciliation.
    op.execute(
        "UPDATE reports SET status='FAILED', retryable=FALSE, "
        "failure_code='LEGACY_ARTIFACT_NOT_CANONICALIZED', "
        "failure_message='Legacy local report artifact requires operator reconciliation.' "
        "WHERE status='READY'"
    )
    with op.batch_alter_table("reports") as batch:
        batch.drop_constraint("ck_reports_ready_artifact", type_="check")
        batch.create_check_constraint(
            "ck_reports_ready_artifact",
            "status != 'READY' OR (pdf_digest IS NOT NULL AND pdf_artifact_id IS NOT NULL AND generated_at IS NOT NULL)",
        )


def downgrade() -> None:
    # The previous schema serves reports from payload_locator. Canonicalized
    # READY reports have no such path, so do not leave them falsely READY.
    op.execute(
        "UPDATE reports SET status='FAILED', retryable=FALSE, "
        "failure_code='CANONICAL_ARTIFACTS_UNAVAILABLE_AFTER_DOWNGRADE', "
        "failure_message='Canonical report artifacts require the current schema.' "
        "WHERE status='READY'"
    )
    op.drop_index("ix_reports_pdf_artifact_id", table_name="reports")
    op.drop_index("ix_reports_document_artifact_id", table_name="reports")
    with op.batch_alter_table("reports") as batch:
        batch.drop_constraint("ck_reports_ready_artifact", type_="check")
        batch.create_check_constraint(
            "ck_reports_ready_artifact",
            "status != 'READY' OR (pdf_digest IS NOT NULL AND payload_locator IS NOT NULL AND generated_at IS NOT NULL)",
        )
        batch.drop_constraint("fk_reports_pdf_artifact_id_artifacts", type_="foreignkey")
        batch.drop_constraint("fk_reports_document_artifact_id_artifacts", type_="foreignkey")
        batch.drop_column("pdf_artifact_id")
        batch.drop_column("document_artifact_id")
        # document_locator remains nullable because canonicalized report rows
        # intentionally discard their local staging locator. A downgrade must
        # not invent a stale filesystem serving authority.
