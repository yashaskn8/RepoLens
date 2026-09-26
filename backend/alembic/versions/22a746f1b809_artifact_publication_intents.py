"""Record and reconcile canonical object writes before SQL registration."""

from alembic import op
import sqlalchemy as sa


revision = "22a746f1b809"
down_revision = "21d8a4f36c10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A READY report is recoverable only when both canonical immutable artifacts
    # are bound. Preserve legacy locator values, but do not leave inconsistent
    # canonical READY rows advertised as complete.
    op.execute(
        "UPDATE reports SET status='FAILED', retryable=FALSE, "
        "failure_code='CANONICAL_REPORT_ARTIFACTS_INCOMPLETE', "
        "failure_message='Canonical report artifacts require operator reconciliation.' "
        "WHERE status='READY' AND (document_artifact_id IS NULL OR document_digest IS NULL)"
    )
    with op.batch_alter_table("reports") as batch:
        batch.drop_constraint("ck_reports_ready_artifact", type_="check")
        batch.create_check_constraint(
            "ck_reports_ready_artifact",
            "status != 'READY' OR (pdf_digest IS NOT NULL AND pdf_artifact_id IS NOT NULL "
            "AND document_digest IS NOT NULL AND document_artifact_id IS NOT NULL AND generated_at IS NOT NULL)",
        )

    op.create_table(
        "artifact_publication_intents",
        sa.Column("artifact_id", sa.String(length=128), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("payload_locator", sa.String(length=1024), nullable=False),
        sa.Column("content_digest", sa.String(length=64), nullable=False),
        sa.Column("payload_size_bytes", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=128), nullable=False),
        sa.Column("artifact_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING','REGISTERED','CLEANED','RETRYABLE_FAILURE')",
            name="ck_artifact_publication_intent_status",
        ),
        sa.CheckConstraint("length(content_digest) = 64", name="ck_artifact_publication_intent_digest"),
        sa.CheckConstraint("payload_size_bytes >= 0", name="ck_artifact_publication_intent_size"),
        sa.CheckConstraint(
            "artifact_type IN ('REPOSITORY_REVISION','ANALYZER_RUN','SCANNER','SYMBOL_INDEX',"
            "'CONTRACT','COVERAGE','EVIDENCE','CLAIM','FINDING','AI_EXECUTION',"
            "'REMEDIATION_RESULT','REPORT_DOCUMENT','PDF_REPORT')",
            name="ck_artifact_publication_intent_type",
        ),
    )
    op.create_index(
        "ix_artifact_publication_intent_reconcile",
        "artifact_publication_intents",
        ["status", "created_at"],
    )
    op.create_index(
        "ix_artifact_publication_intents_tenant_id",
        "artifact_publication_intents",
        ["tenant_id"],
    )
    op.create_index(
        "ix_artifact_publication_intents_status",
        "artifact_publication_intents",
        ["status"],
    )
    op.create_index(
        "ix_artifact_publication_intents_created_at",
        "artifact_publication_intents",
        ["created_at"],
    )


def downgrade() -> None:
    # An unresolved intent may be the only durable record of an object written
    # before its ArtifactModel transaction committed. Dropping it would turn a
    # recoverable publication into a permanent untracked object. Require the
    # reconciler to resolve those records before rolling back this authority.
    unresolved = op.get_bind().execute(
        sa.text(
            "SELECT 1 FROM artifact_publication_intents "
            "WHERE status IN ('PENDING', 'RETRYABLE_FAILURE') LIMIT 1"
        )
    ).first()
    if unresolved is not None:
        raise RuntimeError(
            "Cannot downgrade while unresolved artifact publication intents exist."
        )

    op.drop_index("ix_artifact_publication_intents_created_at", table_name="artifact_publication_intents")
    op.drop_index("ix_artifact_publication_intents_status", table_name="artifact_publication_intents")
    op.drop_index("ix_artifact_publication_intents_tenant_id", table_name="artifact_publication_intents")
    op.drop_index("ix_artifact_publication_intent_reconcile", table_name="artifact_publication_intents")
    op.drop_table("artifact_publication_intents")
    with op.batch_alter_table("reports") as batch:
        batch.drop_constraint("ck_reports_ready_artifact", type_="check")
        batch.create_check_constraint(
            "ck_reports_ready_artifact",
            "status != 'READY' OR (pdf_digest IS NOT NULL AND pdf_artifact_id IS NOT NULL AND generated_at IS NOT NULL)",
        )
