"""Add GitHub App installation binding and signed delivery authority."""

from alembic import op
import sqlalchemy as sa

revision = "18b7c2d9a641"
down_revision = "17a4f8c2d901"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("change_analyses", sa.Column("github_app_installation_id", sa.String(length=32), nullable=True))
    op.add_column("change_analyses", sa.Column("github_app_repository_id", sa.String(length=32), nullable=True))
    op.add_column("change_analyses", sa.Column("github_app_pull_number", sa.Integer(), nullable=True))
    op.create_index("ix_change_analyses_github_app_installation_id", "change_analyses", ["github_app_installation_id"])
    op.create_index("ix_change_analyses_github_app_repository_id", "change_analyses", ["github_app_repository_id"])

    op.create_table(
        "github_app_installations",
        sa.Column("installation_id", sa.String(length=32), primary_key=True),
        sa.Column("account_id", sa.String(length=32), nullable=False),
        sa.Column("account_login", sa.String(length=256), nullable=False),
        sa.Column("account_type", sa.String(length=32), nullable=False),
        sa.Column("permissions_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "permissions_digest",
            sa.String(length=64),
            nullable=False,
            server_default="44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        ),
        sa.Column("owner_user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="UNBOUND"),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_github_app_installations_account_id", "github_app_installations", ["account_id"])
    op.create_index("ix_github_app_installations_owner_user_id", "github_app_installations", ["owner_user_id"])
    op.create_index("ix_github_app_installations_status", "github_app_installations", ["status"])

    op.create_table(
        "github_app_repositories",
        sa.Column("repository_id", sa.String(length=32), primary_key=True),
        sa.Column("installation_id", sa.String(length=32), sa.ForeignKey("github_app_installations.installation_id", ondelete="CASCADE"), nullable=False),
        sa.Column("owner_login", sa.String(length=256), nullable=False),
        sa.Column("repository_name", sa.String(length=256), nullable=False),
        sa.Column("is_private", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_github_app_repositories_installation_id", "github_app_repositories", ["installation_id"])
    op.create_index("ix_github_app_repositories_active", "github_app_repositories", ["active"])

    op.create_table(
        "github_app_oauth_states",
        sa.Column("state_digest", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("verifier_ciphertext", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", name="uq_github_app_oauth_user"),
    )
    op.create_index("ix_github_app_oauth_states_user_id", "github_app_oauth_states", ["user_id"])
    op.create_index("ix_github_app_oauth_states_expires_at", "github_app_oauth_states", ["expires_at"])

    op.create_table(
        "github_app_binding_grants",
        sa.Column("grant_digest", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("installation_ids_json", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", name="uq_github_app_binding_grant_user"),
    )
    op.create_index("ix_github_app_binding_grants_user_id", "github_app_binding_grants", ["user_id"])
    op.create_index("ix_github_app_binding_grants_expires_at", "github_app_binding_grants", ["expires_at"])

    op.create_table(
        "github_app_webhook_deliveries",
        sa.Column("delivery_id", sa.String(length=128), primary_key=True),
        sa.Column("body_sha256", sa.String(length=64), nullable=False),
        sa.Column("event_name", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=True),
        sa.Column("installation_id", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="RECEIVED"),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_github_app_webhook_deliveries_installation_id", "github_app_webhook_deliveries", ["installation_id"])
    op.create_index("ix_github_app_webhook_deliveries_status", "github_app_webhook_deliveries", ["status"])
    op.create_index("ix_github_app_webhook_deliveries_received_at", "github_app_webhook_deliveries", ["received_at"])

    op.create_table(
        "github_app_pull_request_heads",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("installation_id", sa.String(length=32), sa.ForeignKey("github_app_installations.installation_id", ondelete="CASCADE"), nullable=False),
        sa.Column("repository_id", sa.String(length=32), sa.ForeignKey("github_app_repositories.repository_id", ondelete="CASCADE"), nullable=False),
        sa.Column("pull_number", sa.Integer(), nullable=False),
        sa.Column("base_sha", sa.String(length=40), nullable=False),
        sa.Column("head_sha", sa.String(length=40), nullable=False),
        sa.Column("head_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_analysis_id", sa.String(length=36), sa.ForeignKey("change_analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("installation_id", "repository_id", "pull_number", name="uq_github_app_pr_identity"),
    )
    op.create_index("ix_github_app_pull_request_heads_installation_id", "github_app_pull_request_heads", ["installation_id"])
    op.create_index("ix_github_app_pull_request_heads_repository_id", "github_app_pull_request_heads", ["repository_id"])


def downgrade() -> None:
    op.drop_index("ix_github_app_pull_request_heads_repository_id", table_name="github_app_pull_request_heads")
    op.drop_index("ix_github_app_pull_request_heads_installation_id", table_name="github_app_pull_request_heads")
    op.drop_table("github_app_pull_request_heads")
    op.drop_index("ix_github_app_binding_grants_expires_at", table_name="github_app_binding_grants")
    op.drop_index("ix_github_app_binding_grants_user_id", table_name="github_app_binding_grants")
    op.drop_table("github_app_binding_grants")
    op.drop_index("ix_github_app_webhook_deliveries_received_at", table_name="github_app_webhook_deliveries")
    op.drop_index("ix_github_app_webhook_deliveries_status", table_name="github_app_webhook_deliveries")
    op.drop_index("ix_github_app_webhook_deliveries_installation_id", table_name="github_app_webhook_deliveries")
    op.drop_table("github_app_webhook_deliveries")
    op.drop_index("ix_github_app_oauth_states_expires_at", table_name="github_app_oauth_states")
    op.drop_index("ix_github_app_oauth_states_user_id", table_name="github_app_oauth_states")
    op.drop_table("github_app_oauth_states")
    op.drop_index("ix_github_app_repositories_active", table_name="github_app_repositories")
    op.drop_index("ix_github_app_repositories_installation_id", table_name="github_app_repositories")
    op.drop_table("github_app_repositories")
    op.drop_index("ix_github_app_installations_status", table_name="github_app_installations")
    op.drop_index("ix_github_app_installations_owner_user_id", table_name="github_app_installations")
    op.drop_index("ix_github_app_installations_account_id", table_name="github_app_installations")
    op.drop_table("github_app_installations")
    op.drop_index("ix_change_analyses_github_app_repository_id", table_name="change_analyses")
    op.drop_index("ix_change_analyses_github_app_installation_id", table_name="change_analyses")
    op.drop_column("change_analyses", "github_app_pull_number")
    op.drop_column("change_analyses", "github_app_repository_id")
    op.drop_column("change_analyses", "github_app_installation_id")
