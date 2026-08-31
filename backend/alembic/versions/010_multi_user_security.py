"""Add users, user_sessions, usage_counters tables, owner_user_id to scans/change_analyses, and actor_user_id to workflow_events.

Revision ID: 010_multi_user_security
Revises: 009_pr_review_publication
Create Date: 2026-08-31 17:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "010_multi_user_security"
down_revision: Union[str, None] = "009_pr_review_publication"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create users table
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="USER"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_users_id"), ["id"], unique=False)
        batch_op.create_index(batch_op.f("ix_users_email"), ["email"], unique=True)
        batch_op.create_index(batch_op.f("ix_users_role"), ["role"], unique=False)

    # 2. Create user_sessions table
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("user_sessions", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_user_sessions_id"), ["id"], unique=False)
        batch_op.create_index(batch_op.f("ix_user_sessions_user_id"), ["user_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_user_sessions_token_hash"), ["token_hash"], unique=True)

    # 3. Create usage_counters table
    op.create_table(
        "usage_counters",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("bucket_date", sa.Date(), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "bucket_date", "operation", name="uq_usage_user_date_op"),
    )
    with op.batch_alter_table("usage_counters", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_usage_counters_id"), ["id"], unique=False)
        batch_op.create_index(batch_op.f("ix_usage_counters_user_id"), ["user_id"], unique=False)

    # 4. Alter scans table: add owner_user_id
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(sa.Column("owner_user_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_scans_owner_user_id",
            "users",
            ["owner_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(batch_op.f("ix_scans_owner_user_id"), ["owner_user_id"], unique=False)

    # 5. Alter change_analyses table: add owner_user_id
    with op.batch_alter_table("change_analyses", schema=None) as batch_op:
        batch_op.add_column(sa.Column("owner_user_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_change_analyses_owner_user_id",
            "users",
            ["owner_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(batch_op.f("ix_change_analyses_owner_user_id"), ["owner_user_id"], unique=False)

    # 6. Alter workflow_events table: add actor_user_id
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("actor_user_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_workflow_events_actor_user_id",
            "users",
            ["actor_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(batch_op.f("ix_workflow_events_actor_user_id"), ["actor_user_id"], unique=False)


def downgrade() -> None:
    # 1. Clean up workflow_events actor_user_id
    op.execute("UPDATE workflow_events SET actor_user_id = NULL WHERE actor_user_id IS NOT NULL")
    with op.batch_alter_table("workflow_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workflow_events_actor_user_id"))
        batch_op.drop_constraint("fk_workflow_events_actor_user_id", type_="foreignkey")
        batch_op.drop_column("actor_user_id")

    # 2. Clean up change_analyses owner_user_id
    op.execute("UPDATE change_analyses SET owner_user_id = NULL WHERE owner_user_id IS NOT NULL")
    with op.batch_alter_table("change_analyses", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_change_analyses_owner_user_id"))
        batch_op.drop_constraint("fk_change_analyses_owner_user_id", type_="foreignkey")
        batch_op.drop_column("owner_user_id")

    # 3. Clean up scans owner_user_id
    op.execute("UPDATE scans SET owner_user_id = NULL WHERE owner_user_id IS NOT NULL")
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_scans_owner_user_id"))
        batch_op.drop_constraint("fk_scans_owner_user_id", type_="foreignkey")
        batch_op.drop_column("owner_user_id")

    # 4. Drop usage_counters table
    op.drop_table("usage_counters")

    # 5. Drop user_sessions table
    op.drop_table("user_sessions")

    # 6. Drop users table
    op.drop_table("users")
