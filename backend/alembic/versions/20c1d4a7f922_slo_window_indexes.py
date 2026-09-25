"""Index durable work lifecycle timestamps for bounded SLO windows."""

from alembic import op

revision = "20c1d4a7f922"
down_revision = "18b7c2d9a641"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_execution_terminal_window",
        "execution_work_items",
        ["terminal_at", "state"],
    )
    op.create_index(
        "ix_execution_started_window",
        "execution_work_items",
        ["started_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_execution_started_window", table_name="execution_work_items")
    op.drop_index("ix_execution_terminal_window", table_name="execution_work_items")
