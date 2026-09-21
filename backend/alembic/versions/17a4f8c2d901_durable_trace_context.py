"""Persist bounded W3C trace context on durable work items."""

from alembic import op
import sqlalchemy as sa

revision = "17a4f8c2d901"
down_revision = "16c9a2e71f40"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("execution_work_items", sa.Column("traceparent", sa.String(length=55), nullable=True))
    op.add_column("execution_work_items", sa.Column("tracestate", sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column("execution_work_items", "tracestate")
    op.drop_column("execution_work_items", "traceparent")
