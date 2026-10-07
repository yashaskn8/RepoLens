"""Bind human approval to the exact patch artifact and scanned revision."""

from alembic import op
import sqlalchemy as sa


revision = "24b9e0a8c1d2"
down_revision = "22a746f1b809"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("patches", sa.Column("approval_digest", sa.String(length=64), nullable=True))
    # Historical approvals did not bind the diff, plan, tenant, or base revision.
    # Fail closed and require explicit re-review before any future delivery.
    op.execute(
        "UPDATE patches SET status='NEEDS_REVIEW', approved_by=NULL, approved_at=NULL "
        "WHERE status='APPROVED'"
    )


def downgrade() -> None:
    # The previous schema cannot represent content-bound approval. Demote any
    # approval created after upgrade before removing its digest, so old delivery
    # code cannot mistake it for a still-authorized approval.
    op.execute(
        "UPDATE patches SET status='NEEDS_REVIEW', approved_by=NULL, approved_at=NULL "
        "WHERE status='APPROVED'"
    )
    op.drop_column("patches", "approval_digest")
