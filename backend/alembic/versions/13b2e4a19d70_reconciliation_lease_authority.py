"""reconciliation lease authority

Revision ID: 13b2e4a19d70
Revises: 12d4a8f91c20
Create Date: 2026-09-01
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "13b2e4a19d70"
down_revision: Union[str, None] = "12d4a8f91c20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("reconciliation_records") as batch_op:
        batch_op.add_column(sa.Column("lease_owner", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            )
        )
        batch_op.create_index(
            "ix_reconciliation_records_lease_owner", ["lease_owner"], unique=False
        )
        batch_op.create_index(
            "ix_reconciliation_records_lease_expires_at", ["lease_expires_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("reconciliation_records") as batch_op:
        batch_op.drop_index("ix_reconciliation_records_lease_expires_at")
        batch_op.drop_index("ix_reconciliation_records_lease_owner")
        batch_op.drop_column("updated_at")
        batch_op.drop_column("lease_expires_at")
        batch_op.drop_column("lease_owner")
