"""Add machine_verdict column to patches table.

Revision ID: 004_patch_machine_verdict
Revises: 003_phase36_durability_and_provenance
Create Date: 2026-08-21 12:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "004_patch_machine_verdict"
down_revision: Union[str, None] = "003_phase36_durability_and_provenance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("patches", schema=None) as batch_op:
        batch_op.add_column(sa.Column("machine_verdict", sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("patches", schema=None) as batch_op:
        batch_op.drop_column("machine_verdict")
