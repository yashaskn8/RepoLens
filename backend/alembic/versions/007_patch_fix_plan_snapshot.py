"""Add fix_plan_snapshot column to patches table.

Revision ID: 007_patch_fix_plan_snapshot
Revises: 006_deliveries_table
Create Date: 2026-08-27 19:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "007_patch_fix_plan_snapshot"
down_revision: Union[str, None] = "006_deliveries_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("patches", sa.Column("fix_plan_snapshot", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("patches", "fix_plan_snapshot")
