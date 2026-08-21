"""Add patch revision lineage and canonical finding provenance columns.

Revision ID: 003_phase36_durability_and_provenance
Revises: 002_patches_table
Create Date: 2026-08-21 09:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "003_phase36_durability_and_provenance"
down_revision: Union[str, None] = "002_patches_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add revision lineage columns to patches table
    with op.batch_alter_table("patches", schema=None) as batch_op:
        batch_op.add_column(sa.Column("parent_patch_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("revision_number", sa.Integer(), nullable=False, server_default="0"))
        batch_op.create_index(batch_op.f("ix_patches_parent_patch_id"), ["parent_patch_id"], unique=True)
        batch_op.create_foreign_key(
            "fk_patches_parent_patch_id",
            "patches",
            ["parent_patch_id"],
            ["id"],
            ondelete="RESTRICT",
        )

    # 2. Add canonical provenance columns to findings table
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("source_tool", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("detector_id", sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column("detector_kind", sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f("ix_findings_source_tool"), ["source_tool"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_detector_id"), ["detector_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_detector_kind"), ["detector_kind"], unique=False)


def downgrade() -> None:
    # 1. Remove provenance columns from findings table
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_findings_detector_kind"))
        batch_op.drop_index(batch_op.f("ix_findings_detector_id"))
        batch_op.drop_index(batch_op.f("ix_findings_source_tool"))
        batch_op.drop_column("detector_kind")
        batch_op.drop_column("detector_id")
        batch_op.drop_column("source_tool")

    # 2. Remove revision lineage columns from patches table
    with op.batch_alter_table("patches", schema=None) as batch_op:
        batch_op.drop_constraint("fk_patches_parent_patch_id", type_="foreignkey")
        batch_op.drop_index(batch_op.f("ix_patches_parent_patch_id"))
        batch_op.drop_column("revision_number")
        batch_op.drop_column("parent_patch_id")
