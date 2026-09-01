"""complete execution and lifecycle authority

Revision ID: 12d4a8f91c20
Revises: 11b07f8ee574
Create Date: 2026-09-01
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "12d4a8f91c20"
down_revision: Union[str, None] = "11b07f8ee574"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_ARTIFACT_TYPES = (
    "REPOSITORY_REVISION",
    "ANALYZER_RUN",
    "SCANNER",
    "SYMBOL_INDEX",
    "CONTRACT",
    "COVERAGE",
    "EVIDENCE",
    "CLAIM",
    "FINDING",
    "AI_EXECUTION",
    "REMEDIATION_RESULT",
    "REPORT_DOCUMENT",
    "PDF_REPORT",
)


def _artifact_check(values: tuple[str, ...]) -> str:
    return "artifact_type IN ({})".format(",".join(repr(value) for value in values))


def upgrade() -> None:
    with op.batch_alter_table("execution_work_items") as batch_op:
        batch_op.add_column(
            sa.Column("request_payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )

    with op.batch_alter_table("patches") as batch_op:
        batch_op.add_column(sa.Column("generation_work_item_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("result_artifact_id", sa.String(length=128), nullable=True))
        batch_op.create_index(
            "ix_patches_generation_work_item_id", ["generation_work_item_id"], unique=True
        )
        batch_op.create_index("ix_patches_result_artifact_id", ["result_artifact_id"], unique=False)

    with op.batch_alter_table("deliveries") as batch_op:
        batch_op.add_column(sa.Column("request_notes", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("reconciliation_occurred", sa.Boolean(), nullable=False, server_default=sa.false())
        )

    with op.batch_alter_table("artifacts") as batch_op:
        batch_op.drop_constraint("ck_artifact_type", type_="check")
        batch_op.create_check_constraint("ck_artifact_type", _artifact_check(_ARTIFACT_TYPES))


def downgrade() -> None:
    previous_types = tuple(value for value in _ARTIFACT_TYPES if value != "REMEDIATION_RESULT")
    with op.batch_alter_table("artifacts") as batch_op:
        batch_op.drop_constraint("ck_artifact_type", type_="check")
        batch_op.create_check_constraint("ck_artifact_type", _artifact_check(previous_types))

    with op.batch_alter_table("deliveries") as batch_op:
        batch_op.drop_column("reconciliation_occurred")
        batch_op.drop_column("request_notes")

    with op.batch_alter_table("patches") as batch_op:
        batch_op.drop_index("ix_patches_result_artifact_id")
        batch_op.drop_index("ix_patches_generation_work_item_id")
        batch_op.drop_column("result_artifact_id")
        batch_op.drop_column("generation_work_item_id")

    with op.batch_alter_table("execution_work_items") as batch_op:
        batch_op.drop_column("request_payload")
