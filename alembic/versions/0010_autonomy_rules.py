"""autonomy: rotation, narrow retry, fleet limits

Revision ID: 0010_autonomy_rules
Revises: 0009_objectives
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_autonomy_rules"
down_revision: str | None = "0009_objectives"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "autonomy_policies", sa.Column("template_auto", sa.Boolean(), nullable=False, server_default=sa.true())
    )
    op.add_column(
        "autonomy_policies", sa.Column("narrow_on_retry", sa.Boolean(), nullable=False, server_default=sa.true())
    )
    op.add_column(
        "autonomy_policies", sa.Column("max_active_objectives", sa.Integer(), nullable=False, server_default="2")
    )
    op.add_column(
        "autonomy_policies",
        sa.Column("daily_objective_requests", sa.Integer(), nullable=False, server_default="400"),
    )
    op.add_column(
        "autonomy_policies",
        sa.Column("template_history", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
    )
    for column in ("template_auto", "narrow_on_retry", "max_active_objectives", "daily_objective_requests",
                   "template_history"):
        op.alter_column("autonomy_policies", column, server_default=None)


def downgrade() -> None:
    for column in ("template_history", "daily_objective_requests", "max_active_objectives", "narrow_on_retry",
                   "template_auto"):
        op.drop_column("autonomy_policies", column)
