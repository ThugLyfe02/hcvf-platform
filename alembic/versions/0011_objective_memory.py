"""objective_memory: cross-objective recipes per host

Revision ID: 0011_objective_memory
Revises: 0010_autonomy_rules
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_objective_memory"
down_revision: str | None = "0010_autonomy_rules"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "objective_memory",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("template", sa.String(length=32), nullable=False),
        sa.Column("probe_id", sa.String(length=64), nullable=False),
        sa.Column("route_role", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("findings", sa.Integer(), nullable=False),
        sa.Column("verified", sa.Integer(), nullable=False),
        sa.Column("refuted", sa.Integer(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("productive", sa.Boolean(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "host", "template", "probe_id", "route_role", name="uq_objective_memory_recipe"),
    )
    op.create_index("ix_objective_memory_tenant_id", "objective_memory", ["tenant_id"])
    op.create_index("ix_objective_memory_host", "objective_memory", ["host"])


def downgrade() -> None:
    op.drop_table("objective_memory")
