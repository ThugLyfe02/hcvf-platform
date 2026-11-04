"""agent heartbeats + objective depth

Revision ID: 0014_agent_runtime
Revises: 0013_objective_findings
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_agent_runtime"
down_revision: str | None = "0013_objective_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "objectives", sa.Column("depth", sa.String(length=16), nullable=False, server_default="standard")
    )
    op.alter_column("objectives", "depth", server_default=None)

    op.create_table(
        "agent_heartbeats",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("worker", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="idle"),
        sa.Column("objective_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("task_key", sa.String(length=96), nullable=False, server_default=""),
        sa.Column("completed_tasks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_tasks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", name="uq_agent_heartbeat_id"),
    )
    op.create_index("ix_agent_heartbeats_worker", "agent_heartbeats", ["worker"])
    op.create_index("ix_agent_heartbeats_last_seen", "agent_heartbeats", ["last_seen_at"])
    for column in ("state", "task_key", "completed_tasks", "failed_tasks"):
        op.alter_column("agent_heartbeats", column, server_default=None)


def downgrade() -> None:
    op.drop_table("agent_heartbeats")
    op.drop_column("objectives", "depth")
