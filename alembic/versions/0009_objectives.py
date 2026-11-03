"""objectives: delegated work, task DAG, workforce events, autonomy mode

Revision ID: 0009_objectives
Revises: 0008_governance
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_objectives"
down_revision: str | None = "0008_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "objectives",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(length=96), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("template", sa.String(length=32), nullable=False, server_default="posture"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("safety_ceiling", sa.String(length=32), nullable=False, server_default="read_only"),
        sa.Column("budget_requests", sa.Integer(), nullable=False, server_default="120"),
        sa.Column("per_task_budget", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("criteria", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("plan", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("verdict", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("requests_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("origin", sa.String(length=32), nullable=False, server_default="delegated"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "key", name="uq_objective_key"),
    )
    op.create_index("ix_objectives_tenant_id", "objectives", ["tenant_id"])
    op.create_index("ix_objectives_status", "objectives", ["status"])
    op.create_index("ix_objectives_tenant_status", "objectives", ["tenant_id", "status"])
    for column in ("description", "template", "status", "safety_ceiling", "budget_requests", "per_task_budget",
                   "priority", "verdict", "requests_used", "created_by", "origin"):
        op.alter_column("objectives", column, server_default=None)

    op.create_table(
        "objective_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("objective_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(length=96), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("kind", sa.String(length=16), nullable=False, server_default="probe"),
        sa.Column("title", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("worker", sa.String(length=64), nullable=False, server_default="config-worker"),
        sa.Column("probe_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("route", sa.String(length=2048), nullable=False, server_default=""),
        sa.Column("depends_on", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("budget_requests", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("safety", sa.String(length=32), nullable=False, server_default="read_only"),
        sa.Column("verify_kind", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("outcome", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("error", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["objective_id"], ["objectives.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("objective_id", "key", name="uq_objective_task_key"),
    )
    op.create_index("ix_objective_tasks_objective_id", "objective_tasks", ["objective_id"])
    op.create_index("ix_objective_tasks_tenant_id", "objective_tasks", ["tenant_id"])
    op.create_index("ix_objective_tasks_status", "objective_tasks", ["status"])
    op.create_index("ix_objective_tasks_lease", "objective_tasks", ["status", "lease_expires_at"])
    for column in ("seq", "kind", "title", "worker", "probe_id", "route", "budget_requests", "max_attempts",
                   "safety", "verify_kind", "status", "attempts", "error", "risk"):
        op.alter_column("objective_tasks", column, server_default=None)

    op.create_table(
        "objective_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("objective_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("type", sa.String(length=48), nullable=False),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["objective_id"], ["objectives.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_objective_events_objective_id", "objective_events", ["objective_id"])
    op.create_index("ix_objective_events_tenant_id", "objective_events", ["tenant_id"])
    op.create_index("ix_objective_events_at", "objective_events", ["at"])
    op.alter_column("objective_events", "message", server_default=None)

    # -- autonomy shifts from "schedule hunts" to "delegate objectives" -----
    op.add_column("autonomy_policies", sa.Column("mode", sa.String(length=16), nullable=False, server_default="hunt"))
    op.add_column(
        "autonomy_policies", sa.Column("objective_template", sa.String(length=32), nullable=False, server_default="posture")
    )
    op.add_column(
        "autonomy_policies", sa.Column("max_objectives_per_day", sa.Integer(), nullable=False, server_default="4")
    )
    op.add_column(
        "autonomy_policies", sa.Column("objective_budget_requests", sa.Integer(), nullable=False, server_default="120")
    )
    op.add_column(
        "autonomy_policies",
        sa.Column("escalation_cooldown_minutes", sa.Integer(), nullable=False, server_default="180"),
    )
    for column in ("mode", "objective_template", "max_objectives_per_day", "objective_budget_requests",
                   "escalation_cooldown_minutes"):
        op.alter_column("autonomy_policies", column, server_default=None)


def downgrade() -> None:
    for column in ("escalation_cooldown_minutes", "objective_budget_requests", "max_objectives_per_day",
                   "objective_template", "mode"):
        op.drop_column("autonomy_policies", column)
    op.drop_table("objective_events")
    op.drop_table("objective_tasks")
    op.drop_table("objectives")
