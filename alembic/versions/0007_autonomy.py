"""autonomy: standing authorization, target inventory, scheduling decisions

Revision ID: 0007_autonomy
Revises: 0006_agentic_hunt
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_autonomy"
down_revision: str | None = "0006_agentic_hunt"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- campaigns: who launched it, and with which learned probe set ------
    op.add_column(
        "campaigns", sa.Column("origin", sa.String(length=32), nullable=False, server_default="manual")
    )
    op.add_column(
        "campaigns",
        sa.Column(
            "genome",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_index("ix_campaigns_origin_created", "campaigns", ["origin", "created_at"])
    op.alter_column("campaigns", "origin", server_default=None)
    op.alter_column("campaigns", "genome", server_default=None)

    # -- findings: issue-level aggregation --------------------------------
    op.add_column("findings", sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("findings", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("last_run_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.execute("UPDATE findings SET last_seen_at = created_at WHERE last_seen_at IS NULL")
    op.execute("UPDATE findings SET last_run_id = run_id WHERE last_run_id IS NULL")
    op.create_index("ix_findings_last_run_id", "findings", ["last_run_id"])
    op.alter_column("findings", "occurrences", server_default=None)

    # -- standing authorization -------------------------------------------
    op.create_table(
        "autonomy_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("approved_by", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("approval_statement", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("approval_sha256", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("target_allowlist", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("safety_ceiling", sa.String(length=32), nullable=False, server_default="read_only"),
        sa.Column("budget_requests_per_run", sa.Integer(), nullable=False, server_default="120"),
        sa.Column("max_runs_per_day", sa.Integer(), nullable=False, server_default="8"),
        sa.Column("min_interval_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("quiet_hours_start", sa.Integer(), nullable=True),
        sa.Column("quiet_hours_end", sa.Integer(), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=False, server_default="UTC"),
        sa.Column("max_consecutive_failures", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("min_utility", sa.Float(), nullable=False, server_default="0.08"),
        sa.Column("last_tick_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", name="uq_autonomy_policy_tenant"),
    )
    op.create_index("ix_autonomy_policies_tenant_id", "autonomy_policies", ["tenant_id"])
    for column in ("enabled", "approved_by", "approval_statement", "approval_sha256", "safety_ceiling",
                   "budget_requests_per_run", "max_runs_per_day", "min_interval_minutes", "timezone",
                   "max_consecutive_failures", "min_utility"):
        op.alter_column("autonomy_policies", column, server_default=None)

    # -- asset inventory the controller schedules against ------------------
    op.create_table(
        "hunt_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="granted"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("next_eligible_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("runs_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "url", name="uq_hunt_target_url"),
    )
    op.create_index("ix_hunt_targets_tenant_id", "hunt_targets", ["tenant_id"])
    op.create_index("ix_hunt_targets_eligible", "hunt_targets", ["tenant_id", "enabled", "next_eligible_at"])
    for column in ("enabled", "source", "last_status", "consecutive_failures", "runs_total",
                   "findings_total", "last_findings"):
        op.alter_column("hunt_targets", column, server_default=None)

    # -- explainable scheduling decisions ----------------------------------
    op.create_table(
        "autonomy_decisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False, server_default=""),
        sa.Column("reason", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("utility", sa.Float(), nullable=False, server_default="0"),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_autonomy_decisions_tenant_id", "autonomy_decisions", ["tenant_id"])
    op.create_index("ix_autonomy_decisions_at", "autonomy_decisions", ["at"])
    for column in ("target_url", "reason", "utility"):
        op.alter_column("autonomy_decisions", column, server_default=None)


def downgrade() -> None:
    op.drop_table("autonomy_decisions")
    op.drop_table("hunt_targets")
    op.drop_table("autonomy_policies")

    op.drop_index("ix_findings_last_run_id", table_name="findings")
    op.drop_column("findings", "last_run_id")
    op.drop_column("findings", "last_seen_at")
    op.drop_column("findings", "occurrences")

    op.drop_index("ix_campaigns_origin_created", table_name="campaigns")
    op.drop_column("campaigns", "genome")
    op.drop_column("campaigns", "origin")
