"""agentic hunt: plans, leases, findings lifecycle, outbox, evidence, priors

Revision ID: 0006_agentic_hunt
Revises: 0005_add_cancelled_run_status
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_agentic_hunt"
down_revision: str | None = "0005_add_cancelled_run_status"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- runs: tenancy, lease, cancellation, plan, evidence ----------------
    op.add_column("runs", sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("runs", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "runs",
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("runs", sa.Column("plan_seed", sa.Integer(), nullable=True))
    op.add_column(
        "runs",
        sa.Column("plan", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column("runs", sa.Column("evidence_root", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_runs_tenant_id_tenants", "runs", "tenants", ["tenant_id"], ["id"], ondelete="CASCADE"
    )
    op.create_index("ix_runs_tenant_id", "runs", ["tenant_id"])
    op.create_index("ix_runs_status_lease", "runs", ["status", "lease_expires_at"])
    op.execute("UPDATE runs SET tenant_id = campaigns.tenant_id FROM campaigns WHERE runs.campaign_id = campaigns.id")
    op.alter_column("runs", "cancel_requested", server_default=None)
    op.alter_column("runs", "plan", server_default=None)

    # -- campaigns: declared blast radius and budget -----------------------
    op.add_column(
        "campaigns", sa.Column("safety_ceiling", sa.String(length=32), nullable=False, server_default="read_only")
    )
    op.add_column(
        "campaigns", sa.Column("budget_requests", sa.Integer(), nullable=False, server_default="200")
    )
    op.add_column("campaigns", sa.Column("mode", sa.String(length=32), nullable=False, server_default="agentic"))
    op.create_index("ix_campaigns_status_scheduled", "campaigns", ["status", "scheduled_at"])
    op.alter_column("campaigns", "safety_ceiling", server_default=None)
    op.alter_column("campaigns", "budget_requests", server_default=None)
    op.alter_column("campaigns", "mode", server_default=None)

    # -- tenants: role and lifecycle --------------------------------------
    op.add_column("tenants", sa.Column("role", sa.String(length=32), nullable=False, server_default="member"))
    op.add_column("tenants", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.execute("UPDATE tenants SET role = 'admin' WHERE name LIKE 'configured-tenant-%'")
    op.alter_column("tenants", "role", server_default=None)
    op.alter_column("tenants", "is_active", server_default=None)

    # -- findings: fingerprint, confidence, lifecycle, evidence ------------
    op.add_column("findings", sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("findings", sa.Column("fingerprint", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("probe_id", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"))
    op.add_column("findings", sa.Column("status", sa.String(length=32), nullable=False, server_default="open"))
    op.add_column("findings", sa.Column("cwe", sa.String(length=32), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("remediation", sa.Text(), nullable=False, server_default=""))
    op.add_column(
        "findings",
        sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.execute(
        "UPDATE findings SET fingerprint = substr(md5(kind || ':' || coalesce(title, '')), 1, 32) WHERE fingerprint = ''"
    )
    op.execute(
        "UPDATE findings SET tenant_id = runs.tenant_id FROM runs WHERE findings.run_id = runs.id"
    )
    op.execute("UPDATE findings SET evidence = '[]'::jsonb WHERE jsonb_typeof(evidence) = 'object'")
    op.create_foreign_key(
        "fk_findings_tenant_id_tenants", "findings", "tenants", ["tenant_id"], ["id"], ondelete="CASCADE"
    )
    op.create_index("ix_findings_tenant_id", "findings", ["tenant_id"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_status_severity", "findings", ["status", "severity"])
    op.alter_column("findings", "fingerprint", server_default=None)
    op.alter_column("findings", "probe_id", server_default=None)
    op.alter_column("findings", "confidence", server_default=None)
    op.alter_column("findings", "status", server_default=None)
    op.alter_column("findings", "cwe", server_default=None)
    op.alter_column("findings", "remediation", server_default=None)
    op.alter_column("findings", "evidence_refs", server_default=None)

    # -- transactional outbox ---------------------------------------------
    op.create_table(
        "outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("topic", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_outbox_topic", "outbox", ["topic"])
    op.create_index("ix_outbox_pending", "outbox", ["published_at", "available_at"])
    op.alter_column("outbox", "attempts", server_default=None)
    op.alter_column("outbox", "last_error", server_default=None)

    # -- evidence pointers -------------------------------------------------
    op.create_table(
        "evidence_blobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("media_type", sa.String(length=128), nullable=False, server_default="application/octet-stream"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("digest"),
    )
    op.create_index("ix_evidence_blobs_digest", "evidence_blobs", ["digest"])
    op.alter_column("evidence_blobs", "label", server_default=None)
    op.alter_column("evidence_blobs", "size", server_default=None)
    op.alter_column("evidence_blobs", "media_type", server_default=None)

    # -- learned probe priors ---------------------------------------------
    op.create_table(
        "probe_stats",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("probe_id", sa.String(length=64), nullable=False),
        sa.Column("target_host", sa.String(length=255), nullable=False),
        sa.Column("alpha", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("beta", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("trials", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("probe_id", "target_host", name="uq_probe_stat_target"),
    )
    op.create_index("ix_probe_stats_probe_id", "probe_stats", ["probe_id"])
    op.create_index("ix_probe_stats_target_host", "probe_stats", ["target_host"])
    op.alter_column("probe_stats", "alpha", server_default=None)
    op.alter_column("probe_stats", "beta", server_default=None)
    op.alter_column("probe_stats", "trials", server_default=None)


def downgrade() -> None:
    op.drop_table("probe_stats")
    op.drop_table("evidence_blobs")
    op.drop_index("ix_outbox_pending", table_name="outbox")
    op.drop_index("ix_outbox_topic", table_name="outbox")
    op.drop_table("outbox")

    op.drop_index("ix_findings_status_severity", table_name="findings")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_index("ix_findings_tenant_id", table_name="findings")
    op.drop_constraint("fk_findings_tenant_id_tenants", "findings", type_="foreignkey")
    for column in (
        "evidence_refs",
        "remediation",
        "cwe",
        "status",
        "confidence",
        "probe_id",
        "fingerprint",
        "tenant_id",
    ):
        op.drop_column("findings", column)

    op.alter_column("tenants", "is_active", server_default=sa.true())
    op.drop_column("tenants", "is_active")
    op.drop_column("tenants", "role")

    op.drop_index("ix_campaigns_status_scheduled", table_name="campaigns")
    op.drop_column("campaigns", "mode")
    op.drop_column("campaigns", "budget_requests")
    op.drop_column("campaigns", "safety_ceiling")

    op.drop_index("ix_runs_status_lease", table_name="runs")
    op.drop_index("ix_runs_tenant_id", table_name="runs")
    op.drop_constraint("fk_runs_tenant_id_tenants", "runs", type_="foreignkey")
    for column in ("evidence_root", "plan", "plan_seed", "cancel_requested", "lease_expires_at", "tenant_id"):
        op.drop_column("runs", column)
