"""governance: scopes, quotas, idempotency, suppressions, webhooks, audit chain

Revision ID: 0008_governance
Revises: 0007_autonomy
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_governance"
down_revision: str | None = "0007_autonomy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- tenants: capability scopes, key rotation, daily quotas ------------
    op.add_column(
        "tenants",
        sa.Column(
            "scopes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[\"*\"]'::jsonb"),
        ),
    )
    op.add_column("tenants", sa.Column("key_rotated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tenants", sa.Column("daily_run_quota", sa.Integer(), nullable=False, server_default="100"))
    op.add_column("tenants", sa.Column("daily_request_quota", sa.Integer(), nullable=False, server_default="20000"))
    op.execute("UPDATE tenants SET scopes = '[\"*\"]'::jsonb WHERE role = 'admin'")
    op.execute(
        "UPDATE tenants SET scopes = '[\"campaigns:read\",\"campaigns:write\",\"findings:read\"]'::jsonb "
        "WHERE role <> 'admin'"
    )
    op.create_index("ix_tenants_key_rotated_at", "tenants", ["key_rotated_at"])
    for column in ("scopes", "daily_run_quota", "daily_request_quota"):
        op.alter_column("tenants", column, server_default=None)

    # -- runs: risk score --------------------------------------------------
    op.add_column("runs", sa.Column("risk_score", sa.Float(), nullable=True))

    # -- campaigns: cron scheduling ---------------------------------------
    op.add_column("campaigns", sa.Column("cron", sa.String(length=64), nullable=True))
    op.create_index("ix_campaigns_cron", "campaigns", ["cron"])

    # -- audit: per-tenant hash chain --------------------------------------
    op.add_column("audit_logs", sa.Column("seq", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("audit_logs", sa.Column("prev_hash", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("audit_logs", sa.Column("hash", sa.String(length=64), nullable=False, server_default=""))
    op.create_index("ix_audit_logs_hash", "audit_logs", ["hash"])
    op.create_index("ix_audit_logs_seq", "audit_logs", ["seq"])
    op.execute("UPDATE audit_logs SET seq = 0")
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    for column in ("seq", "prev_hash", "hash"):
        op.alter_column("audit_logs", column, server_default=None)

    # -- idempotency -------------------------------------------------------
    op.create_table(
        "idempotency_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("response", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "key", name="uq_idempotency_tenant_key"),
    )
    op.create_index("ix_idempotency_keys_tenant_id", "idempotency_keys", ["tenant_id"])
    op.create_index("ix_idempotency_keys_expires_at", "idempotency_keys", ["expires_at"])
    op.alter_column("idempotency_keys", "status_code", server_default=None)

    # -- finding suppressions ---------------------------------------------
    op.create_table(
        "finding_suppressions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(length=128), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("reason", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "kind", "fingerprint", name="uq_suppression_target"),
    )
    op.create_index("ix_finding_suppressions_tenant_id", "finding_suppressions", ["tenant_id"])
    op.create_index("ix_finding_suppressions_expires_at", "finding_suppressions", ["expires_at"])
    for column in ("fingerprint", "reason", "created_by"):
        op.alter_column("finding_suppressions", column, server_default=None)

    # -- webhooks ----------------------------------------------------------
    op.create_table(
        "webhooks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("secret", sa.String(length=128), nullable=False),
        sa.Column("events", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webhooks_tenant_id", "webhooks", ["tenant_id"])
    for column in ("active", "failures", "last_error"):
        op.alter_column("webhooks", column, server_default=None)


def downgrade() -> None:
    op.drop_table("webhooks")
    op.drop_table("finding_suppressions")
    op.drop_index("ix_idempotency_keys_expires_at", table_name="idempotency_keys")
    op.drop_index("ix_idempotency_keys_tenant_id", table_name="idempotency_keys")
    op.drop_table("idempotency_keys")

    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_hash", table_name="audit_logs")
    op.drop_index("ix_audit_logs_seq", table_name="audit_logs")
    op.drop_column("audit_logs", "hash")
    op.drop_column("audit_logs", "seq")
    op.drop_column("audit_logs", "prev_hash")

    op.drop_index("ix_campaigns_cron", table_name="campaigns")
    op.drop_column("campaigns", "cron")
    op.drop_column("runs", "risk_score")

    op.drop_index("ix_tenants_key_rotated_at", table_name="tenants")
    op.drop_column("tenants", "daily_request_quota")
    op.drop_column("tenants", "daily_run_quota")
    op.drop_column("tenants", "key_rotated_at")
    op.drop_column("tenants", "scopes")
