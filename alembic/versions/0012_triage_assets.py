"""new fields to findings + finding_notes + assets

Revision ID: 0012_triage_assets
Revises: 0011_objective_memory
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_triage_assets"
down_revision: str | None = "0011_objective_memory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("assignee", sa.String(length=255), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("triaged_by", sa.String(length=255), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True))
    for column in ("assignee", "triaged_by"):
        op.alter_column("findings", column, server_default=None)

    op.create_table(
        "finding_notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("status_from", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("status_to", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_notes_tenant_id", "finding_notes", ["tenant_id"])
    op.create_index("ix_finding_notes_finding_id", "finding_notes", ["finding_id"])
    for column in ("author", "note", "status_from", "status_to"):
        op.alter_column("finding_notes", column, server_default=None)

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("route", sa.String(length=2048), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="other"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_objective_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("objective_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "route", name="uq_asset_route"),
    )
    op.create_index("ix_assets_tenant_id", "assets", ["tenant_id"])
    op.create_index("ix_assets_host", "assets", ["host"])
    op.create_index("ix_assets_last_seen", "assets", ["last_seen_at"])
    for column in ("role", "status", "objective_count", "finding_count"):
        op.alter_column("assets", column, server_default=None)


def downgrade() -> None:
    op.drop_table("assets")
    op.drop_table("finding_notes")
    for column in ("sla_due_at", "triaged_by", "triaged_at", "assignee"):
        op.drop_column("findings", column)
