"""add tenant authorized targets

Revision ID: 0003_tenant_authorized_targets
Revises: 0002_campaign_cancelled
Create Date: 2026-08-26
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003_tenant_authorized_targets"
down_revision: Union[str, None] = "0002_campaign_cancelled"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "authorized_targets",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.alter_column("tenants", "authorized_targets", server_default=None)


def downgrade() -> None:
    op.drop_column("tenants", "authorized_targets")
