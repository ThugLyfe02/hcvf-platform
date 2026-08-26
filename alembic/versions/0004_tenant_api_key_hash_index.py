"""add tenant api key hash index

Revision ID: 0004_tenant_api_key_hash_index
Revises: 0003_tenant_authorized_targets
Create Date: 2026-08-26
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004_tenant_api_key_hash_index"
down_revision: str | None = "0003_tenant_authorized_targets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_tenants_api_key_hash",
        "tenants",
        ["api_key_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_tenants_api_key_hash", table_name="tenants")
