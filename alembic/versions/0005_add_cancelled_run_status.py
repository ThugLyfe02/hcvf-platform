"""add cancelled run status

Revision ID: 0005_add_cancelled_run_status
Revises: 0004_tenant_api_key_hash_index
Create Date: 2026-08-26
"""

from alembic import op

revision = "0005_add_cancelled_run_status"
down_revision = "0004_tenant_api_key_hash_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE run_status ADD VALUE IF NOT EXISTS 'cancelled'")


def downgrade() -> None:
    # PostgreSQL enum values cannot be removed safely in-place without rebuilding dependent columns.
    pass
