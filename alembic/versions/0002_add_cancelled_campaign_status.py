"""add cancelled campaign status

Revision ID: 0002_add_cancelled_campaign_status
Revises: 0001_initial_schema
Create Date: 2026-08-26
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0002_add_cancelled_campaign_status"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE campaign_status ADD VALUE IF NOT EXISTS 'cancelled'")


def downgrade() -> None:
    # PostgreSQL cannot safely remove an enum value in place without rebuilding
    # dependent columns. Keep the value on downgrade to preserve data integrity.
    pass
