"""objective findings become first-class findings

Revision ID: 0013_objective_findings
Revises: 0012_triage_assets
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_objective_findings"
down_revision: str | None = "0012_triage_assets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("findings", "run_id", existing_type=postgresql.UUID(as_uuid=True), nullable=True)
    op.add_column("findings", sa.Column("objective_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_findings_objective_id_objectives",
        "findings",
        "objectives",
        ["objective_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_findings_objective_id", "findings", ["objective_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_objective_id", table_name="findings")
    op.drop_constraint("fk_findings_objective_id_objectives", "findings", type_="foreignkey")
    op.drop_column("findings", "objective_id")
    op.alter_column("findings", "run_id", existing_type=postgresql.UUID(as_uuid=True), nullable=False)
