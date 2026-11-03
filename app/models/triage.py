from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class FindingNote(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """Append-only triage history for one finding.

    Notes carry the status transition they accompanied, so a reviewer can
    reconstruct how a finding was decided without trusting a current status
    column. The row is never edited.
    """

    __tablename__ = "finding_notes"

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status_from: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    status_to: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Asset(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """A route the platform has observed for a tenant, with its own lifecycle.

    Assets answer a question findings cannot: what surface exists, when did we
    first see it, and did it appear or disappear since the last objective?
    """

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("tenant_id", "route", name="uq_asset_route"),)

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    route: Mapped[str] = mapped_column(String(2048), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_objective_id: Mapped[UUID | None] = mapped_column(GUID(), nullable=True)
    objective_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
