from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class ObjectiveMemory(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """What actually yielded on this host, learned across objectives.

    Two objectives against the same host should not both start from zero. This
    table is the workforce's cross-objective memory: trials, findings and
    verified reproductions per (host, template, probe, route role). It biases
    planning; it never overrides safety or authorization.
    """

    __tablename__ = "objective_memory"
    __table_args__ = (
        UniqueConstraint("tenant_id", "host", "template", "probe_id", "route_role", name="uq_objective_memory_recipe"),
    )

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    template: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    probe_id: Mapped[str] = mapped_column(String(64), nullable=False)
    route_role: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verified: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    refuted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    productive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
