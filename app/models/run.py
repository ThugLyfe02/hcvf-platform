from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONDoc


class RunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Run(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "runs"

    #: Denormalized tenant id. Isolation is enforced by joins *and* by this
    #: column, so a missed join cannot silently cross tenants.
    tenant_id: Mapped[UUID | None] = mapped_column(
        GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=True
    )
    campaign_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    status: Mapped[RunStatus] = mapped_column(
        Enum(RunStatus, name="run_status"),
        nullable=False,
        default=RunStatus.queued,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Wall-clock lease held by the worker; the reaper expires stale leases so
    #: a killed worker can never strand a run in ``running`` forever.
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    #: Agentic plan + decision trace, so every run is explainable and replayable.
    plan_seed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    plan: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    evidence_root: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Composite risk score for this run (0-100), used for trend reporting.
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    campaign = relationship("Campaign", back_populates="runs")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")
