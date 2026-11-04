from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONDoc


class CampaignStatus(str, enum.Enum):
    draft = "draft"
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Campaign(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "campaigns"

    tenant_id: Mapped[UUID] = mapped_column(
        GUID(),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    authorization_attested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[CampaignStatus] = mapped_column(
        Enum(CampaignStatus, name="campaign_status"),
        nullable=False,
        default=CampaignStatus.draft,
    )
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Optional five-field cron expression; the scheduler recomputes the next run.
    cron: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Declared blast-radius ceiling. The engine refuses any probe above it.
    safety_ceiling: Mapped[str] = mapped_column(String(32), nullable=False, default="read_only")
    budget_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=200)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="agentic")
    #: "manual" for human-triggered campaigns, "autonomy" for controller ones.
    origin: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    #: Probe-set bias handed to the engine (derived from per-target learning).
    genome: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)

    tenant = relationship("Tenant", back_populates="campaigns")
    runs = relationship("Run", back_populates="campaign", cascade="all, delete-orphan")
