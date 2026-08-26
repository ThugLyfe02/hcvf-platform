from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class Run(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "runs"

    campaign_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    status: Mapped[RunStatus] = mapped_column(Enum(RunStatus, name="run_status"), nullable=False, default=RunStatus.queued)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    campaign = relationship("Campaign", back_populates="runs")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")
