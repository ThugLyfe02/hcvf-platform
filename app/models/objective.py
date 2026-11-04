from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONDoc


class Objective(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """A delegated piece of work with observable acceptance criteria."""

    __tablename__ = "objectives"
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_objective_key"),)

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(96), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    template: Mapped[str] = mapped_column(String(32), nullable=False, default="posture")
    #: surface | standard | deep - declared thoroughness, used by planners.
    depth: Mapped[str] = mapped_column(String(16), nullable=False, default="standard")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    safety_ceiling: Mapped[str] = mapped_column(String(32), nullable=False, default="read_only")
    budget_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=120)
    per_task_budget: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    criteria: Mapped[list] = mapped_column(JSONDoc, nullable=False, default=list)
    plan: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    result: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    verdict: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    requests_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    origin: Mapped[str] = mapped_column(String(32), nullable=False, default="delegated")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tasks = relationship(
        "ObjectiveTask", back_populates="objective", cascade="all, delete-orphan", order_by="ObjectiveTask.seq"
    )


class ObjectiveTask(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """One surgical unit of work inside an objective."""

    __tablename__ = "objective_tasks"
    __table_args__ = (UniqueConstraint("objective_id", "key", name="uq_objective_task_key"),)

    objective_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("objectives.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(96), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="probe")
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    worker: Mapped[str] = mapped_column(String(64), nullable=False, default="config-worker")
    probe_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    route: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    depends_on: Mapped[list] = mapped_column(JSONDoc, nullable=False, default=list)
    budget_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    safety: Mapped[str] = mapped_column(String(32), nullable=False, default="read_only")
    verify_kind: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    payload: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    outcome: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    error: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    objective = relationship("Objective", back_populates="tasks")


class ObjectiveEvent(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """Append-only narrative of what the workforce did and why."""

    __tablename__ = "objective_events"

    objective_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("objectives.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(48), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    payload: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
