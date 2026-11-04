from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class AgentHeartbeat(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """A running specialist agent, visible to every other process.

    The row is a liveness record, not a lock: leases on tasks are the locks. An
    operator (or another runtime) can see which agent is executing which task and
    how long ago it last reported, without reading process memory.
    """

    __tablename__ = "agent_heartbeats"

    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    worker: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="idle")
    objective_id: Mapped[UUID | None] = mapped_column(GUID(), nullable=True)
    task_key: Mapped[str] = mapped_column(String(96), nullable=False, default="")
    completed_tasks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_tasks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
