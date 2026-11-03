from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import JSONDoc


class Outbox(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """Transactional outbox.

    A run row and its dispatch intent commit together, so a broker outage can
    never leave an orphaned ``queued`` run: the relay retries until published.
    """

    __tablename__ = "outbox"

    topic: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(String(512), nullable=False, default="")
