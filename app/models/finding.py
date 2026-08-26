from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    run_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="info")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    run = relationship("Run", back_populates="findings")
