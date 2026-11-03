from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONDoc


class AuditLog(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "audit_logs"

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    #: Monotonic position in the tenant chain; timestamps are not a total order.
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    #: Per-tenant tamper-evident chain over audit records.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    tenant = relationship("Tenant", back_populates="audit_logs")
