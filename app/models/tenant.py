from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.audit import AuditLog
    from app.models.campaign import Campaign
    from app.models.finding import Finding
    from app.models.run import Run


class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    api_key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    campaigns: Mapped[list[Campaign]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    runs: Mapped[list[Run]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="tenant")
