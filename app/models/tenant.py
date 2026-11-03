from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import JSONDoc


class TenantRole:
    admin = "admin"
    member = "member"
    auditor = "auditor"

    ALL = (admin, member, auditor)


class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    api_key_hash: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=False,
    )
    #: admin may manage other tenants; member may only act inside its own scope.
    role: Mapped[str] = mapped_column(String(32), nullable=False, default=TenantRole.member)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    authorized_targets: Mapped[list] = mapped_column(
        JSONDoc,
        nullable=False,
        default=list,
    )
    #: Fine-grained capability grants. Admin tenants carry ["*"].
    scopes: Mapped[list] = mapped_column(JSONDoc, nullable=False, default=lambda: ["*"])
    key_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Daily governance limits enforced before a run is created.
    daily_run_quota: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    daily_request_quota: Mapped[int] = mapped_column(Integer, nullable=False, default=20000)

    campaigns = relationship(
        "Campaign",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )

    @property
    def is_admin(self) -> bool:
        return self.role == TenantRole.admin
