from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONDoc


class IdempotencyKey(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """A claimed request key with its recorded response.

    A retried POST must not create a second run. The row is claimed before the
    handler executes (``status_code = 0``) and completed afterwards, so two
    concurrent retries cannot both proceed.
    """

    __tablename__ = "idempotency_keys"
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_idempotency_tenant_key"),)

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class FindingSuppression(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """An accepted false positive, scoped to a tenant and optionally one issue.

    Suppressed findings are not stored, so counts and risk scores stop drifting
    because of a known-benign observation.
    """

    __tablename__ = "finding_suppressions"
    __table_args__ = (UniqueConstraint("tenant_id", "kind", "fingerprint", name="uq_suppression_target"),)

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Empty string means "every finding of this kind for this tenant".
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    reason: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class Webhook(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """Outbound event delivery with HMAC signing.

    The signing secret is stored so the worker can sign; production should wrap
    it with a KMS. Only the last four characters are ever returned by the API.
    """

    __tablename__ = "webhooks"

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret: Mapped[str] = mapped_column(String(128), nullable=False)
    events: Mapped[list] = mapped_column(JSONDoc, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(String(512), nullable=False, default="")
