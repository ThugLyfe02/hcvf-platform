from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class EvidenceBlob(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """Content-addressed pointer to a sealed evidence artifact.

    The bytes live in an object store or filesystem; the row carries the digest,
    size and kind so a manifest can be verified without the original store.
    """

    __tablename__ = "evidence_blobs"

    digest: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    media_type: Mapped[str] = mapped_column(String(128), nullable=False, default="application/octet-stream")


class ProbeStat(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """Persisted Beta prior per (probe, target host).

    This is the durable half of the bandit: hunts on the same host share what
    they have learned, without leaking learning across tenants.
    """

    __tablename__ = "probe_stats"
    __table_args__ = (UniqueConstraint("probe_id", "target_host", name="uq_probe_stat_target"),)

    probe_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    alpha: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    beta: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    trials: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
