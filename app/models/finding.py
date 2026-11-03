from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONDoc


class FindingStatus:
    open = "open"
    triaged = "triaged"
    confirmed = "confirmed"
    false_positive = "false_positive"
    risk_accepted = "risk_accepted"
    fixed = "fixed"
    verified = "verified"

    ALL = (open, triaged, confirmed, false_positive, risk_accepted, fixed, verified)


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    run_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[UUID | None] = mapped_column(
        GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=True
    )

    #: Stable identity of the issue across runs (probe + kind + location).
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    probe_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="info")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=FindingStatus.open)
    cwe: Mapped[str] = mapped_column(String(32), nullable=False, default="")

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[list] = mapped_column(JSONDoc, nullable=False, default=list)
    evidence_refs: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)

    #: Issue-level aggregation: autonomous hunts repeat, and a repeated finding is
    #: one issue seen N times, not N issues. `last_run_id` keeps per-run reports
    #: accurate after the row has been carried forward.
    occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    #: Triage ownership and SLA; set on first decision and surfaced by /findings/summary.
    assignee: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triaged_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_id: Mapped[UUID | None] = mapped_column(GUID(), nullable=True, index=True)

    run = relationship("Run", back_populates="findings")
