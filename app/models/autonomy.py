from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONDoc


class AutonomyPolicy(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """A standing, bounded, human-approved authorization to hunt unaided.

    Autonomy is not a bypass: the controller may only act inside this policy, and
    the policy may only reference targets the tenant is already granted. Turning
    autonomy on is a deliberate act with a recorded approval statement and hash.
    """

    __tablename__ = "autonomy_policies"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_autonomy_policy_tenant"),)

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    #: Human approval artifact. `approval_statement` is the free-text go-ahead,
    #: `approval_sha256` binds it to the tenant and timestamp.
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    approval_statement: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    approval_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target_allowlist: Mapped[list] = mapped_column(JSONDoc, nullable=False, default=list)
    safety_ceiling: Mapped[str] = mapped_column(String(32), nullable=False, default="read_only")
    budget_requests_per_run: Mapped[int] = mapped_column(Integer, nullable=False, default=120)
    max_runs_per_day: Mapped[int] = mapped_column(Integer, nullable=False, default=8)
    min_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)

    #: Quiet hours are local to the tenant's zone, inclusive start / exclusive end.
    quiet_hours_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quiet_hours_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")

    max_consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    #: "hunt" schedules campaigns directly; "objective" delegates work to the workforce.
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="hunt")
    objective_template: Mapped[str] = mapped_column(String(32), nullable=False, default="posture")
    max_objectives_per_day: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    objective_budget_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=120)
    escalation_cooldown_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=180)
    #: Always pick the doctrine by gap analysis + rotation, ignoring a fixed template.
    template_auto: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: After a block, retry only the criteria that failed instead of the whole doctrine.
    narrow_on_retry: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_active_objectives: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    daily_objective_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=400)
    template_history: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    #: Minimum scheduling utility required to launch an autonomous hunt.
    min_utility: Mapped[float] = mapped_column(Float, nullable=False, default=0.08)
    last_tick_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class HuntTarget(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """The asset inventory autonomy schedules against.

    Without this the controller would have to guess what to test; with it, every
    target has explicit state — how recently it ran, whether it keeps failing,
    and what it has yielded.
    """

    __tablename__ = "hunt_targets"
    __table_args__ = (UniqueConstraint("tenant_id", "url", name="uq_hunt_target_url"),)

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="granted")

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    next_eligible_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    runs_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_run_id: Mapped[UUID | None] = mapped_column(GUID(), nullable=True)


class AutonomyDecision(TimestampMixin, UUIDPrimaryKeyMixin, Base):
    """An explainable record of every autonomous scheduling decision."""

    __tablename__ = "autonomy_decisions"

    tenant_id: Mapped[UUID] = mapped_column(GUID(), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    reason: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    utility: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    run_id: Mapped[UUID | None] = mapped_column(GUID(), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONDoc, nullable=False, default=dict)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC), index=True
    )

    tenant = relationship("Tenant")
