from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Campaign, Run, Tenant


class QuotaExceeded(ValueError):
    def __init__(self, message: str, *, retry_after: int = 3600) -> None:
        super().__init__(message)
        self.retry_after = retry_after


def _local_day_start(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def usage(db: Session, tenant_id, *, now: datetime | None = None) -> tuple[int, int]:
    """Return (runs created today, requests budgeted by those runs)."""

    now = now or datetime.now(UTC)
    since = _local_day_start(now)
    runs = int(
        db.scalar(select(func.count()).select_from(Run).where(Run.tenant_id == tenant_id, Run.created_at >= since)) or 0
    )
    budget = int(
        db.scalar(
            select(func.coalesce(func.sum(Campaign.budget_requests), 0))
            .select_from(Run)
            .join(Campaign, Run.campaign_id == Campaign.id)
            .where(Run.tenant_id == tenant_id, Run.created_at >= since)
        )
        or 0
    )
    return runs, budget


def check_run_quota(db: Session, tenant: Tenant, *, now: datetime | None = None) -> None:
    """Fail closed when a tenant would exceed its daily run or request budget."""

    if not settings.quota_enforced:
        return
    runs, budget = usage(db, tenant.id, now=now)
    if runs >= tenant.daily_run_quota:
        raise QuotaExceeded(
            f"Daily run quota reached ({runs}/{tenant.daily_run_quota})",
            retry_after=3600,
        )
    if budget >= tenant.daily_request_quota:
        raise QuotaExceeded(
            f"Daily request quota reached ({budget}/{tenant.daily_request_quota})",
            retry_after=3600,
        )
