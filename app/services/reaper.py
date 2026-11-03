"""Reconcile runs that no worker will ever finish.

A hard task time limit (SIGKILL), an OOM kill or a node eviction leaves a run in
``running`` with a stale lease. Without a reaper that run — and its campaign —
are permanently wedged, which is exactly the failure the original code had no
recovery path for.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Campaign, CampaignStatus, Run, RunStatus

logger = logging.getLogger(__name__)


def reap_stale_runs(db: Session, *, now: datetime | None = None, limit: int = 100) -> int:
    now = now or datetime.now(UTC)
    runs = list(
        db.scalars(
            select(Run)
            .where(
                Run.status == RunStatus.running,
                Run.lease_expires_at.is_not(None),
                Run.lease_expires_at < now,
            )
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    reaped = 0
    for run in runs:
        run.status = RunStatus.failed
        run.completed_at = now
        run.error_message = "lease expired: worker stopped without reporting"
        run.lease_expires_at = None
        campaign = db.get(Campaign, run.campaign_id)
        if campaign is not None and campaign.status == CampaignStatus.running:
            campaign.status = CampaignStatus.failed
        reaped += 1
        logger.warning("reaped stale run %s", run.id)

    # Honour cancellations that arrived while a run was queued or running.
    cancelled = list(
        db.scalars(
            select(Run)
            .where(Run.cancel_requested.is_(True), Run.status.in_([RunStatus.queued, RunStatus.running]))
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    for run in cancelled:
        run.status = RunStatus.cancelled
        run.completed_at = now
        run.error_message = "cancelled by operator"
        campaign = db.get(Campaign, run.campaign_id)
        if campaign is not None:
            campaign.status = CampaignStatus.cancelled
        reaped += 1

    if reaped:
        db.commit()
    return reaped
