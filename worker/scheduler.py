from __future__ import annotations

import signal
import time
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import SessionLocal
from app.models.campaign import Campaign, CampaignStatus
from app.models.run import Run, RunStatus
from app.services.audit_service import record_audit_log
from app.services.campaign_service import enqueue_existing_run

logger = structlog.get_logger(__name__)
settings = get_settings()
_shutdown_requested = False


def dispatch_due_campaigns() -> int:
    """Claim and enqueue one bounded batch of due scheduled campaigns."""

    now = datetime.now(timezone.utc)
    claimed_run_ids: list[tuple[uuid.UUID, uuid.UUID]] = []

    with SessionLocal() as db:
        statement = (
            select(Campaign)
            .where(
                Campaign.status == CampaignStatus.SCHEDULED,
                Campaign.schedule_at.is_not(None),
                Campaign.schedule_at <= now,
            )
            .order_by(Campaign.schedule_at, Campaign.created_at)
            .limit(settings.scheduler_batch_size)
        )
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            statement = statement.with_for_update(skip_locked=True)

        campaigns = list(db.scalars(statement))
        for campaign in campaigns:
            run = Run(
                tenant_id=campaign.tenant_id,
                campaign_id=campaign.id,
                status=RunStatus.QUEUED,
            )
            db.add(run)
            campaign.status = CampaignStatus.QUEUED
            campaign.schedule_at = None
            campaign.started_at = None
            campaign.completed_at = None
            campaign.last_error = None
            db.flush()
            record_audit_log(
                db,
                tenant_id=campaign.tenant_id,
                actor="system:scheduler",
                action="campaign.scheduled_execution_requested",
                resource_type="campaign",
                resource_id=str(campaign.id),
                request_id=None,
                details={"run_id": str(run.id)},
            )
            claimed_run_ids.append((campaign.id, run.id))
        db.commit()

    enqueued = 0
    for campaign_id, run_id in claimed_run_ids:
        try:
            enqueue_existing_run(run_id=run_id, source="scheduler")
            enqueued += 1
        except Exception as exc:
            logger.exception(
                "scheduled_campaign_enqueue_failed",
                campaign_id=str(campaign_id),
                run_id=str(run_id),
                error_type=exc.__class__.__name__,
            )

    if claimed_run_ids:
        logger.info(
            "scheduler_batch_processed",
            claimed=len(claimed_run_ids),
            enqueued=enqueued,
        )
    return enqueued


def _request_shutdown(signum: int, _: object) -> None:
    global _shutdown_requested
    _shutdown_requested = True
    logger.info("scheduler_shutdown_requested", signal=signum)


def main() -> None:
    configure_logging()
    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGINT, _request_shutdown)
    logger.info(
        "scheduler_started",
        poll_seconds=settings.scheduler_poll_seconds,
        batch_size=settings.scheduler_batch_size,
    )

    while not _shutdown_requested:
        try:
            dispatch_due_campaigns()
        except Exception as exc:
            logger.exception(
                "scheduler_iteration_failed",
                error_type=exc.__class__.__name__,
            )
        time.sleep(settings.scheduler_poll_seconds)

    logger.info("scheduler_stopped")


if __name__ == "__main__":
    main()
