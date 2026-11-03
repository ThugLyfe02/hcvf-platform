from __future__ import annotations

import logging
import time

from app.core.config import settings
from app.core.logging import setup_logging
from app.db.session import SessionLocal
from app.services.campaign_service import CampaignService
from app.services.outbox import dispatch_pending
from app.services.reaper import reap_stale_runs
from worker.autonomy import maybe_tick as autonomy_tick
from worker.objectives import maybe_tick as objective_tick
from worker.tasks import execute_campaign, publish_outbox_message

logger = logging.getLogger(__name__)


def relay_outbox() -> int:
    with SessionLocal() as db:
        return dispatch_pending(db, publish_outbox_message)


def reap() -> int:
    with SessionLocal() as db:
        return reap_stale_runs(db)


def dispatch_cron_campaigns() -> int:
    with SessionLocal() as db:
        runs = CampaignService(db).claim_cron_campaigns()
    for run in runs:
        execute_campaign.delay(str(run.id))
    if runs:
        logger.info("cron campaigns dispatched", extra={"run_ids": [str(run.id) for run in runs]})
    return len(runs)


def dispatch_due_campaigns() -> int:
    with SessionLocal() as db:
        runs = CampaignService(db).claim_due_campaigns()
    for run in runs:
        execute_campaign.delay(str(run.id))
    if runs:
        logger.info("scheduled campaigns dispatched", extra={"run_ids": [str(run.id) for run in runs]})
    return len(runs)


def main() -> None:
    setup_logging()
    logger.info("scheduler started (outbox relay + reaper + autonomy controller)")
    while True:
        try:
            relay_outbox()
            reap()
            dispatch_due_campaigns()
            dispatch_cron_campaigns()
            autonomy_tick()
            objective_tick()
        except Exception:
            logger.exception("scheduler iteration failed")
        time.sleep(settings.scheduler_interval_seconds)


if __name__ == "__main__":
    main()
