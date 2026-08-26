from __future__ import annotations

import logging
import time

from app.core.config import settings
from app.core.logging import configure_logging
from app.db.session import SessionLocal
from app.services.campaign_service import CampaignService
from worker.tasks import execute_campaign

logger = logging.getLogger(__name__)


def dispatch_due_campaigns() -> int:
    with SessionLocal() as db:
        runs = CampaignService(db).claim_due_campaigns()
    for run in runs:
        execute_campaign.delay(str(run.id))
    if runs:
        logger.info("scheduled campaigns dispatched", extra={"run_id": ",".join(str(run.id) for run in runs)})
    return len(runs)


def main() -> None:
    configure_logging()
    logger.info("scheduler started")
    while True:
        try:
            dispatch_due_campaigns()
        except Exception:
            logger.exception("scheduler iteration failed")
        time.sleep(settings.scheduler_interval_seconds)


if __name__ == "__main__":
    main()
