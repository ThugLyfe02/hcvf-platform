from __future__ import annotations

import structlog
from celery import Task

from worker.celery_app import celery_app
from worker.pipeline import CampaignPipeline

logger = structlog.get_logger(__name__)


@celery_app.task(
    bind=True,
    base=Task,
    name="hcvf.execute_campaign",
    acks_late=True,
)
def execute_campaign(self: Task, *, run_id: str) -> dict[str, object]:
    task_id = self.request.id
    logger.info("campaign_task_received", run_id=run_id, celery_task_id=task_id)
    result = CampaignPipeline(run_id=run_id, task_id=task_id).execute()
    logger.info(
        "campaign_task_finished",
        run_id=run_id,
        celery_task_id=task_id,
        status=result.get("status"),
    )
    return result
