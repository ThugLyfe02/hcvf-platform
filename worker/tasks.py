from __future__ import annotations

from uuid import UUID

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.exc import OperationalError

from app.db.session import SessionLocal
from worker.celery_app import celery_app
from worker.pipeline import CampaignPipeline


@celery_app.task(
    name="hcvf.execute_campaign",
    bind=True,
    autoretry_for=(OperationalError,),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    retry_kwargs={"max_retries": 5},
    soft_time_limit=270,
    time_limit=300,
    acks_late=True,
)
def execute_campaign(self, run_id: str) -> dict[str, object]:
    parsed_run_id = UUID(run_id)

    try:
        with SessionLocal() as db:
            run = CampaignPipeline(db).execute(parsed_run_id)
            return {
                "run_id": str(run.id),
                "campaign_id": str(run.campaign_id),
                "status": run.status.value,
                "http_status": run.http_status,
                "error_message": run.error_message,
            }
    except SoftTimeLimitExceeded:
        raise RuntimeError(f"Campaign run {run_id} exceeded the soft time limit")
