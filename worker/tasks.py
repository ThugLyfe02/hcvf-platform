from __future__ import annotations

from uuid import UUID

from app.db.session import SessionLocal
from worker.celery_app import celery_app
from worker.pipeline import CampaignPipeline


@celery_app.task(name="hcvf.execute_campaign", bind=True, autoretry_for=(), acks_late=True)
def execute_campaign(self, run_id: str) -> dict:
    parsed_run_id = UUID(run_id)
    with SessionLocal() as db:
        run = CampaignPipeline(db).execute(parsed_run_id)
        return {
            "run_id": str(run.id),
            "campaign_id": str(run.campaign_id),
            "status": run.status.value,
            "http_status": run.http_status,
            "error_message": run.error_message,
        }
