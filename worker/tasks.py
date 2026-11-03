from __future__ import annotations

from uuid import UUID

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.exc import OperationalError

from app.db.session import SessionLocal
from app.services.hunt_service import HuntService
from worker.celery_app import celery_app


@celery_app.task(
    name="hcvf.execute_campaign",
    bind=True,
    autoretry_for=(OperationalError,),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    retry_kwargs={"max_retries": 5},
    soft_time_limit=540,
    time_limit=600,
    acks_late=True,
)
def execute_campaign(self, run_id: str) -> dict[str, object]:
    """Execute one agentic hunt. Idempotent: terminal runs return immediately."""

    parsed = UUID(run_id)
    try:
        with SessionLocal() as db:
            run = HuntService(db).execute_run(parsed)
            return {
                "run_id": str(run.id),
                "campaign_id": str(run.campaign_id),
                "status": run.status.value,
                "http_status": run.http_status,
                "error_message": run.error_message,
                "evidence_root": run.evidence_root,
            }
    except SoftTimeLimitExceeded:
        # The lease reaper will fail the row; raising turns it into a Celery
        # failure so the task is visible in Flower/monitoring.
        raise RuntimeError(f"Hunt run {run_id} exceeded the soft time limit") from None


def publish_outbox_message(topic: str, payload: dict) -> None:
    """Deliver an outbox intent to its executor. Raises on failure to retry."""

    if topic == "campaign.run":
        run_id = payload.get("run_id")
        if not run_id:
            raise ValueError("campaign.run payload is missing run_id")
        execute_campaign.delay(str(run_id))
        return
    if topic == "webhook.deliver":
        from app.services.webhooks import deliver_payload

        deliver_payload(payload)
        return
    raise ValueError(f"unknown outbox topic: {topic}")


def dispatch_outbox(*, limit: int = 20) -> int:
    """Relay helper usable from the scheduler and tests."""

    from app.services.outbox import dispatch_pending

    with SessionLocal() as db:
        return dispatch_pending(db, publish_outbox_message, limit=limit)
