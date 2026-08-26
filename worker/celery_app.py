from __future__ import annotations

from celery import Celery, signals

from app.core.config import get_settings
from app.core.logging import configure_logging

settings = get_settings()

celery_app = Celery(
    "hcvf",
    broker=settings.effective_celery_broker_url,
    backend=settings.effective_celery_result_backend,
    include=["worker.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    worker_hijack_root_logger=False,
    task_time_limit=300,
    task_soft_time_limit=270,
    task_always_eager=settings.celery_task_always_eager,
    task_eager_propagates=settings.celery_task_eager_propagates,
    task_store_eager_result=False,
)


@signals.setup_logging.connect
def _configure_celery_logging(**_: object) -> None:
    configure_logging()
