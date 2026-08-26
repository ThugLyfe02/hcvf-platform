from __future__ import annotations

from celery import Celery

from app.core.config import settings
from app.core.logging import setup_logging

setup_logging()

celery_app = Celery(
    "hcvf",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    task_soft_time_limit=270,
    task_time_limit=300,
    timezone="UTC",
    enable_utc=True,
)
