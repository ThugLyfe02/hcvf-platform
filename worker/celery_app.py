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
    # Results are never read (the run row is the source of truth). Leaving the
    # result consumer enabled makes every publish open a pubsub connection to
    # Redis, which turns a broker hiccup into a slow API request.
    task_ignore_result=True,
    result_backend=None,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"max_retries": 3, "interval_start": 0, "interval_step": 0.2},
    task_soft_time_limit=540,
    task_time_limit=600,
    timezone="UTC",
    enable_utc=True,
)
