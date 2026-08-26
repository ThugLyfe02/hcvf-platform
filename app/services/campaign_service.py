from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.errors import bad_request, conflict, not_found, service_unavailable
from app.core.metrics import CAMPAIGN_EXECUTION_REQUESTS, CAMPAIGNS_CREATED
from app.core.security import actor_for_tenant
from app.db.session import SessionLocal
from app.models.campaign import Campaign, CampaignStatus
from app.models.finding import Finding
from app.models.run import Run, RunStatus
from app.models.tenant import Tenant
from app.services.audit_service import record_audit_log
from worker.fuzz_runner import FuzzRunner

logger = structlog.get_logger(__name__)

_ACTIVE_CAMPAIGN_STATUSES = {CampaignStatus.QUEUED, CampaignStatus.RUNNING}
_ACTIVE_RUN_STATUSES = {RunStatus.QUEUED, RunStatus.RUNNING}
_TERMINAL_CAMPAIGN_STATUSES = {
    CampaignStatus.COMPLETED,
    CampaignStatus.FAILED,
}


def create_campaign(
    db: Session,
    *,
    tenant: Tenant,
    name: str,
    target_url: str,
    authorization_reference: str,
    config: dict[str, Any],
    schedule_at: datetime | None,
    request_id: str | None,
) -> Campaign:
    normalized_schedule = _normalize_schedule(schedule_at)
    try:
        validated_runner = FuzzRunner(target_url=target_url, config=config)
    except ValueError as exc:
        raise bad_request("invalid_campaign_target", str(exc)) from exc

    campaign = Campaign(
        tenant_id=tenant.id,
        name=name,
        target_url=validated_runner.target_url,
        authorization_reference=authorization_reference,
        config=dict(config),
        schedule_at=normalized_schedule,
        status=(
            CampaignStatus.SCHEDULED
            if normalized_schedule is not None
            else CampaignStatus.CREATED
        ),
    )
    db.add(campaign)
    db.flush()
    record_audit_log(
        db,
        tenant_id=tenant.id,
        actor=actor_for_tenant(tenant),
        action="campaign.created",
        resource_type="campaign",
        resource_id=str(campaign.id),
        request_id=request_id,
        details={
            "scheduled": normalized_schedule is not None,
            "authorization_reference": campaign.authorization_reference,
        },
    )
    db.commit()
    db.refresh(campaign)
    CAMPAIGNS_CREATED.inc()
    logger.info(
        "campaign_created",
        campaign_id=str(campaign.id),
        tenant_id=str(tenant.id),
        status=campaign.status.value,
    )
    return campaign


def list_campaigns(db: Session, *, tenant_id: uuid.UUID) -> list[Campaign]:
    return list(
        db.scalars(
            select(Campaign)
            .where(Campaign.tenant_id == tenant_id)
            .order_by(desc(Campaign.created_at))
        )
    )


def get_campaign(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
    for_update: bool = False,
) -> Campaign:
    statement = select(Campaign).where(
        Campaign.id == campaign_id,
        Campaign.tenant_id == tenant_id,
    )
    if for_update:
        statement = statement.with_for_update()
    campaign = db.scalar(statement)
    if campaign is None:
        raise not_found("campaign")
    return campaign


def list_campaign_runs(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
) -> list[Run]:
    get_campaign(db, tenant_id=tenant_id, campaign_id=campaign_id)
    return list(
        db.scalars(
            select(Run)
            .where(
                Run.tenant_id == tenant_id,
                Run.campaign_id == campaign_id,
            )
            .order_by(desc(Run.created_at))
        )
    )


def list_campaign_findings(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
) -> list[Finding]:
    get_campaign(db, tenant_id=tenant_id, campaign_id=campaign_id)
    return list(
        db.scalars(
            select(Finding)
            .where(
                Finding.tenant_id == tenant_id,
                Finding.campaign_id == campaign_id,
            )
            .order_by(desc(Finding.created_at))
        )
    )


def request_campaign_execution(
    db: Session,
    *,
    tenant: Tenant,
    campaign_id: uuid.UUID,
    request_id: str | None,
) -> tuple[Campaign, Run]:
    campaign = get_campaign(
        db,
        tenant_id=tenant.id,
        campaign_id=campaign_id,
        for_update=True,
    )
    if campaign.status in _ACTIVE_CAMPAIGN_STATUSES:
        raise conflict(
            "campaign_already_active",
            "This campaign already has a queued or running execution.",
        )

    run = Run(
        tenant_id=tenant.id,
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
        tenant_id=tenant.id,
        actor=actor_for_tenant(tenant),
        action="campaign.execution_requested",
        resource_type="campaign",
        resource_id=str(campaign.id),
        request_id=request_id,
        details={"run_id": str(run.id), "source": "api"},
    )
    db.commit()

    try:
        enqueue_existing_run(run_id=run.id, source="api")
    except Exception as exc:
        logger.exception(
            "campaign_dispatch_failed",
            campaign_id=str(campaign.id),
            run_id=str(run.id),
            error_type=exc.__class__.__name__,
        )
        raise service_unavailable(
            "campaign_dispatch_unavailable",
            "The campaign was persisted but could not be dispatched to a worker.",
        ) from exc

    db.expire_all()
    refreshed_campaign = get_campaign(
        db,
        tenant_id=tenant.id,
        campaign_id=campaign.id,
    )
    refreshed_run = db.get(Run, run.id)
    if refreshed_run is None:
        raise RuntimeError(f"Run {run.id} disappeared after enqueue.")
    return refreshed_campaign, refreshed_run


def cancel_campaign(
    db: Session,
    *,
    tenant: Tenant,
    campaign_id: uuid.UUID,
    request_id: str | None,
) -> tuple[Campaign, Run | None]:
    campaign = get_campaign(
        db,
        tenant_id=tenant.id,
        campaign_id=campaign_id,
        for_update=True,
    )
    latest_run = db.scalar(
        select(Run)
        .where(
            Run.campaign_id == campaign.id,
            Run.tenant_id == tenant.id,
        )
        .order_by(desc(Run.created_at))
        .limit(1)
        .with_for_update()
    )

    if campaign.status == CampaignStatus.CANCELLED:
        return campaign, latest_run

    active_run = latest_run if latest_run and latest_run.status in _ACTIVE_RUN_STATUSES else None
    if active_run is None and campaign.status in _TERMINAL_CAMPAIGN_STATUSES:
        raise conflict(
            "campaign_not_active",
            "A completed or failed campaign has no active execution to cancel.",
        )

    now = datetime.now(timezone.utc)
    if active_run is not None:
        active_run.cancel_requested_at = now
        active_run.status = RunStatus.CANCELLED
        active_run.completed_at = now
        active_run.summary = {
            **dict(active_run.summary or {}),
            "status": RunStatus.CANCELLED.value,
            "run_id": str(active_run.id),
            "campaign_id": str(campaign.id),
            "cancelled": True,
        }

    campaign.status = CampaignStatus.CANCELLED
    campaign.completed_at = now
    campaign.schedule_at = None
    campaign.last_error = None
    record_audit_log(
        db,
        tenant_id=tenant.id,
        actor=actor_for_tenant(tenant),
        action="campaign.cancelled",
        resource_type="campaign",
        resource_id=str(campaign.id),
        request_id=request_id,
        details={"run_id": str(active_run.id) if active_run else None},
    )
    db.commit()

    if active_run is not None and active_run.celery_task_id:
        try:
            from worker.celery_app import celery_app

            celery_app.control.revoke(active_run.celery_task_id, terminate=False)
        except Exception as exc:  # Cancellation remains persisted if the broker is unavailable.
            logger.warning(
                "campaign_task_revoke_failed",
                campaign_id=str(campaign.id),
                run_id=str(active_run.id),
                error_type=exc.__class__.__name__,
            )

    db.refresh(campaign)
    if active_run is not None:
        db.refresh(active_run)
    logger.info(
        "campaign_cancelled",
        campaign_id=str(campaign.id),
        tenant_id=str(tenant.id),
        run_id=str(active_run.id) if active_run else None,
    )
    return campaign, active_run or latest_run


def enqueue_existing_run(*, run_id: uuid.UUID, source: str) -> str:
    """Persist a task ID, send one queued run to Celery, and return that identifier."""

    task_id = str(uuid.uuid4())
    with SessionLocal() as db:
        run = db.scalar(select(Run).where(Run.id == run_id).with_for_update())
        if run is None:
            raise RuntimeError(f"Run {run_id} does not exist.")
        if run.status != RunStatus.QUEUED:
            raise RuntimeError(
                f"Run {run_id} cannot be enqueued from status {run.status.value}."
            )
        run.celery_task_id = task_id
        db.commit()

    try:
        from worker.tasks import execute_campaign

        execute_campaign.apply_async(
            kwargs={"run_id": str(run_id)},
            task_id=task_id,
        )
    except Exception as exc:
        _mark_enqueue_failed(run_id=run_id, exc=exc)
        raise

    CAMPAIGN_EXECUTION_REQUESTS.labels(source=source).inc()
    logger.info(
        "campaign_run_enqueued",
        run_id=str(run_id),
        celery_task_id=task_id,
        source=source,
    )
    return task_id


def _mark_enqueue_failed(*, run_id: uuid.UUID, exc: Exception) -> None:
    with SessionLocal() as db:
        campaign_id = db.scalar(select(Run.campaign_id).where(Run.id == run_id))
        if campaign_id is None:
            return
        campaign = db.scalar(
            select(Campaign).where(Campaign.id == campaign_id).with_for_update()
        )
        run = db.scalar(select(Run).where(Run.id == run_id).with_for_update())
        if run is None or campaign is None or run.status not in _ACTIVE_RUN_STATUSES:
            return

        error_message = f"{exc.__class__.__name__}: {str(exc)}"[:2_000]
        now = datetime.now(timezone.utc)
        run.status = RunStatus.FAILED
        run.completed_at = now
        run.error = error_message
        run.summary = {
            "status": RunStatus.FAILED.value,
            "run_id": str(run.id),
            "campaign_id": str(campaign.id),
            "error_type": exc.__class__.__name__,
        }
        if campaign.status in _ACTIVE_CAMPAIGN_STATUSES:
            campaign.status = CampaignStatus.FAILED
            campaign.completed_at = now
            campaign.last_error = error_message
        record_audit_log(
            db,
            tenant_id=run.tenant_id,
            actor="system:dispatcher",
            action="campaign.enqueue_failed",
            resource_type="run",
            resource_id=str(run.id),
            request_id=None,
            details={"error_type": exc.__class__.__name__},
        )
        db.commit()


def _normalize_schedule(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise bad_request(
            "invalid_schedule",
            "schedule_at must include an explicit timezone offset.",
        )
    return value.astimezone(timezone.utc)
