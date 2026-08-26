from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.campaign import Campaign, CampaignStatus
from app.models.finding import Finding
from app.models.run import Run, RunStatus
from app.services.audit_service import record_audit_log
from worker.fuzz_runner import FuzzFinding, FuzzRunner

logger = structlog.get_logger(__name__)

_TERMINAL_RUN_STATUSES = {
    RunStatus.COMPLETED,
    RunStatus.FAILED,
    RunStatus.CANCELLED,
}


@dataclass(frozen=True, slots=True)
class _RunClaim:
    target_url: str | None
    config: dict[str, Any]
    short_circuit_result: dict[str, Any] | None = None


class CampaignPipeline:
    """Lock-protected, idempotent campaign state machine executed by Celery."""

    def __init__(
        self,
        *,
        run_id: str | uuid.UUID,
        task_id: str | None = None,
    ) -> None:
        self.run_id = uuid.UUID(str(run_id))
        self.task_id = task_id

    def execute(self) -> dict[str, Any]:
        claim = self._claim_run()
        if claim.short_circuit_result is not None:
            return claim.short_circuit_result
        if claim.target_url is None:
            raise RuntimeError(f"Run {self.run_id} was claimed without a target URL.")

        try:
            result = FuzzRunner(target_url=claim.target_url, config=claim.config).execute()
            return self._persist_result(result.summary, result.findings)
        except Exception as exc:
            try:
                failure_result = self._mark_failed(exc)
            except Exception as persistence_exc:
                logger.exception(
                    "campaign_failure_persistence_failed",
                    run_id=str(self.run_id),
                    original_error_type=exc.__class__.__name__,
                    persistence_error_type=persistence_exc.__class__.__name__,
                )
                raise exc from persistence_exc

            if failure_result["status"] != RunStatus.FAILED.value:
                return failure_result

            logger.exception(
                "campaign_run_failed",
                run_id=str(self.run_id),
                error_type=exc.__class__.__name__,
            )
            raise

    def _claim_run(self) -> _RunClaim:
        with SessionLocal() as db:
            campaign, run = self._lock_run_and_campaign(db)

            if run.status in _TERMINAL_RUN_STATUSES:
                logger.info(
                    "campaign_terminal_delivery_ignored",
                    campaign_id=str(campaign.id),
                    run_id=str(run.id),
                    status=run.status.value,
                )
                return _RunClaim(
                    target_url=None,
                    config={},
                    short_circuit_result=_run_result(run, campaign),
                )

            if run.cancel_requested_at is not None:
                self._transition_cancelled(
                    db,
                    campaign=campaign,
                    run=run,
                    action="campaign.run_cancelled_before_start",
                    summary=dict(run.summary or {}),
                )
                db.commit()
                logger.info(
                    "campaign_run_cancelled_before_start",
                    campaign_id=str(campaign.id),
                    run_id=str(run.id),
                )
                return _RunClaim(
                    target_url=None,
                    config={},
                    short_circuit_result=_run_result(run, campaign),
                )

            if (
                self.task_id is not None
                and run.celery_task_id is not None
                and run.celery_task_id != self.task_id
            ):
                logger.warning(
                    "campaign_duplicate_delivery_ignored",
                    campaign_id=str(campaign.id),
                    run_id=str(run.id),
                    persisted_task_id=run.celery_task_id,
                    received_task_id=self.task_id,
                    status=run.status.value,
                )
                return _RunClaim(
                    target_url=None,
                    config={},
                    short_circuit_result=_run_result(run, campaign),
                )

            now = datetime.now(timezone.utc)
            resumed = run.status == RunStatus.RUNNING
            if self.task_id is not None and run.celery_task_id is None:
                run.celery_task_id = self.task_id
            run.status = RunStatus.RUNNING
            run.started_at = run.started_at or now
            run.completed_at = None
            run.error = None
            run.summary = {
                **dict(run.summary or {}),
                "status": RunStatus.RUNNING.value,
                "run_id": str(run.id),
                "campaign_id": str(campaign.id),
            }
            campaign.status = CampaignStatus.RUNNING
            campaign.started_at = run.started_at
            campaign.completed_at = None
            campaign.last_error = None
            record_audit_log(
                db,
                tenant_id=run.tenant_id,
                actor="system:celery-worker",
                action=("campaign.run_resumed" if resumed else "campaign.run_started"),
                resource_type="run",
                resource_id=str(run.id),
                request_id=None,
                details={
                    "campaign_id": str(campaign.id),
                    "celery_task_id": run.celery_task_id,
                },
            )
            db.commit()
            logger.info(
                "campaign_run_resumed" if resumed else "campaign_run_started",
                campaign_id=str(campaign.id),
                run_id=str(run.id),
                celery_task_id=run.celery_task_id,
            )
            return _RunClaim(
                target_url=campaign.target_url,
                config=dict(campaign.config or {}),
            )

    def _persist_result(
        self,
        summary: dict[str, Any],
        fuzz_findings: list[FuzzFinding],
    ) -> dict[str, Any]:
        with SessionLocal() as db:
            campaign, run = self._lock_run_and_campaign(db)

            if run.status in _TERMINAL_RUN_STATUSES:
                return _run_result(run, campaign)

            if run.cancel_requested_at is not None:
                self._transition_cancelled(
                    db,
                    campaign=campaign,
                    run=run,
                    action="campaign.run_cancelled",
                    summary=summary,
                )
                db.commit()
                logger.info(
                    "campaign_run_cancelled",
                    campaign_id=str(campaign.id),
                    run_id=str(run.id),
                )
                return _run_result(run, campaign)

            if run.status != RunStatus.RUNNING:
                raise RuntimeError(
                    f"Run {run.id} cannot persist results from status {run.status.value}."
                )

            for fuzz_finding in fuzz_findings:
                db.add(
                    Finding(
                        tenant_id=run.tenant_id,
                        campaign_id=campaign.id,
                        run_id=run.id,
                        title=fuzz_finding.title,
                        category=fuzz_finding.category,
                        severity=fuzz_finding.severity,
                        fingerprint=fuzz_finding.fingerprint,
                        evidence=fuzz_finding.evidence,
                        description=fuzz_finding.description,
                    )
                )

            now = datetime.now(timezone.utc)
            terminal_summary = {
                **summary,
                "status": RunStatus.COMPLETED.value,
                "run_id": str(run.id),
                "campaign_id": str(campaign.id),
            }
            run.status = RunStatus.COMPLETED
            run.completed_at = now
            run.summary = terminal_summary
            run.error = None
            campaign.status = CampaignStatus.COMPLETED
            campaign.completed_at = now
            campaign.last_error = None
            record_audit_log(
                db,
                tenant_id=run.tenant_id,
                actor="system:celery-worker",
                action="campaign.run_completed",
                resource_type="run",
                resource_id=str(run.id),
                request_id=None,
                details={
                    "campaign_id": str(campaign.id),
                    "finding_count": len(fuzz_findings),
                },
            )
            db.commit()
            logger.info(
                "campaign_run_completed",
                campaign_id=str(campaign.id),
                run_id=str(run.id),
                finding_count=len(fuzz_findings),
            )
            return terminal_summary

    def _mark_failed(self, exc: Exception) -> dict[str, Any]:
        error_message = f"{exc.__class__.__name__}: {str(exc)}"[:2_000]
        with SessionLocal() as db:
            campaign, run = self._lock_run_and_campaign(db)

            if run.status in _TERMINAL_RUN_STATUSES:
                return _run_result(run, campaign)

            if run.cancel_requested_at is not None:
                self._transition_cancelled(
                    db,
                    campaign=campaign,
                    run=run,
                    action="campaign.run_cancelled_after_worker_error",
                    summary=dict(run.summary or {}),
                )
                db.commit()
                logger.info(
                    "campaign_run_cancelled_after_worker_error",
                    campaign_id=str(campaign.id),
                    run_id=str(run.id),
                    error_type=exc.__class__.__name__,
                )
                return _run_result(run, campaign)

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
            campaign.status = CampaignStatus.FAILED
            campaign.completed_at = now
            campaign.last_error = error_message
            record_audit_log(
                db,
                tenant_id=run.tenant_id,
                actor="system:celery-worker",
                action="campaign.run_failed",
                resource_type="run",
                resource_id=str(run.id),
                request_id=None,
                details={
                    "campaign_id": str(campaign.id),
                    "error_type": exc.__class__.__name__,
                },
            )
            db.commit()
            return _run_result(run, campaign)

    def _lock_run_and_campaign(self, db: Session) -> tuple[Campaign, Run]:
        campaign_id = db.scalar(select(Run.campaign_id).where(Run.id == self.run_id))
        if campaign_id is None:
            raise RuntimeError(f"Run {self.run_id} does not exist.")

        campaign = db.scalar(
            select(Campaign).where(Campaign.id == campaign_id).with_for_update()
        )
        run = db.scalar(
            select(Run)
            .where(Run.id == self.run_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if campaign is None or run is None:
            raise RuntimeError(f"Run {self.run_id} lost its campaign relationship.")
        return campaign, run

    @staticmethod
    def _transition_cancelled(
        db: Session,
        *,
        campaign: Campaign,
        run: Run,
        action: str,
        summary: dict[str, Any],
    ) -> None:
        now = datetime.now(timezone.utc)
        run.status = RunStatus.CANCELLED
        run.cancel_requested_at = run.cancel_requested_at or now
        run.completed_at = now
        run.summary = {
            **summary,
            "status": RunStatus.CANCELLED.value,
            "run_id": str(run.id),
            "campaign_id": str(campaign.id),
            "cancelled": True,
        }
        campaign.status = CampaignStatus.CANCELLED
        campaign.completed_at = now
        campaign.last_error = None
        record_audit_log(
            db,
            tenant_id=run.tenant_id,
            actor="system:celery-worker",
            action=action,
            resource_type="run",
            resource_id=str(run.id),
            request_id=None,
            details={"campaign_id": str(campaign.id)},
        )


def _run_result(run: Run, campaign: Campaign) -> dict[str, Any]:
    return {
        **dict(run.summary or {}),
        "status": run.status.value,
        "run_id": str(run.id),
        "campaign_id": str(campaign.id),
    }
