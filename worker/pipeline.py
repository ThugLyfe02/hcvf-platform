from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.metrics import CAMPAIGNS_COMPLETED, FINDINGS_DETECTED, TASK_DURATION
from app.models import Campaign, CampaignStatus, Finding, Run, RunStatus
from worker.fuzz_runner import FuzzRunner

logger = logging.getLogger(__name__)


class CampaignPipeline:
    def __init__(self, db: Session, runner: FuzzRunner | None = None) -> None:
        self.db = db
        self.runner = runner or FuzzRunner()

    def execute(self, run_id: UUID) -> Run:
        started = time.perf_counter()
        run = self.db.scalar(select(Run).where(Run.id == run_id).with_for_update())
        if run is None:
            raise ValueError(f"Run {run_id} not found")

        campaign = self.db.scalar(select(Campaign).where(Campaign.id == run.campaign_id))
        if campaign is None:
            raise ValueError(f"Campaign {run.campaign_id} not found")
        if not campaign.authorization_attested:
            raise ValueError("Campaign authorization attestation is missing")

        run.status = RunStatus.running
        run.started_at = datetime.now(timezone.utc)
        campaign.status = CampaignStatus.running
        self.db.commit()

        logger.info(
            "campaign run started",
            extra={
                "run_id": run.id,
                "campaign_id": campaign.id,
                "tenant_id": campaign.tenant_id,
            },
        )

        try:
            result = self.runner.run(campaign.target_url)
            finding = Finding(
                run_id=run.id,
                kind="http_reachability",
                severity="info" if result.http_status < 500 else "medium",
                title="Authorized target reachability validation",
                detail=f"Target returned HTTP {result.http_status}",
                evidence={
                    "final_url": result.final_url,
                    "http_status": result.http_status,
                    "server": result.headers.get("server"),
                },
            )
            self.db.add(finding)

            run.http_status = result.http_status
            run.status = RunStatus.completed
            run.completed_at = datetime.now(timezone.utc)
            campaign.status = CampaignStatus.completed
            self.db.commit()

            FINDINGS_DETECTED.inc()
            CAMPAIGNS_COMPLETED.inc()

            logger.info(
                "campaign run completed",
                extra={
                    "run_id": run.id,
                    "campaign_id": campaign.id,
                    "tenant_id": campaign.tenant_id,
                    "finding_id": finding.id,
                    "http_status": result.http_status,
                },
            )
        except Exception as exc:
            self.db.rollback()
            run = self.db.get(Run, run_id)
            if run is None:
                raise
            campaign = self.db.get(Campaign, run.campaign_id)
            run.status = RunStatus.failed
            run.completed_at = datetime.now(timezone.utc)
            run.error_message = f"{exc.__class__.__name__}: {exc}"
            if campaign is not None:
                campaign.status = CampaignStatus.failed
            self.db.commit()

            logger.exception(
                "campaign run failed",
                extra={
                    "run_id": run.id,
                    "campaign_id": run.campaign_id,
                    "tenant_id": run.tenant_id,
                },
            )
            raise
        finally:
            duration = time.perf_counter() - started
            TASK_DURATION.observe(duration)
            logger.info(
                "campaign task duration recorded",
                extra={"run_id": run_id, "duration_seconds": duration},
            )

        self.db.refresh(run)
        return run
