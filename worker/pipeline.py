from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.metrics import CAMPAIGN_RUNS
from app.models import Campaign, CampaignStatus, Finding, Run, RunStatus
from worker.fuzz_runner import FuzzRunner

logger = logging.getLogger(__name__)


class CampaignPipeline:
    def __init__(self, db: Session, runner: FuzzRunner | None = None):
        self.db = db
        self.runner = runner or FuzzRunner()

    def execute(self, run_id: UUID) -> Run:
        run = self.db.scalar(
            select(Run).where(Run.id == run_id).with_for_update()
        )
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
            extra={"run_id": run.id, "campaign_id": campaign.id, "tenant_id": campaign.tenant_id},
        )

        try:
            result = self.runner.run(campaign.target_url)
            run.http_status = result.http_status
            run.status = RunStatus.completed
            run.completed_at = datetime.now(timezone.utc)
            campaign.status = CampaignStatus.completed
            self.db.add(
                Finding(
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
            )
            CAMPAIGN_RUNS.labels("completed").inc()
            logger.info(
                "campaign run completed",
                extra={"run_id": run.id, "campaign_id": campaign.id, "tenant_id": campaign.tenant_id},
            )
        except Exception as exc:
            run.status = RunStatus.failed
            run.completed_at = datetime.now(timezone.utc)
            run.error_message = f"{exc.__class__.__name__}: {exc}"
            campaign.status = CampaignStatus.failed
            CAMPAIGN_RUNS.labels("failed").inc()
            logger.exception(
                "campaign run failed",
                extra={"run_id": run.id, "campaign_id": campaign.id, "tenant_id": campaign.tenant_id},
            )
        finally:
            self.db.commit()
            self.db.refresh(run)

        return run
