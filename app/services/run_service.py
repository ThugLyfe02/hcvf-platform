from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Campaign, Finding, Run


class RunService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_runs_for_campaign(self, *, tenant_id: UUID, campaign_id: UUID) -> list[Run]:
        return list(
            self.db.scalars(
                select(Run)
                .join(Campaign, Run.campaign_id == Campaign.id)
                .where(Campaign.id == campaign_id, Campaign.tenant_id == tenant_id)
                .order_by(Run.created_at.desc())
            )
        )

    def get_run(self, *, tenant_id: UUID, campaign_id: UUID, run_id: UUID) -> Run | None:
        return self.db.scalar(
            select(Run)
            .join(Campaign, Run.campaign_id == Campaign.id)
            .where(
                Run.id == run_id,
                Campaign.id == campaign_id,
                Campaign.tenant_id == tenant_id,
            )
        )

    def list_findings_for_run(self, *, tenant_id: UUID, campaign_id: UUID, run_id: UUID) -> list[Finding]:
        return list(
            self.db.scalars(
                select(Finding)
                .join(Run, Finding.run_id == Run.id)
                .join(Campaign, Run.campaign_id == Campaign.id)
                .where(
                    Run.id == run_id,
                    Campaign.id == campaign_id,
                    Campaign.tenant_id == tenant_id,
                )
                .order_by(Finding.created_at.desc())
            )
        )

    def get_finding(
        self,
        *,
        tenant_id: UUID,
        campaign_id: UUID,
        run_id: UUID,
        finding_id: UUID,
    ) -> Finding | None:
        return self.db.scalar(
            select(Finding)
            .join(Run, Finding.run_id == Run.id)
            .join(Campaign, Run.campaign_id == Campaign.id)
            .where(
                Finding.id == finding_id,
                Run.id == run_id,
                Campaign.id == campaign_id,
                Campaign.tenant_id == tenant_id,
            )
        )
