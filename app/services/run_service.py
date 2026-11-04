from __future__ import annotations

from uuid import UUID

from sqlalchemy import or_, select
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

    def list_findings_for_run(
        self,
        *,
        tenant_id: UUID,
        campaign_id: UUID,
        run_id: UUID,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[Finding]:
        """Findings observed by a run, including issues first seen earlier.

        Findings are aggregated per issue, so a run that re-observes a known
        issue updates ``last_run_id`` instead of inserting a duplicate row. The
        run must still be resolved first, which is what enforces campaign and
        tenant scope.
        """

        if self.get_run(tenant_id=tenant_id, campaign_id=campaign_id, run_id=run_id) is None:
            return []

        query = select(Finding).where(
            Finding.tenant_id == tenant_id,
            or_(Finding.run_id == run_id, Finding.last_run_id == run_id),
        )
        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        return list(self.db.scalars(query.order_by(Finding.severity.desc(), Finding.created_at.desc())))

    def get_finding(
        self,
        *,
        tenant_id: UUID,
        campaign_id: UUID,
        run_id: UUID,
        finding_id: UUID,
    ) -> Finding | None:
        if self.get_run(tenant_id=tenant_id, campaign_id=campaign_id, run_id=run_id) is None:
            return None
        return self.db.scalar(
            select(Finding).where(
                Finding.id == finding_id,
                Finding.tenant_id == tenant_id,
                or_(Finding.run_id == run_id, Finding.last_run_id == run_id),
            )
        )
