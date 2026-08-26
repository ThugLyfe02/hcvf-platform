from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, Campaign, CampaignStatus, Run, RunStatus, Tenant


class CampaignService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_campaign(
        self,
        *,
        tenant: Tenant,
        name: str,
        target_url: str,
        authorization_attested: bool,
        scheduled_at: datetime | None,
        actor: str,
        request_id: str | None,
    ) -> Campaign:
        campaign = Campaign(
            tenant_id=tenant.id,
            name=name,
            target_url=target_url,
            authorization_attested=authorization_attested,
            scheduled_at=scheduled_at,
            status=CampaignStatus.draft,
        )
        self.db.add(campaign)
        self.db.flush()
        self._audit(
            tenant_id=tenant.id,
            actor=actor,
            action="campaign.create",
            resource_type="campaign",
            resource_id=str(campaign.id),
            request_id=request_id,
            detail={
                "name": name,
                "target_url": target_url,
                "scheduled_at": scheduled_at.isoformat() if scheduled_at else None,
            },
        )
        self.db.commit()
        self.db.refresh(campaign)
        return campaign

    def list_campaigns(self, *, tenant_id: UUID) -> list[Campaign]:
        return list(
            self.db.scalars(
                select(Campaign)
                .where(Campaign.tenant_id == tenant_id)
                .order_by(Campaign.created_at.desc())
            )
        )

    def get_campaign(self, *, tenant_id: UUID, campaign_id: UUID) -> Campaign | None:
        return self.db.scalar(
            select(Campaign).where(Campaign.id == campaign_id, Campaign.tenant_id == tenant_id)
        )

    def cancel_campaign(
        self,
        *,
        campaign: Campaign,
        actor: str,
        request_id: str | None,
    ) -> Campaign:
        if campaign.status in {CampaignStatus.completed, CampaignStatus.failed, CampaignStatus.cancelled}:
            raise ValueError(f"Campaign in {campaign.status.value} state cannot be cancelled")
        if campaign.status == CampaignStatus.running:
            raise ValueError("Running campaign cannot be cancelled through the control plane")

        campaign.status = CampaignStatus.cancelled
        self._audit(
            tenant_id=campaign.tenant_id,
            actor=actor,
            action="campaign.cancel",
            resource_type="campaign",
            resource_id=str(campaign.id),
            request_id=request_id,
            detail={},
        )
        self.db.commit()
        self.db.refresh(campaign)
        return campaign

    def create_run(
        self,
        *,
        campaign: Campaign,
        actor: str,
        request_id: str | None,
    ) -> Run:
        if not campaign.authorization_attested:
            raise ValueError("Campaign cannot execute without authorization attestation")
        if campaign.status == CampaignStatus.running:
            raise ValueError("Campaign is already running")
        if campaign.status == CampaignStatus.cancelled:
            raise ValueError("Cancelled campaign cannot execute")

        run = Run(campaign_id=campaign.id, status=RunStatus.queued)
        campaign.status = CampaignStatus.queued
        self.db.add(run)
        self.db.flush()
        self._audit(
            tenant_id=campaign.tenant_id,
            actor=actor,
            action="campaign.execute",
            resource_type="campaign",
            resource_id=str(campaign.id),
            request_id=request_id,
            detail={"run_id": str(run.id)},
        )
        self.db.commit()
        self.db.refresh(run)
        return run

    def claim_due_campaigns(self, *, limit: int = 20) -> list[Run]:
        now = datetime.now(timezone.utc)
        campaigns = list(
            self.db.scalars(
                select(Campaign)
                .where(
                    Campaign.status == CampaignStatus.draft,
                    Campaign.authorization_attested.is_(True),
                    Campaign.scheduled_at.is_not(None),
                    Campaign.scheduled_at <= now,
                )
                .with_for_update(skip_locked=True)
                .limit(limit)
            )
        )
        runs: list[Run] = []
        for campaign in campaigns:
            campaign.status = CampaignStatus.queued
            run = Run(campaign_id=campaign.id, status=RunStatus.queued)
            self.db.add(run)
            runs.append(run)
        self.db.commit()
        for run in runs:
            self.db.refresh(run)
        return runs

    def _audit(
        self,
        *,
        tenant_id: UUID,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        request_id: str | None,
        detail: dict,
    ) -> None:
        self.db.add(
            AuditLog(
                tenant_id=tenant_id,
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                request_id=request_id,
                detail=detail,
            )
        )
