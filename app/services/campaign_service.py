from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Campaign, CampaignStatus, Run, RunStatus, Tenant
from app.services.audit_service import AuditService


class CampaignService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)

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
        if not authorization_attested:
            raise ValueError("Campaign cannot be created without authorization attestation")
        if not self._is_authorized_target(target_url, tenant.authorized_targets):
            raise ValueError("Campaign target is not authorized for this tenant")

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
        self.audit.record(
            tenant_id=tenant.id,
            action="campaign.create",
            details={
                "name": name,
                "target_url": target_url,
                "scheduled_at": scheduled_at.isoformat() if scheduled_at else None,
            },
            user_id=actor,
            resource_type="campaign",
            resource_id=str(campaign.id),
            request_id=request_id,
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
        self.audit.record(
            tenant_id=campaign.tenant_id,
            action="campaign.cancel",
            details={},
            user_id=actor,
            resource_type="campaign",
            resource_id=str(campaign.id),
            request_id=request_id,
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
        self.audit.record(
            tenant_id=campaign.tenant_id,
            action="campaign.execute",
            details={"run_id": str(run.id)},
            user_id=actor,
            resource_type="campaign",
            resource_id=str(campaign.id),
            request_id=request_id,
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

    @staticmethod
    def _is_authorized_target(target_url: str, authorized_targets: list[str]) -> bool:
        target = urlsplit(target_url)
        if not target.scheme or not target.hostname:
            return False

        target_scheme = target.scheme.lower()
        target_host = target.hostname.lower()
        target_port = target.port
        development = settings.environment.lower() == "development"
        loopback_hosts = {"127.0.0.1", "localhost", "::1"}

        for authorized in authorized_targets:
            candidate = urlsplit(authorized)
            if not candidate.scheme or not candidate.hostname:
                continue
            if candidate.scheme.lower() != target_scheme:
                continue
            if candidate.hostname.lower() != target_host:
                continue

            candidate_host = candidate.hostname.lower()
            if development and candidate_host in loopback_hosts:
                return True

            if candidate.port != target_port:
                continue
            return True
        return False
