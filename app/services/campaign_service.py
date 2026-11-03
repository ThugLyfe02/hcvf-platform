from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Campaign, CampaignStatus, Run, RunStatus, Tenant
from app.services.audit_service import AuditService
from app.services.outbox import enqueue

VALID_SAFETY = {"read_only", "state_changing", "destructive"}


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
        safety_ceiling: str = "read_only",
        budget_requests: int = 200,
        mode: str = "agentic",
        origin: str = "manual",
        genome: dict | None = None,
    ) -> Campaign:
        if not authorization_attested:
            raise ValueError("Campaign cannot be created without authorization attestation")
        cleaned_name = name.strip()
        if not cleaned_name:
            raise ValueError("Campaign name is required")
        if len(cleaned_name) > 255:
            raise ValueError("Campaign name must be at most 255 characters")
        if safety_ceiling not in VALID_SAFETY:
            raise ValueError(f"safety_ceiling must be one of {sorted(VALID_SAFETY)}")
        if not 1 <= budget_requests <= 5000:
            raise ValueError("budget_requests must be between 1 and 5000")
        if not self._is_authorized_target(target_url, tenant.authorized_targets):
            raise ValueError("Campaign target is not authorized for this tenant")

        campaign = Campaign(
            tenant_id=tenant.id,
            name=cleaned_name,
            target_url=target_url,
            authorization_attested=authorization_attested,
            scheduled_at=scheduled_at,
            status=CampaignStatus.draft,
            safety_ceiling=safety_ceiling,
            budget_requests=budget_requests,
            mode=mode,
            origin=origin,
            genome=genome or {},
        )
        self.db.add(campaign)
        self.db.flush()
        self.audit.record(
            tenant_id=tenant.id,
            action="campaign.create",
            details={
                "name": cleaned_name,
                "target_url": target_url,
                "scheduled_at": scheduled_at.isoformat() if scheduled_at else None,
                "safety_ceiling": safety_ceiling,
                "budget_requests": budget_requests,
                "origin": origin,
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
                select(Campaign).where(Campaign.tenant_id == tenant_id).order_by(Campaign.created_at.desc())
            )
        )

    def get_campaign(self, *, tenant_id: UUID, campaign_id: UUID) -> Campaign | None:
        return self.db.scalar(select(Campaign).where(Campaign.id == campaign_id, Campaign.tenant_id == tenant_id))

    def cancel_campaign(self, *, campaign: Campaign, actor: str, request_id: str | None) -> Campaign:
        if campaign.status in {CampaignStatus.completed, CampaignStatus.failed, CampaignStatus.cancelled}:
            raise ValueError(f"Campaign in {campaign.status.value} state cannot be cancelled")

        campaign.status = CampaignStatus.cancelled
        # Signal the worker; the engine checks this between probes so a running
        # hunt stops at a request boundary rather than being killed mid-request.
        active_runs = list(
            self.db.scalars(
                select(Run).where(
                    Run.campaign_id == campaign.id,
                    Run.status.in_([RunStatus.queued, RunStatus.running]),
                )
            )
        )
        for run in active_runs:
            run.cancel_requested = True
            if run.status == RunStatus.queued:
                run.status = RunStatus.cancelled
                run.completed_at = datetime.now(UTC)
                run.error_message = "cancelled before execution"

        self.audit.record(
            tenant_id=campaign.tenant_id,
            action="campaign.cancel",
            details={"cancelled_runs": len(active_runs)},
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
        campaign_id: UUID,
        tenant_id: UUID,
        actor: str,
        request_id: str | None,
    ) -> Run:
        # Row lock closes the double-execute race that a plain status check
        # leaves open: two concurrent requests could both observe "not running".
        campaign = self.db.scalar(
            select(Campaign).where(Campaign.id == campaign_id, Campaign.tenant_id == tenant_id).with_for_update()
        )
        if campaign is None:
            raise LookupError("Campaign not found")
        if not campaign.authorization_attested:
            raise ValueError("Campaign cannot execute without authorization attestation")
        if campaign.status == CampaignStatus.running:
            raise ValueError("Campaign is already running")
        if campaign.status == CampaignStatus.queued:
            raise ValueError("Campaign already has a queued run")
        if campaign.status == CampaignStatus.cancelled:
            raise ValueError("Cancelled campaign cannot execute")

        from app.models import Tenant as TenantModel
        from app.services import quotas

        tenant = self.db.get(TenantModel, tenant_id)
        if tenant is not None:
            quotas.check_run_quota(self.db, tenant)

        run = Run(campaign_id=campaign.id, tenant_id=tenant_id, status=RunStatus.queued)
        campaign.status = CampaignStatus.queued
        self.db.add(run)
        self.db.flush()
        enqueue(self.db, topic="campaign.run", payload={"run_id": str(run.id)})
        self.audit.record(
            tenant_id=tenant_id,
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
        now = datetime.now(UTC)
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
            run = Run(campaign_id=campaign.id, tenant_id=campaign.tenant_id, status=RunStatus.queued)
            self.db.add(run)
            self.db.flush()
            enqueue(self.db, topic="campaign.run", payload={"run_id": str(run.id)})
            runs.append(run)
        self.db.commit()
        for run in runs:
            self.db.refresh(run)
        return runs

    def claim_cron_campaigns(self, *, now: datetime | None = None, limit: int = 20) -> list[Run]:
        """Create runs for cron-scheduled campaigns and advance their next slot."""

        from app.services.cron import next_run

        now = now or datetime.now(UTC)
        campaigns = list(
            self.db.scalars(
                select(Campaign)
                .where(
                    Campaign.cron.is_not(None),
                    Campaign.authorization_attested.is_(True),
                    Campaign.status.not_in([CampaignStatus.queued, CampaignStatus.running, CampaignStatus.cancelled]),
                )
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        runs: list[Run] = []
        for campaign in campaigns:
            if campaign.scheduled_at is None:
                campaign.scheduled_at = next_run(str(campaign.cron), after=now)
                continue
            due = campaign.scheduled_at
            if due.tzinfo is None:
                due = due.replace(tzinfo=UTC)
            if due > now:
                continue
            campaign.status = CampaignStatus.queued
            run = Run(campaign_id=campaign.id, tenant_id=campaign.tenant_id, status=RunStatus.queued)
            self.db.add(run)
            self.db.flush()
            enqueue(self.db, topic="campaign.run", payload={"run_id": str(run.id)})
            campaign.scheduled_at = next_run(str(campaign.cron), after=now)
            runs.append(run)
        self.db.commit()
        for run in runs:
            self.db.refresh(run)
        return runs

    @staticmethod
    def _is_authorized_target(target_url: str, authorized_targets: list[str]) -> bool:
        """Origin-and-port equality, with an explicit development loopback path.

        Scope is an authorization decision, so the default is deny. Loopback is
        permitted without a port match only in development, and it is logged by
        the caller as a development-mode grant.
        """

        target = urlsplit(target_url)
        if not target.scheme or not target.hostname:
            return False

        target_scheme = target.scheme.lower()
        target_host = target.hostname.lower()
        target_port = target.port or (443 if target_scheme == "https" else 80)
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

            candidate_port = candidate.port or (443 if candidate.scheme.lower() == "https" else 80)
            if candidate_port != target_port:
                continue
            return True
        return False
