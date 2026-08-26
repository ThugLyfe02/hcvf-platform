from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from app.core.errors import bad_request, not_found
from app.core.security import get_current_tenant
from app.db.session import get_db
from app.models import Campaign, Run, Tenant
from app.services.campaign_service import CampaignService
from worker.tasks import execute_campaign

router = APIRouter(prefix="/api/v1/campaigns", tags=["campaigns"])


class CampaignCreate(BaseModel):
    name: str
    target_url: HttpUrl
    authorization_attested: bool
    scheduled_at: datetime | None = None


class CampaignResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    target_url: str
    authorization_attested: bool
    status: str
    scheduled_at: datetime | None
    created_at: datetime
    updated_at: datetime


class RunResponse(BaseModel):
    id: UUID
    campaign_id: UUID
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    http_status: int | None
    error_message: str | None


def campaign_to_response(campaign: Campaign) -> CampaignResponse:
    return CampaignResponse(
        id=campaign.id,
        tenant_id=campaign.tenant_id,
        name=campaign.name,
        target_url=campaign.target_url,
        authorization_attested=campaign.authorization_attested,
        status=campaign.status.value,
        scheduled_at=campaign.scheduled_at,
        created_at=campaign.created_at,
        updated_at=campaign.updated_at,
    )


def run_to_response(run: Run) -> RunResponse:
    return RunResponse(
        id=run.id,
        campaign_id=run.campaign_id,
        status=run.status.value,
        started_at=run.started_at,
        completed_at=run.completed_at,
        http_status=run.http_status,
        error_message=run.error_message,
    )


@router.post("", response_model=CampaignResponse, status_code=status.HTTP_201_CREATED)
def create_campaign(
    payload: CampaignCreate,
    request: Request,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> CampaignResponse:
    if not payload.authorization_attested:
        raise bad_request("authorization_attested must be true for an executable campaign")
    service = CampaignService(db)
    campaign = service.create_campaign(
        tenant=tenant,
        name=payload.name.strip(),
        target_url=str(payload.target_url),
        authorization_attested=payload.authorization_attested,
        scheduled_at=payload.scheduled_at,
        actor=request.state.actor,
        request_id=request.state.request_id,
    )
    return campaign_to_response(campaign)


@router.get("/{campaign_id}", response_model=CampaignResponse)
def get_campaign(
    campaign_id: UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> CampaignResponse:
    campaign = CampaignService(db).get_campaign(tenant_id=tenant.id, campaign_id=campaign_id)
    if campaign is None:
        raise not_found("Campaign")
    return campaign_to_response(campaign)


@router.post("/{campaign_id}/execute", response_model=RunResponse, status_code=status.HTTP_202_ACCEPTED)
def execute_campaign_endpoint(
    campaign_id: UUID,
    request: Request,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> RunResponse:
    service = CampaignService(db)
    campaign = service.get_campaign(tenant_id=tenant.id, campaign_id=campaign_id)
    if campaign is None:
        raise not_found("Campaign")
    try:
        run = service.create_run(campaign=campaign, actor=request.state.actor, request_id=request.state.request_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    execute_campaign.delay(str(run.id))
    return run_to_response(run)
