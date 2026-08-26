from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Annotated

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.core.security import get_current_tenant
from app.db.session import get_db
from app.models.campaign import Campaign, CampaignStatus
from app.models.finding import Finding, FindingSeverity
from app.models.run import Run, RunStatus
from app.models.tenant import Tenant
from app.services.campaign_service import (
    cancel_campaign,
    create_campaign,
    get_campaign,
    list_campaign_findings,
    list_campaign_runs,
    list_campaigns,
    request_campaign_execution,
)

router = APIRouter(prefix="/campaigns", tags=["campaigns"])
DBSession = Annotated[Session, Depends(get_db)]
AuthenticatedTenant = Annotated[Tenant, Depends(get_current_tenant)]


class CampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_url: str = Field(min_length=8, max_length=2_048)
    authorization_reference: str = Field(min_length=3, max_length=500)
    config: dict[str, Any] = Field(default_factory=dict)
    schedule_at: datetime | None = None

    @field_validator("name", "target_url", "authorization_reference", mode="before")
    @classmethod
    def strip_required_text(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class CampaignRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    target_url: str
    authorization_reference: str
    status: CampaignStatus
    config: dict[str, Any]
    schedule_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class RunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    campaign_id: uuid.UUID
    celery_task_id: str | None
    status: RunStatus
    started_at: datetime | None
    completed_at: datetime | None
    cancel_requested_at: datetime | None
    summary: dict[str, Any]
    error: str | None
    created_at: datetime
    updated_at: datetime


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    campaign_id: uuid.UUID
    run_id: uuid.UUID
    title: str
    category: str
    severity: FindingSeverity
    fingerprint: str
    evidence: dict[str, Any]
    description: str
    created_at: datetime


class CampaignExecutionRead(BaseModel):
    campaign: CampaignRead
    run: RunRead


class CampaignCancellationRead(BaseModel):
    campaign: CampaignRead
    run: RunRead | None


@router.post("", response_model=CampaignRead, status_code=status.HTTP_201_CREATED)
def create_campaign_endpoint(
    payload: CampaignCreate,
    request: Request,
    db: DBSession,
    tenant: AuthenticatedTenant,
) -> Campaign:
    return create_campaign(
        db,
        tenant=tenant,
        name=payload.name,
        target_url=payload.target_url,
        authorization_reference=payload.authorization_reference,
        config=payload.config,
        schedule_at=payload.schedule_at,
        request_id=request.state.request_id,
    )


@router.get("", response_model=list[CampaignRead])
def list_campaigns_endpoint(
    db: DBSession,
    tenant: AuthenticatedTenant,
) -> list[Campaign]:
    return list_campaigns(db, tenant_id=tenant.id)


@router.get("/{campaign_id}", response_model=CampaignRead)
def get_campaign_endpoint(
    campaign_id: uuid.UUID,
    db: DBSession,
    tenant: AuthenticatedTenant,
) -> Campaign:
    return get_campaign(db, tenant_id=tenant.id, campaign_id=campaign_id)


@router.post(
    "/{campaign_id}/execute",
    response_model=CampaignExecutionRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def execute_campaign_endpoint(
    campaign_id: uuid.UUID,
    request: Request,
    db: DBSession,
    tenant: AuthenticatedTenant,
) -> CampaignExecutionRead:
    campaign, run = request_campaign_execution(
        db,
        tenant=tenant,
        campaign_id=campaign_id,
        request_id=request.state.request_id,
    )
    return CampaignExecutionRead(
        campaign=CampaignRead.model_validate(campaign),
        run=RunRead.model_validate(run),
    )


@router.post("/{campaign_id}/cancel", response_model=CampaignCancellationRead)
def cancel_campaign_endpoint(
    campaign_id: uuid.UUID,
    request: Request,
    db: DBSession,
    tenant: AuthenticatedTenant,
) -> CampaignCancellationRead:
    campaign, run = cancel_campaign(
        db,
        tenant=tenant,
        campaign_id=campaign_id,
        request_id=request.state.request_id,
    )
    return CampaignCancellationRead(
        campaign=CampaignRead.model_validate(campaign),
        run=RunRead.model_validate(run) if run is not None else None,
    )


@router.get("/{campaign_id}/runs", response_model=list[RunRead])
def list_campaign_runs_endpoint(
    campaign_id: uuid.UUID,
    db: DBSession,
    tenant: AuthenticatedTenant,
) -> list[Run]:
    return list_campaign_runs(db, tenant_id=tenant.id, campaign_id=campaign_id)


@router.get("/{campaign_id}/findings", response_model=list[FindingRead])
def list_campaign_findings_endpoint(
    campaign_id: uuid.UUID,
    db: DBSession,
    tenant: AuthenticatedTenant,
) -> list[Finding]:
    return list_campaign_findings(db, tenant_id=tenant.id, campaign_id=campaign_id)
