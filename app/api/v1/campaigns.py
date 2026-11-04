from __future__ import annotations

import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import bad_request, not_found
from app.core.metrics import CAMPAIGNS_CREATED
from app.core.security import require_scope
from app.db.session import get_db
from app.models import Campaign, Run, Tenant
from app.services import idempotency, quotas
from app.services.campaign_service import CampaignService
from app.services.profiles import ProfileError, get_profile

router = APIRouter(prefix="/api/v1/campaigns", tags=["campaigns"])


class CampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    target_url: HttpUrl
    authorization_attested: bool
    scheduled_at: datetime | None = None
    safety_ceiling: Literal["read_only", "state_changing", "destructive"] = "read_only"
    budget_requests: int = Field(default=200, ge=1, le=5000)
    mode: Literal["agentic"] = "agentic"
    profile: str | None = None


class CampaignResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    target_url: str
    authorization_attested: bool
    status: str
    scheduled_at: datetime | None
    safety_ceiling: str
    budget_requests: int
    mode: str
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
    plan_seed: int | None
    evidence_root: str | None
    cancel_requested: bool


def campaign_to_response(campaign: Campaign) -> CampaignResponse:
    return CampaignResponse(
        id=campaign.id,
        tenant_id=campaign.tenant_id,
        name=campaign.name,
        target_url=campaign.target_url,
        authorization_attested=campaign.authorization_attested,
        status=campaign.status.value,
        scheduled_at=campaign.scheduled_at,
        safety_ceiling=campaign.safety_ceiling,
        budget_requests=campaign.budget_requests,
        mode=campaign.mode,
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
        plan_seed=run.plan_seed,
        evidence_root=run.evidence_root,
        cancel_requested=run.cancel_requested,
    )


@router.post("", response_model=CampaignResponse, status_code=status.HTTP_201_CREATED)
def create_campaign(
    payload: CampaignCreate,
    request: Request,
    tenant: Tenant = Depends(require_scope("campaigns:write")),
    db: Session = Depends(get_db),
) -> CampaignResponse:
    if not payload.authorization_attested:
        raise bad_request("authorization_attested must be true for an executable campaign")

    record, state = idempotency.claim(
        db,
        tenant_id=tenant.id,
        key=request.headers.get("Idempotency-Key"),
        payload=payload.model_dump(mode="json"),
    )
    if state == idempotency.CONFLICT:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Idempotency-Key reused with a different body")
    if state == idempotency.IN_PROGRESS:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Request with this key is in progress")
    if state == idempotency.REPLAY and record is not None:
        return JSONResponse(status_code=record.status_code or 201, content=record.response)

    budget_requests = payload.budget_requests
    safety_ceiling = payload.safety_ceiling
    genome: dict = {}
    if payload.profile:
        try:
            profile = get_profile(payload.profile)
        except ProfileError as exc:
            raise bad_request(str(exc)) from exc
        if budget_requests == 200:
            budget_requests = int(profile["budget_requests"])  # type: ignore[arg-type]
        if safety_ceiling == "read_only":
            safety_ceiling = str(profile["safety_ceiling"])
        genome = dict(profile.get("genome") or {})

    try:
        campaign = CampaignService(db).create_campaign(
            tenant=tenant,
            name=payload.name,
            target_url=str(payload.target_url),
            authorization_attested=payload.authorization_attested,
            scheduled_at=payload.scheduled_at,
            actor=request.state.actor,
            request_id=request.state.request_id,
            safety_ceiling=safety_ceiling,
            budget_requests=budget_requests,
            mode=payload.mode,
            genome=genome,
        )
    except ValueError as exc:
        raise bad_request(str(exc)) from exc
    CAMPAIGNS_CREATED.inc()
    response = campaign_to_response(campaign)
    idempotency.complete(
        db,
        record,
        status_code=201,
        body=json.loads(response.model_dump_json()),
    )
    return response


@router.get("", response_model=list[CampaignResponse])
def list_campaigns(
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    limit: int = 50,
    offset: int = 0,
) -> list[CampaignResponse]:
    campaigns = CampaignService(db).list_campaigns(tenant_id=tenant.id)
    return [campaign_to_response(campaign) for campaign in campaigns[offset : offset + min(limit, 200)]]


@router.get("/{campaign_id}", response_model=CampaignResponse)
def get_campaign(
    campaign_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> CampaignResponse:
    campaign = CampaignService(db).get_campaign(tenant_id=tenant.id, campaign_id=campaign_id)
    if campaign is None:
        raise not_found("Campaign")
    return campaign_to_response(campaign)


@router.post("/{campaign_id}/cancel", response_model=CampaignResponse)
def cancel_campaign(
    campaign_id: UUID,
    request: Request,
    tenant: Tenant = Depends(require_scope("campaigns:write")),
    db: Session = Depends(get_db),
) -> CampaignResponse:
    service = CampaignService(db)
    campaign = service.get_campaign(tenant_id=tenant.id, campaign_id=campaign_id)
    if campaign is None:
        raise not_found("Campaign")
    try:
        campaign = service.cancel_campaign(
            campaign=campaign,
            actor=request.state.actor,
            request_id=request.state.request_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return campaign_to_response(campaign)


@router.post("/{campaign_id}/execute", response_model=RunResponse, status_code=status.HTTP_202_ACCEPTED)
def execute_campaign_endpoint(
    campaign_id: UUID,
    request: Request,
    tenant: Tenant = Depends(require_scope("campaigns:write")),
    db: Session = Depends(get_db),
) -> RunResponse:
    record, state = idempotency.claim(
        db,
        tenant_id=tenant.id,
        key=request.headers.get("Idempotency-Key"),
        payload={"campaign_id": str(campaign_id), "action": "execute"},
    )
    if state == idempotency.CONFLICT:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Idempotency-Key reused for a different request"
        )
    if state == idempotency.IN_PROGRESS:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Request with this key is in progress")
    if state == idempotency.REPLAY and record is not None:
        return JSONResponse(status_code=record.status_code or 202, content=record.response)

    service = CampaignService(db)
    try:
        run = service.create_run(
            campaign_id=campaign_id,
            tenant_id=tenant.id,
            actor=request.state.actor,
            request_id=request.state.request_id,
        )
    except LookupError as exc:
        raise not_found("Campaign") from exc
    except quotas.QuotaExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    # The request returns as soon as the run and its outbox intent are committed.
    # Publishing is the relay's job: coupling a 202 to broker health is how you
    # turn a Redis blip into a client-visible outage.
    response = run_to_response(run)
    idempotency.complete(db, record, status_code=202, body=json.loads(response.model_dump_json()))
    return response


@router.get("/{campaign_id}/risk-trend")
def risk_trend(
    campaign_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    limit: int = 30,
) -> dict[str, object]:
    """Risk score per completed run, oldest first, for trend reporting."""

    from app.models import Run

    campaign = CampaignService(db).get_campaign(tenant_id=tenant.id, campaign_id=campaign_id)
    if campaign is None:
        raise not_found("Campaign")
    runs = list(
        db.scalars(
            select(Run)
            .where(Run.campaign_id == campaign.id, Run.risk_score.is_not(None))
            .order_by(Run.created_at.asc())
            .limit(max(1, min(limit, 200)))
        )
    )
    return {
        "campaign_id": str(campaign.id),
        "points": [
            {
                "run_id": str(run.id),
                "at": run.created_at.isoformat(),
                "risk_score": run.risk_score,
                "findings": None,
            }
            for run in runs
        ],
    }
