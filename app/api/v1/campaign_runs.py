from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.security import get_current_tenant
from app.db.session import get_db
from app.models import Finding, Run, Tenant
from app.services.run_service import RunService

router = APIRouter(prefix="/api/v1/campaigns/{campaign_id}/runs", tags=["campaign-runs"])


class RunResponse(BaseModel):
    id: UUID
    campaign_id: UUID
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    http_status: int | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime


class FindingResponse(BaseModel):
    id: UUID
    run_id: UUID
    kind: str
    severity: str
    title: str
    detail: str
    evidence: dict
    created_at: datetime
    updated_at: datetime


def run_to_response(run: Run) -> RunResponse:
    return RunResponse(
        id=run.id,
        campaign_id=run.campaign_id,
        status=run.status.value,
        started_at=run.started_at,
        completed_at=run.completed_at,
        http_status=run.http_status,
        error_message=run.error_message,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


def finding_to_response(finding: Finding) -> FindingResponse:
    return FindingResponse(
        id=finding.id,
        run_id=finding.run_id,
        kind=finding.kind,
        severity=finding.severity,
        title=finding.title,
        detail=finding.detail,
        evidence=finding.evidence,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


@router.get("", response_model=list[RunResponse])
def list_runs(
    campaign_id: UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> list[RunResponse]:
    runs = RunService(db).list_runs_for_campaign(tenant_id=tenant.id, campaign_id=campaign_id)
    return [run_to_response(run) for run in runs]


@router.get("/{run_id}", response_model=RunResponse)
def get_run(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> RunResponse:
    run = RunService(db).get_run(tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return run_to_response(run)


@router.get("/{run_id}/findings", response_model=list[FindingResponse])
def list_findings(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> list[FindingResponse]:
    findings = RunService(db).list_findings_for_run(
        tenant_id=tenant.id,
        campaign_id=campaign_id,
        run_id=run_id,
    )
    return [finding_to_response(finding) for finding in findings]


@router.get("/{run_id}/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    campaign_id: UUID,
    run_id: UUID,
    finding_id: UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> FindingResponse:
    finding = RunService(db).get_finding(
        tenant_id=tenant.id,
        campaign_id=campaign_id,
        run_id=run_id,
        finding_id=finding_id,
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding_to_response(finding)
