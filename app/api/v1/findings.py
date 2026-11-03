from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import require_scope
from app.db.session import get_db
from app.models import Finding, FindingStatus, Run, Tenant
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


class FindingResponse(BaseModel):
    id: UUID
    run_id: UUID
    fingerprint: str
    probe_id: str
    kind: str
    severity: str
    confidence: float
    status: str
    cwe: str
    title: str
    detail: str
    remediation: str
    evidence_refs: dict
    occurrences: int = 1
    last_seen_at: datetime | None = None
    created_at: datetime


class FindingPage(BaseModel):
    items: list[FindingResponse]
    total: int
    limit: int
    offset: int


class FindingTriage(BaseModel):
    status: str = Field(description="open|triaged|confirmed|false_positive|risk_accepted|fixed|verified")
    note: str = Field(default="", max_length=2000)


def _to_response(finding: Finding) -> FindingResponse:
    return FindingResponse(
        id=finding.id,
        run_id=finding.run_id,
        fingerprint=finding.fingerprint,
        probe_id=finding.probe_id,
        kind=finding.kind,
        severity=finding.severity,
        confidence=finding.confidence,
        status=finding.status,
        cwe=finding.cwe,
        title=finding.title,
        detail=finding.detail,
        remediation=finding.remediation,
        evidence_refs=dict(finding.evidence_refs or {}),
        occurrences=finding.occurrences,
        last_seen_at=finding.last_seen_at,
        created_at=finding.created_at,
    )


@router.get("", response_model=FindingPage)
def list_findings(
    tenant: Tenant = Depends(require_scope("findings:read")),
    db: Session = Depends(get_db),
    severity: str | None = None,
    finding_status: str | None = Query(default=None, alias="status"),
    kind: str | None = None,
    campaign_id: UUID | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> FindingPage:
    conditions = [Finding.tenant_id == tenant.id]
    if severity:
        conditions.append(Finding.severity == severity)
    if finding_status:
        conditions.append(Finding.status == finding_status)
    if kind:
        conditions.append(Finding.kind == kind)
    if campaign_id is not None:
        conditions.append(Finding.run_id.in_(select(Run.id).where(Run.campaign_id == campaign_id)))

    total = db.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
    rows = list(
        db.scalars(select(Finding).where(*conditions).order_by(Finding.created_at.desc()).limit(limit).offset(offset))
    )
    return FindingPage(items=[_to_response(row) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: UUID,
    tenant: Tenant = Depends(require_scope("findings:read")),
    db: Session = Depends(get_db),
) -> FindingResponse:
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.tenant_id == tenant.id))
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return _to_response(finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
def triage_finding(
    finding_id: UUID,
    payload: FindingTriage,
    request: Request,
    tenant: Tenant = Depends(require_scope("findings:write")),
    db: Session = Depends(get_db),
) -> FindingResponse:
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.tenant_id == tenant.id))
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    if payload.status not in FindingStatus.ALL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"status must be one of {list(FindingStatus.ALL)}",
        )
    previous = finding.status
    finding.status = payload.status
    AuditService(db).record(
        tenant_id=tenant.id,
        action="finding.triage",
        details={"from": previous, "to": payload.status, "note": payload.note},
        user_id=request.state.actor,
        resource_type="finding",
        resource_id=str(finding.id),
        request_id=request.state.request_id,
    )
    db.commit()
    db.refresh(finding)
    return _to_response(finding)
