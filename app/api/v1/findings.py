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
from app.services import findings_service

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


class FindingResponse(BaseModel):
    id: UUID
    run_id: UUID | None
    objective_id: UUID | None = None
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
    assignee: str = ""
    triaged_at: datetime | None = None
    triaged_by: str = ""
    sla_due_at: datetime | None = None
    last_seen_at: datetime | None = None
    created_at: datetime


class FindingPage(BaseModel):
    items: list[FindingResponse]
    total: int
    limit: int
    offset: int


class FindingTriage(BaseModel):
    status: str = Field(description="open|triaged|confirmed|false_positive|risk_accepted|fixed|verified")
    note: str = Field(default="", max_length=4000)
    assignee: str | None = Field(default=None, max_length=255)


def _to_response(finding: Finding) -> FindingResponse:
    return FindingResponse(
        id=finding.id,
        run_id=finding.run_id,
        objective_id=finding.objective_id,
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
        assignee=finding.assignee,
        triaged_at=finding.triaged_at,
        triaged_by=finding.triaged_by,
        sla_due_at=finding.sla_due_at,
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
    objective_id: UUID | None = None,
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
    if objective_id is not None:
        conditions.append(Finding.objective_id == objective_id)

    total = db.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
    rows = list(
        db.scalars(select(Finding).where(*conditions).order_by(Finding.created_at.desc()).limit(limit).offset(offset))
    )
    return FindingPage(items=[_to_response(row) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/summary")
def findings_summary(
    tenant: Tenant = Depends(require_scope("findings:read")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """SLA and aging overview for triage: what is overdue and by how much."""

    result = findings_service.summary(db, tenant)
    db.commit()
    return result


@router.get("/{finding_id}/notes")
def list_finding_notes(
    finding_id: UUID,
    tenant: Tenant = Depends(require_scope("findings:read")),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, object]]:
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.tenant_id == tenant.id))
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return [
        {
            "id": str(note.id),
            "author": note.author,
            "note": note.note,
            "status_from": note.status_from,
            "status_to": note.status_to,
            "at": note.at.isoformat(),
        }
        for note in findings_service.notes(db, finding.id, limit=limit)
    ]


@router.post("/{finding_id}/notes", status_code=status.HTTP_201_CREATED)
def add_finding_note(
    finding_id: UUID,
    payload: FindingTriage,
    request: Request,
    tenant: Tenant = Depends(require_scope("findings:write")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.tenant_id == tenant.id))
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    result = findings_service.triage(
        db,
        tenant=tenant,
        finding=finding,
        status=finding.status,
        actor=request.state.actor,
        note=payload.note or "(note)",
        assignee=payload.assignee,
        request_id=request.state.request_id,
    )
    db.commit()
    return {"id": str(result.note.id), "status": finding.status, "at": result.note.at.isoformat()}


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
    try:
        findings_service.triage(
            db,
            tenant=tenant,
            finding=finding,
            status=payload.status,
            actor=request.state.actor,
            note=payload.note,
            assignee=payload.assignee,
            request_id=request.state.request_id,
        )
    except findings_service.TriageError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    db.commit()
    db.refresh(finding)
    return _to_response(finding)
