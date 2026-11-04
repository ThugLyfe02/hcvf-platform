from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import require_scope
from app.db.session import get_db
from app.engine.evidence import FileEvidenceStore, MerkleTree, verification_key_from_env, verify_manifest
from app.engine.transcript import render_markdown
from app.models import Finding, Run, Tenant
from app.services import baseline
from app.services.report_service import run_sarif
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
    plan_seed: int | None = None
    evidence_root: str | None = None
    cancel_requested: bool = False


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
    evidence: list
    evidence_refs: dict
    occurrences: int = 1
    last_seen_at: datetime | None = None
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
        plan_seed=run.plan_seed,
        evidence_root=run.evidence_root,
        cancel_requested=run.cancel_requested,
    )


def finding_to_response(finding: Finding) -> FindingResponse:
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
        evidence=list(finding.evidence or []),
        evidence_refs=dict(finding.evidence_refs or {}),
        occurrences=finding.occurrences,
        last_seen_at=finding.last_seen_at,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


@router.get("", response_model=list[RunResponse])
def list_runs(
    campaign_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[RunResponse]:
    runs = RunService(db).list_runs_for_campaign(tenant_id=tenant.id, campaign_id=campaign_id)
    return [run_to_response(run) for run in runs[offset : offset + limit]]


@router.get("/{run_id}", response_model=RunResponse)
def get_run(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> RunResponse:
    run = RunService(db).get_run(tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return run_to_response(run)


@router.get("/{run_id}/plan")
def get_run_plan(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> dict:
    """Return the full agent decision trace for a run.

    This is the audit surface for the agentic layer: every proposal, every
    critique, every selected and rejected probe, and the seed needed to replay
    the decision exactly.
    """

    run = RunService(db).get_run(tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not run.plan:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Run has no recorded plan")
    return {
        "run_id": str(run.id),
        "seed": run.plan_seed,
        "evidence_root": run.evidence_root,
        "plan": run.plan,
    }


@router.get("/{run_id}/transcript")
def get_run_transcript(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    include_votes: bool = Query(default=True),
) -> dict:
    """The agents' conversation: proposals, objections, replies, rulings, consensus."""

    run = RunService(db).get_run(tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not run.plan:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Run has no recorded plan")
    debate = run.plan.get("deliberation") or {}
    return {
        "run_id": str(run.id),
        "format": "markdown",
        "rounds": debate.get("rounds", 0),
        "converged": debate.get("converged", False),
        "agents": debate.get("agents", []),
        "content": render_markdown(run.plan, include_votes=include_votes),
    }


@router.get("/{run_id}/report.sarif")
def get_run_sarif(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> dict:
    run = RunService(db).get_run(tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    findings = RunService(db).list_findings_for_run(tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)
    return run_sarif(run, findings)


@router.get("/{run_id}/findings", response_model=list[FindingResponse])
def list_findings(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    severity: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
) -> list[FindingResponse]:
    findings = RunService(db).list_findings_for_run(
        tenant_id=tenant.id,
        campaign_id=campaign_id,
        run_id=run_id,
        severity=severity,
        status=status_filter,
    )
    return [finding_to_response(finding) for finding in findings]


@router.get("/{run_id}/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    campaign_id: UUID,
    run_id: UUID,
    finding_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
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


@router.get("/{run_id}/diff")
def get_run_diff(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> dict:
    """Compare this run against the previous completed run of the same campaign."""

    run = RunService(db).get_run(tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return baseline.compare(db, tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)


@router.get("/{run_id}/evidence/verify")
def verify_run_evidence(
    campaign_id: UUID,
    run_id: UUID,
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> dict:
    """Recompute the Merkle root, signature and blob hashes for a finished run."""

    run = RunService(db).get_run(tenant_id=tenant.id, campaign_id=campaign_id, run_id=run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")

    manifest_path = Path(settings.evidence_dir) / str(run.id) / "manifest.json"
    if not manifest_path.exists():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No evidence manifest stored for this run")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("entries", [])
    root_ok = False
    if entries:
        tree = MerkleTree([bytes.fromhex(str(entry["digest"])) for entry in entries])
        root_ok = tree.root == manifest.get("root")

    signature = str((manifest.get("signature") or {}).get("value", ""))
    signature_ok = verify_manifest(manifest, signature, verification_key_from_env())

    store = FileEvidenceStore(Path(settings.evidence_dir) / str(run.id))
    blobs_ok = True
    for entry in entries:
        try:
            store.get(str(entry["digest"]))
        except Exception:
            blobs_ok = False
            break

    return {
        "run_id": str(run.id),
        "ok": bool(root_ok and signature_ok and blobs_ok),
        "root": manifest.get("root"),
        "root_recomputed": root_ok,
        "signature": signature_ok,
        "blobs": blobs_ok,
        "leaves": len(entries),
    }
