from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Campaign, Finding, Run, RunStatus


def _fingerprints(db: Session, *, tenant_id: UUID, campaign_id: UUID, run_id: UUID) -> dict[str, Finding]:
    rows = db.scalars(
        select(Finding)
        .join(Run, Finding.run_id == Run.id)
        .join(Campaign, Run.campaign_id == Campaign.id)
        .where(
            Finding.tenant_id == tenant_id,
            Campaign.id == campaign_id,
            (Finding.run_id == run_id) | (Finding.last_run_id == run_id),
        )
    )
    return {finding.fingerprint: finding for finding in rows}


def previous_run(db: Session, *, tenant_id: UUID, campaign_id: UUID, run_id: UUID) -> Run | None:
    current = db.get(Run, run_id)
    if current is None or current.started_at is None:
        return None
    return db.scalar(
        select(Run)
        .join(Campaign, Run.campaign_id == Campaign.id)
        .where(
            Campaign.id == campaign_id,
            Campaign.tenant_id == tenant_id,
            Run.id != run_id,
            Run.status == RunStatus.completed,
            Run.started_at < current.started_at,
        )
        .order_by(Run.started_at.desc())
        .limit(1)
    )


def compare(db: Session, *, tenant_id: UUID, campaign_id: UUID, run_id: UUID) -> dict[str, object]:
    """Diff this run against the previous completed run of the same campaign."""

    current = _fingerprints(db, tenant_id=tenant_id, campaign_id=campaign_id, run_id=run_id)
    previous_run_row = previous_run(db, tenant_id=tenant_id, campaign_id=campaign_id, run_id=run_id)
    if previous_run_row is None:
        return {
            "baseline_run_id": None,
            "new": sorted(current),
            "fixed": [],
            "recurring": [],
            "counts": {"new": len(current), "fixed": 0, "recurring": 0, "current": len(current)},
        }

    previous = _fingerprints(db, tenant_id=tenant_id, campaign_id=campaign_id, run_id=previous_run_row.id)
    new = sorted(set(current) - set(previous))
    fixed = sorted(set(previous) - set(current))
    recurring = sorted(set(current) & set(previous))
    return {
        "baseline_run_id": str(previous_run_row.id),
        "new": new,
        "fixed": fixed,
        "recurring": recurring,
        "counts": {
            "new": len(new),
            "fixed": len(fixed),
            "recurring": len(recurring),
            "current": len(current),
        },
    }
