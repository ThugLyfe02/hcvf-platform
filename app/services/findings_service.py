"""Findings triage: status transitions, notes, assignment and SLA.

A finding list without a workflow is a report. This service makes findings
operable: every transition is validated, recorded as an append-only note, written
to the audit chain, and reflected in the SLA summary an operator uses to decide
what to do next.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, FindingNote, FindingStatus, Tenant
from app.services import webhooks
from app.services.audit_service import AuditService

#: Hours from first observation to the target decision, by severity.
SLA_HOURS: dict[str, int] = {
    "critical": 24,
    "high": 72,
    "medium": 24 * 14,
    "low": 24 * 30,
    "info": 24 * 45,
}

#: Allowed transitions. Reopening a fixed finding is allowed because a
#: regression genuinely reopens it; arbitrary jumps are not.
TRANSITIONS: dict[str, set[str]] = {
    FindingStatus.open: {
        FindingStatus.triaged,
        FindingStatus.confirmed,
        FindingStatus.false_positive,
        FindingStatus.risk_accepted,
        FindingStatus.fixed,
        FindingStatus.verified,
    },
    FindingStatus.triaged: {
        FindingStatus.confirmed,
        FindingStatus.false_positive,
        FindingStatus.risk_accepted,
        FindingStatus.fixed,
        FindingStatus.verified,
        FindingStatus.open,
    },
    FindingStatus.confirmed: {
        FindingStatus.fixed,
        FindingStatus.verified,
        FindingStatus.risk_accepted,
        FindingStatus.false_positive,
    },
    FindingStatus.false_positive: {FindingStatus.open, FindingStatus.triaged},
    FindingStatus.risk_accepted: {FindingStatus.open, FindingStatus.triaged, FindingStatus.fixed},
    FindingStatus.fixed: {FindingStatus.verified, FindingStatus.open},
    FindingStatus.verified: {FindingStatus.open},
}


class TriageError(ValueError):
    pass


@dataclass(frozen=True)
class TriageResult:
    finding: Finding
    previous: str
    note: FindingNote


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def sla_due(severity: str, created_at: datetime | None) -> datetime:
    base = _aware(created_at) or datetime.now(UTC)
    return base + timedelta(hours=SLA_HOURS.get(severity, SLA_HOURS["info"]))


def ensure_sla(db: Session, tenant_id: UUID) -> int:
    """Backfill SLA deadlines for findings created before the column existed."""

    rows = list(
        db.scalars(select(Finding).where(Finding.tenant_id == tenant_id, Finding.sla_due_at.is_(None)).limit(500))
    )
    for finding in rows:
        finding.sla_due_at = sla_due(finding.severity, finding.created_at)
    if rows:
        db.flush()
    return len(rows)


def triage(
    db: Session,
    *,
    tenant: Tenant,
    finding: Finding,
    status: str,
    actor: str,
    note: str = "",
    assignee: str | None = None,
    request_id: str | None = None,
) -> TriageResult:
    if status not in FindingStatus.ALL:
        raise TriageError(f"status must be one of {list(FindingStatus.ALL)}")
    previous = finding.status
    if status != previous and status not in TRANSITIONS.get(previous, set()):
        allowed = ", ".join(sorted(TRANSITIONS.get(previous, set()))) or "none"
        raise TriageError(f"cannot move a finding from {previous} to {status}; allowed: {allowed}")

    if assignee is not None:
        finding.assignee = assignee.strip()[:255]

    changed = status != previous or (assignee is not None and assignee.strip() != "")
    if changed:
        finding.status = status
        finding.triaged_at = datetime.now(UTC)
        finding.triaged_by = actor[:255]
        if finding.sla_due_at is None:
            finding.sla_due_at = sla_due(finding.severity, finding.created_at)

    entry = FindingNote(
        tenant_id=tenant.id,
        finding_id=finding.id,
        author=actor[:255],
        note=note.strip()[:4000],
        status_from=previous,
        status_to=status,
        at=datetime.now(UTC),
    )
    db.add(entry)

    AuditService(db).record(
        tenant_id=tenant.id,
        action="finding.triage",
        details={"from": previous, "to": status, "note": note.strip()[:400], "assignee": finding.assignee},
        user_id=actor,
        resource_type="finding",
        resource_id=str(finding.id),
        request_id=request_id,
    )

    if changed:
        webhooks.publish(
            db,
            tenant_id=tenant.id,
            event="finding.triaged",
            payload={
                "finding_id": str(finding.id),
                "fingerprint": finding.fingerprint,
                "kind": finding.kind,
                "severity": finding.severity,
                "from": previous,
                "to": status,
                "assignee": finding.assignee,
                "actor": actor,
            },
        )
    return TriageResult(finding=finding, previous=previous, note=entry)


def notes(db: Session, finding_id: UUID, *, limit: int = 50) -> list[FindingNote]:
    return list(
        db.scalars(
            select(FindingNote).where(FindingNote.finding_id == finding_id).order_by(FindingNote.at.desc()).limit(limit)
        )
    )


def summary(db: Session, tenant: Tenant) -> dict[str, object]:
    ensure_sla(db, tenant.id)
    now = datetime.now(UTC)
    rows = list(db.scalars(select(Finding).where(Finding.tenant_id == tenant.id)))
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    overdue: list[dict[str, object]] = []
    aging = {"under_24h": 0, "1_3d": 0, "3_14d": 0, "over_14d": 0}
    open_states = {
        FindingStatus.open,
        FindingStatus.triaged,
        FindingStatus.confirmed,
        FindingStatus.risk_accepted,
    }
    for finding in rows:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_status[finding.status] = by_status.get(finding.status, 0) + 1
        created = _aware(finding.created_at) or now
        age_hours = (now - created).total_seconds() / 3600.0
        if age_hours < 24:
            aging["under_24h"] += 1
        elif age_hours < 72:
            aging["1_3d"] += 1
        elif age_hours < 336:
            aging["3_14d"] += 1
        else:
            aging["over_14d"] += 1
        due = _aware(finding.sla_due_at)
        if finding.status in open_states and due is not None and due < now:
            overdue.append(
                {
                    "id": str(finding.id),
                    "severity": finding.severity,
                    "title": finding.title,
                    "status": finding.status,
                    "assignee": finding.assignee,
                    "due_at": due.isoformat(),
                    "hours_overdue": round((now - due).total_seconds() / 3600.0, 1),
                }
            )
    overdue.sort(key=lambda item: float(item["hours_overdue"]), reverse=True)
    return {
        "total": len(rows),
        "by_severity": by_severity,
        "by_status": by_status,
        "aging": aging,
        "overdue": overdue[:25],
        "overdue_count": len(overdue),
        "sla_hours": dict(SLA_HOURS),
    }


def assign(db: Session, *, finding: Finding, assignee: str) -> None:
    finding.assignee = assignee.strip()[:255]
    db.flush()
