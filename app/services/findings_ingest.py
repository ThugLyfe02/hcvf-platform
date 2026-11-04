"""Ingest objective evidence into the findings ledger.

Objectives produced evidence and reports but never rows in the findings table, so
their findings could not be triaged, filtered, or counted with everything else.
This is the missing join between the two records of truth.

Aggregation mirrors the campaign path: identity is ``(tenant, fingerprint)``.
Seeing the same issue again increments occurrences and reopens a fixed finding
rather than creating a duplicate. The full response stays sealed in the
objective's Merkle evidence; the row carries the identity and the pointer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.metrics import FINDINGS_DETECTED
from app.models import Finding, FindingStatus, Objective
from app.services.findings_service import SLA_HOURS


@dataclass(frozen=True)
class IngestResult:
    created: int = 0
    updated: int = 0
    reopened: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"created": self.created, "updated": self.updated, "reopened": self.reopened}


def record_objective(db: Session, objective: Objective, supervisor) -> IngestResult:
    """Upsert every finding an objective observed into the findings ledger."""

    now = datetime.now(UTC)
    created = updated = reopened = 0
    seen: set[tuple[str, str]] = set()

    for state in supervisor.ordered():
        outcome = state.outcome
        if outcome is None or not outcome.findings:
            continue
        for finding in outcome.findings:
            key = (finding.fingerprint, finding.kind)
            if key in seen:
                continue
            seen.add(key)
            existing = db.scalar(
                select(Finding).where(
                    Finding.tenant_id == objective.tenant_id,
                    Finding.fingerprint == finding.fingerprint,
                )
            )
            if existing is not None:
                existing.occurrences += 1
                existing.last_seen_at = now
                existing.confidence = finding.confidence
                existing.objective_id = objective.id
                if existing.status in {FindingStatus.fixed, FindingStatus.verified}:
                    existing.status = FindingStatus.open
                    existing.detail = _detail(finding, objective)
                    reopened += 1
                elif not existing.title and finding.title:
                    existing.title = finding.title
                updated += 1
                continue

            db.add(
                Finding(
                    run_id=None,
                    objective_id=objective.id,
                    tenant_id=objective.tenant_id,
                    fingerprint=finding.fingerprint,
                    probe_id=finding.probe_id,
                    kind=finding.kind,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    status=FindingStatus.open,
                    cwe=finding.cwe,
                    title=finding.title or finding.kind.replace("-", " ").title(),
                    detail=_detail(finding, objective),
                    remediation=finding.remediation,
                    evidence_refs={
                        "objective_id": str(objective.id),
                        "task": state.spec.key,
                        "route": finding.route,
                        "manifest": f"objectives/{objective.id}/{state.spec.key}/manifest.json",
                    },
                    occurrences=1,
                    last_seen_at=now,
                    last_run_id=None,
                    sla_due_at=now + _sla_delta(finding.severity),
                )
            )
            created += 1

    if created:
        FINDINGS_DETECTED.inc(created)
    if created or updated:
        db.flush()
    return IngestResult(created=created, updated=updated, reopened=reopened)


def _detail(finding, objective: Objective) -> str:
    route = finding.route or objective.target_url
    return (
        f"{finding.title or finding.kind} observed at {route} during objective "
        f"{objective.key}. The response and derivation are sealed in the objective "
        "evidence manifest; this row is the triage identity."
    )


def _sla_delta(severity: str):
    from datetime import timedelta

    return timedelta(hours=SLA_HOURS.get(severity, SLA_HOURS["info"]))
