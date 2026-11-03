"""Cross-objective memory: what yields on a host, learned from outcomes.

The planner reads this as a bias, never as a rule. Safety, authorization and
coverage remain the constraints; memory only decides where to look first.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engine.workforce.coverage import classify_route
from app.models import ObjectiveMemory

#: A recipe can raise a candidate's score by at most this much.
MAX_BOOST = 0.6


def host_of(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return host or url[:255]


def record_objective(db: Session, objective, supervisor) -> int:
    """Fold this objective's task outcomes into per-recipe statistics."""

    host = host_of(objective.target_url)
    template = str(objective.template or "")
    now = datetime.now(UTC)
    rows: dict[tuple[str, str, str], ObjectiveMemory] = {}
    updated = 0

    for state in supervisor.ordered():
        outcome = state.outcome
        if outcome is None or not outcome.probes_run:
            continue
        route = outcome.route or state.spec.route or objective.target_url
        role = classify_route(route)
        probe_id = state.spec.probe_id or outcome.probes_run[0]
        key = (probe_id, role, template)
        row = rows.get(key)
        if row is None:
            row = db.scalar(
                select(ObjectiveMemory).where(
                    ObjectiveMemory.tenant_id == objective.tenant_id,
                    ObjectiveMemory.host == host,
                    ObjectiveMemory.template == template,
                    ObjectiveMemory.probe_id == probe_id,
                    ObjectiveMemory.route_role == role,
                )
            )
        if row is None:
            row = ObjectiveMemory(
                tenant_id=objective.tenant_id,
                host=host,
                template=template,
                probe_id=probe_id,
                route_role=role,
                attempts=0,
                findings=0,
                verified=0,
                refuted=0,
                score=0.0,
                productive=False,
                last_seen_at=now,
            )
            db.add(row)
        row.attempts += 1
        row.findings += len(outcome.findings)
        if outcome.confirmed is True:
            row.verified += 1
        elif outcome.confirmed is False:
            row.refuted += 1
        # Findings are useful; verified findings are worth more; refutations
        # discount a recipe because time spent there is not returning evidence.
        weighted = row.findings + 1.5 * row.verified - 1.2 * row.refuted
        row.score = max(0.0, min(MAX_BOOST, weighted / max(1, row.attempts) / 2.0))
        row.productive = row.verified > 0
        row.last_seen_at = now
        rows[key] = row
        updated += 1

    if updated:
        db.flush()
    return updated


def boosts(db: Session, *, tenant_id: UUID, host: str, template: str) -> dict[tuple[str, str], float]:
    """(probe, role) -> multiplier used by the adaptive planner."""

    rows = db.scalars(
        select(ObjectiveMemory).where(
            ObjectiveMemory.tenant_id == tenant_id,
            ObjectiveMemory.host == host,
            ObjectiveMemory.template == template,
        )
    )
    return {(row.probe_id, row.route_role): float(row.score) for row in rows}


def recipes(db: Session, *, tenant_id: UUID, limit: int = 25) -> list[dict[str, object]]:
    rows = db.scalars(
        select(ObjectiveMemory)
        .where(ObjectiveMemory.tenant_id == tenant_id)
        .order_by(ObjectiveMemory.score.desc(), ObjectiveMemory.last_seen_at.desc())
        .limit(limit)
    )
    return [
        {
            "host": row.host,
            "template": row.template,
            "probe": row.probe_id,
            "role": row.route_role,
            "attempts": row.attempts,
            "findings": row.findings,
            "verified": row.verified,
            "refuted": row.refuted,
            "score": round(row.score, 4),
            "productive": row.productive,
            "last_seen_at": row.last_seen_at.isoformat(),
        }
        for row in rows
    ]
