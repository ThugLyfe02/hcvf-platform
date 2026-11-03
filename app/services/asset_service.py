"""Asset inventory: what exists, when we first saw it, and what changed.

Findings describe issues; assets describe the surface those issues live on. The
inventory is fed by every objective (discovered routes and probed routes) and
answers the continuous-validation questions that coverage alone cannot: what is
new, what went stale, and which routes have never been probed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.engine.workforce.coverage import normalize_route
from app.models import Asset, Objective


@dataclass(frozen=True)
class AssetChange:
    new: list[Asset]
    stale: list[Asset]
    vanished: list[Asset]


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()[:255]


def role_of(route: str) -> str:
    from app.engine.workforce.coverage import classify_route

    return classify_route(route)


def record_objective(db: Session, objective: Objective, supervisor) -> int:
    """Upsert assets from an objective's observed routes.

    A route counts once per objective, no matter how many tasks touched it, so
    the objective_count is a truthful measure of how often we have looked.
    """

    now = datetime.now(UTC)
    touched = 0
    seen_routes: set[str] = set()
    findings_by_route: dict[str, int] = {}

    for state in supervisor.ordered():
        outcome = state.outcome
        if outcome is None:
            continue
        candidate_routes: list[str] = []
        if outcome.route:
            candidate_routes.append(outcome.route)
        candidate_routes.extend(outcome.endpoints)
        for candidate in candidate_routes:
            route = normalize_route(candidate)
            if not route or route == normalize_route(objective.target_url):
                continue
            seen_routes.add(route)
            findings_by_route[route] = findings_by_route.get(route, 0) + len(outcome.findings)

    for route in seen_routes:
        asset = db.scalar(select(Asset).where(Asset.tenant_id == objective.tenant_id, Asset.route == route))
        if asset is None:
            asset = Asset(
                tenant_id=objective.tenant_id,
                host=host_of(route),
                route=route,
                role=role_of(route),
                status="active",
                first_seen_at=now,
                last_seen_at=now,
                last_objective_id=objective.id,
                objective_count=1,
                finding_count=findings_by_route.get(route, 0),
            )
            db.add(asset)
        else:
            asset.last_seen_at = now
            asset.status = "active"
            if (asset.last_objective_id or None) != objective.id:
                asset.objective_count += 1
                asset.last_objective_id = objective.id
            asset.finding_count += findings_by_route.get(route, 0)
        touched += 1
    if touched:
        db.flush()
    return touched


def list_assets(
    db: Session,
    tenant_id: UUID,
    *,
    query: str = "",
    role: str = "",
    status_filter: str = "",
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[Asset], int]:
    stmt = select(Asset).where(Asset.tenant_id == tenant_id)
    count_stmt = select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant_id)
    if query:
        like = f"%{query}%"
        stmt = stmt.where(or_(Asset.route.ilike(like), Asset.host.ilike(like)))
        count_stmt = count_stmt.where(or_(Asset.route.ilike(like), Asset.host.ilike(like)))
    if role:
        stmt = stmt.where(Asset.role == role)
        count_stmt = count_stmt.where(Asset.role == role)
    if status_filter:
        stmt = stmt.where(Asset.status == status_filter)
        count_stmt = count_stmt.where(Asset.status == status_filter)
    total = int(db.scalar(count_stmt) or 0)
    items = list(db.scalars(stmt.order_by(Asset.last_seen_at.desc()).offset(offset).limit(limit)))
    return items, total


def changes(db: Session, tenant_id: UUID, *, days: int = 7, stale_days: int = 30) -> AssetChange:
    now = datetime.now(UTC)
    since = now - timedelta(days=days)
    stale_before = now - timedelta(days=stale_days)
    assets = list(db.scalars(select(Asset).where(Asset.tenant_id == tenant_id)))
    fresh = [asset for asset in assets if _aware(asset.first_seen_at) and _aware(asset.first_seen_at) >= since]
    stale = [
        asset for asset in assets if (_aware(asset.last_seen_at) or now) < stale_before and asset.status == "active"
    ]
    return AssetChange(new=fresh, stale=stale, vanished=[])


def mark_stale(db: Session, tenant_id: UUID, *, stale_days: int = 30) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=stale_days)
    assets = list(
        db.scalars(
            select(Asset).where(
                Asset.tenant_id == tenant_id,
                Asset.status == "active",
                Asset.last_seen_at < cutoff,
            )
        )
    )
    for asset in assets:
        asset.status = "stale"
    if assets:
        db.flush()
    return len(assets)


def summary(db: Session, tenant_id: UUID) -> dict[str, object]:
    rows = list(db.scalars(select(Asset).where(Asset.tenant_id == tenant_id)))
    by_role: dict[str, int] = {}
    by_status: dict[str, int] = {}
    never_probed = 0
    for asset in rows:
        by_role[asset.role] = by_role.get(asset.role, 0) + 1
        by_status[asset.status] = by_status.get(asset.status, 0) + 1
        if asset.finding_count == 0 and asset.objective_count <= 1:
            never_probed += 1
    return {
        "total": len(rows),
        "by_role": by_role,
        "by_status": by_status,
        "single_observation": never_probed,
        "oldest_first_seen": min(
            (_aware(asset.first_seen_at) for asset in rows if asset.first_seen_at), default=None
        ).isoformat()
        if rows
        else "",
    }


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value
