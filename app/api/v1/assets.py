"""Asset inventory API: observed surface, change feed and summary."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.security import require_scope
from app.db.session import get_db
from app.models import Asset, Tenant
from app.services import asset_service

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


class AssetView(BaseModel):
    id: UUID
    host: str
    route: str
    role: str
    status: str
    first_seen_at: str
    last_seen_at: str
    objective_count: int
    finding_count: int

    @classmethod
    def of(cls, asset: Asset) -> AssetView:
        return cls(
            id=asset.id,
            host=asset.host,
            route=asset.route,
            role=asset.role,
            status=asset.status,
            first_seen_at=asset.first_seen_at.isoformat() if asset.first_seen_at else "",
            last_seen_at=asset.last_seen_at.isoformat() if asset.last_seen_at else "",
            objective_count=asset.objective_count,
            finding_count=asset.finding_count,
        )


@router.get("")
def list_assets(
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    q: str = Query(default=""),
    role: str = Query(default=""),
    status_filter: str = Query(default="", alias="status"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, object]:
    items, total = asset_service.list_assets(
        db,
        tenant.id,
        query=q,
        role=role,
        status_filter=status_filter,
        offset=offset,
        limit=limit,
    )
    return {"items": [AssetView.of(asset) for asset in items], "total": total, "limit": limit, "offset": offset}


@router.get("/summary")
def assets_summary(
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return asset_service.summary(db, tenant.id)


@router.get("/changes")
def assets_changes(
    tenant: Tenant = Depends(require_scope("campaigns:read")),
    db: Session = Depends(get_db),
    days: int = Query(default=7, ge=1, le=365),
    stale_days: int = Query(default=30, ge=1, le=365),
) -> dict[str, object]:
    change = asset_service.changes(db, tenant.id, days=days, stale_days=stale_days)
    return {
        "window_days": days,
        "new": [AssetView.of(asset) for asset in change.new],
        "stale": [AssetView.of(asset) for asset in change.stale],
        "vanished": [AssetView.of(asset) for asset in change.vanished],
    }
