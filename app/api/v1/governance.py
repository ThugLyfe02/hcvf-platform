from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_current_tenant, require_admin
from app.db.session import get_db
from app.models import Tenant, Webhook
from app.services import suppressions
from app.services.audit_service import AuditService
from app.services.profiles import ProfileError, get_profile, list_profiles
from app.services.webhooks import SUPPORTED_EVENTS, create_webhook

router = APIRouter(prefix="/api/v1", tags=["governance"])


# -- profiles ---------------------------------------------------------------
@router.get("/profiles")
def get_profiles(_: Tenant = Depends(get_current_tenant)) -> list[dict[str, object]]:
    """Reusable doctrine presets for campaign creation."""

    return list_profiles()


@router.get("/profiles/{name}")
def get_profile_detail(name: str, _: Tenant = Depends(get_current_tenant)) -> dict[str, object]:
    try:
        return {"name": name, **get_profile(name)}
    except ProfileError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# -- webhooks ---------------------------------------------------------------
class WebhookCreate(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    events: list[str] = Field(default_factory=lambda: ["run.completed"])


class WebhookResponse(BaseModel):
    id: UUID
    url: str
    events: list[str]
    active: bool
    failures: int
    last_delivery_at: datetime | None
    last_error: str
    secret_hint: str


def _webhook_response(hook: Webhook) -> WebhookResponse:
    return WebhookResponse(
        id=hook.id,
        url=hook.url,
        events=list(hook.events or []),
        active=hook.active,
        failures=hook.failures,
        last_delivery_at=hook.last_delivery_at,
        last_error=hook.last_error,
        secret_hint=f"…{hook.secret[-4:]}",
    )


@router.get("/webhooks", response_model=list[WebhookResponse])
def list_webhooks(admin: Tenant = Depends(require_admin), db: Session = Depends(get_db)) -> list[WebhookResponse]:
    rows = db.scalars(select(Webhook).where(Webhook.tenant_id == admin.id).order_by(Webhook.created_at.desc()))
    return [_webhook_response(row) for row in rows]


@router.post("/webhooks", status_code=status.HTTP_201_CREATED)
def add_webhook(
    payload: WebhookCreate,
    request: Request,
    admin: Tenant = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        hook, secret = create_webhook(db, tenant=admin, url=payload.url, events=payload.events)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    AuditService(db).record(
        tenant_id=admin.id,
        action="webhook.create",
        details={"url": hook.url, "events": list(hook.events)},
        user_id=request.state.actor,
        resource_type="webhook",
        resource_id=str(hook.id),
        request_id=request.state.request_id,
    )
    db.commit()
    return {
        **_webhook_response(hook).model_dump(),
        "secret": secret,
        "supported_events": list(SUPPORTED_EVENTS),
    }


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(webhook_id: UUID, admin: Tenant = Depends(require_admin), db: Session = Depends(get_db)) -> None:
    hook = db.scalar(select(Webhook).where(Webhook.id == webhook_id, Webhook.tenant_id == admin.id))
    if hook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    db.delete(hook)
    db.commit()


# -- finding suppressions ---------------------------------------------------
class SuppressionCreate(BaseModel):
    kind: str = Field(min_length=1, max_length=128)
    fingerprint: str = Field(default="", max_length=64)
    reason: str = Field(default="", max_length=512)
    expires_at: datetime | None = None


class SuppressionResponse(BaseModel):
    id: UUID
    kind: str
    fingerprint: str
    reason: str
    created_by: str
    expires_at: datetime | None
    created_at: datetime


def _suppression_response(rule) -> SuppressionResponse:
    return SuppressionResponse(
        id=rule.id,
        kind=rule.kind,
        fingerprint=rule.fingerprint,
        reason=rule.reason,
        created_by=rule.created_by,
        expires_at=rule.expires_at,
        created_at=rule.created_at,
    )


@router.get("/suppressions", response_model=list[SuppressionResponse])
def list_suppressions(
    tenant: Tenant = Depends(get_current_tenant), db: Session = Depends(get_db)
) -> list[SuppressionResponse]:
    return [_suppression_response(rule) for rule in suppressions.list_all(db, tenant_id=tenant.id)]


@router.post("/suppressions", response_model=SuppressionResponse, status_code=202)
def add_suppression(
    payload: SuppressionCreate,
    request: Request,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> SuppressionResponse:
    rule = suppressions.create(
        db,
        tenant_id=tenant.id,
        kind=payload.kind,
        fingerprint=payload.fingerprint,
        reason=payload.reason,
        created_by=request.state.actor,
        expires_at=payload.expires_at,
    )
    AuditService(db).record(
        tenant_id=tenant.id,
        action="finding.suppress",
        details={"kind": rule.kind, "fingerprint": rule.fingerprint, "reason": rule.reason},
        user_id=request.state.actor,
        resource_type="suppression",
        resource_id=str(rule.id),
        request_id=request.state.request_id,
    )
    db.commit()
    return _suppression_response(rule)


@router.delete("/suppressions/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_suppression(
    suppression_id: UUID, tenant: Tenant = Depends(get_current_tenant), db: Session = Depends(get_db)
) -> None:
    if not suppressions.delete(db, tenant_id=tenant.id, suppression_id=suppression_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression not found")


# -- audit chain ------------------------------------------------------------
@router.get("/audit/verify")
def verify_audit_chain(admin: Tenant = Depends(require_admin), db: Session = Depends(get_db)) -> dict[str, object]:
    ok, checked, first_bad = AuditService(db).verify_chain(tenant_id=admin.id)
    return {"ok": ok, "records": checked, "first_invalid_id": first_bad or None}
