from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import get_current_tenant, require_admin
from app.db.session import get_db
from app.models import Tenant
from app.services.tenant_service import TenantService

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    authorized_targets: list[str] = Field(default_factory=list)
    role: str = Field(default="member", pattern="^(admin|member|auditor)$")


class TenantUpdate(BaseModel):
    authorized_targets: list[str] | None = None
    scopes: list[str] | None = None


class TenantResponse(BaseModel):
    id: UUID
    name: str
    role: str
    is_active: bool
    authorized_targets: list[str]
    created_at: datetime
    updated_at: datetime


class TenantCreateResponse(TenantResponse):
    api_key: str


def tenant_to_response(tenant: Tenant) -> TenantResponse:
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        role=tenant.role,
        is_active=tenant.is_active,
        authorized_targets=tenant.authorized_targets,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.post("", response_model=TenantCreateResponse, status_code=status.HTTP_201_CREATED)
def create_tenant(
    payload: TenantCreate,
    request: Request,
    admin: Tenant = Depends(require_admin),
    db: Session = Depends(get_db),
) -> TenantCreateResponse:
    try:
        tenant, api_key = TenantService(db).create_tenant(
            name=payload.name,
            authorized_targets=payload.authorized_targets,
            actor_tenant_id=admin.id,
            actor=request.state.actor,
            request_id=request.state.request_id,
            role=payload.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return TenantCreateResponse(
        **tenant_to_response(tenant).model_dump(),
        api_key=api_key,
    )


@router.get("", response_model=list[TenantResponse])
def list_tenants(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> list[TenantResponse]:
    """Admins see every tenant; everyone else sees only themselves."""

    if tenant.is_admin:
        return [tenant_to_response(item) for item in TenantService(db).list_tenants()]
    return [tenant_to_response(tenant)]


@router.get("/{tenant_id}", response_model=TenantResponse)
def get_tenant(
    tenant_id: UUID,
    current: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> TenantResponse:
    if not current.is_admin and current.id != tenant_id:
        # 404 rather than 403: do not confirm the existence of another tenant.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    tenant = TenantService(db).get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return tenant_to_response(tenant)


@router.patch("/{tenant_id}", response_model=TenantResponse)
def update_tenant(
    tenant_id: UUID,
    payload: TenantUpdate,
    request: Request,
    admin: Tenant = Depends(require_admin),
    db: Session = Depends(get_db),
) -> TenantResponse:
    """Scope changes require an administrator.

    A tenant must not be able to widen its own ``authorized_targets``: that
    would turn the allowlist into a self-signed permission slip.
    """

    service = TenantService(db)
    tenant = service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    try:
        if payload.authorized_targets is not None:
            tenant = service.update_authorized_targets(
                tenant=tenant,
                authorized_targets=payload.authorized_targets,
                actor_tenant_id=admin.id,
                actor=request.state.actor,
                request_id=request.state.request_id,
            )
        if payload.scopes is not None:
            tenant.scopes = sorted({scope.strip() for scope in payload.scopes if scope.strip()})
            service.audit.record(
                tenant_id=admin.id,
                action="tenant.update_scopes",
                details={"updated_tenant_id": str(tenant.id), "scopes": tenant.scopes},
                user_id=request.state.actor,
                resource_type="tenant",
                resource_id=str(tenant.id),
                request_id=request.state.request_id,
            )
            db.commit()
            db.refresh(tenant)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return tenant_to_response(tenant)


@router.post("/{tenant_id}/rotate-key")
def rotate_tenant_key(
    tenant_id: UUID,
    request: Request,
    current: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Issue a new API key and invalidate the previous one.

    Self-rotation is allowed; rotating another tenant requires admin.
    """

    if not current.is_admin and current.id != tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    service = TenantService(db)
    tenant = service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    api_key = service.rotate_api_key(tenant=tenant)
    service.audit.record(
        tenant_id=current.id,
        action="tenant.rotate_key",
        details={"rotated_tenant_id": str(tenant.id)},
        user_id=request.state.actor,
        resource_type="tenant",
        resource_id=str(tenant.id),
        request_id=request.state.request_id,
    )
    db.commit()
    return {"tenant_id": str(tenant.id), "api_key": api_key, "rotated_at": tenant.key_rotated_at}
