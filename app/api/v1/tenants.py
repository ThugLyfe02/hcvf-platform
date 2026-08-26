from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import get_current_tenant
from app.db.session import get_db
from app.models import Tenant
from app.services.tenant_service import TenantService

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    authorized_targets: list[str] = Field(default_factory=list)


class TenantUpdate(BaseModel):
    authorized_targets: list[str]


class TenantResponse(BaseModel):
    id: UUID
    name: str
    authorized_targets: list[str]
    created_at: datetime
    updated_at: datetime


class TenantCreateResponse(TenantResponse):
    api_key: str


def tenant_to_response(tenant: Tenant) -> TenantResponse:
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        authorized_targets=tenant.authorized_targets,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.post("", response_model=TenantCreateResponse, status_code=status.HTTP_201_CREATED)
def create_tenant(
    payload: TenantCreate,
    request: Request,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> TenantCreateResponse:
    try:
        tenant, api_key = TenantService(db).create_tenant(
            name=payload.name,
            authorized_targets=payload.authorized_targets,
            actor_tenant_id=current_tenant.id,
            actor=request.state.actor,
            request_id=request.state.request_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return TenantCreateResponse(
        **tenant_to_response(tenant).model_dump(),
        api_key=api_key,
    )


@router.get("", response_model=list[TenantResponse])
def list_tenants(
    _: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> list[TenantResponse]:
    return [tenant_to_response(tenant) for tenant in TenantService(db).list_tenants()]


@router.get("/{tenant_id}", response_model=TenantResponse)
def get_tenant(
    tenant_id: UUID,
    _: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> TenantResponse:
    tenant = TenantService(db).get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return tenant_to_response(tenant)


@router.patch("/{tenant_id}", response_model=TenantResponse)
def update_tenant(
    tenant_id: UUID,
    payload: TenantUpdate,
    request: Request,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
) -> TenantResponse:
    service = TenantService(db)
    tenant = service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    tenant = service.update_authorized_targets(
        tenant=tenant,
        authorized_targets=payload.authorized_targets,
        actor_tenant_id=current_tenant.id,
        actor=request.state.actor,
        request_id=request.state.request_id,
    )
    return tenant_to_response(tenant)
