from __future__ import annotations

import hashlib
import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models import Tenant

api_key_header = APIKeyHeader(name=settings.api_key_header, auto_error=False)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def validate_configured_api_key(api_key: str) -> bool:
    return any(secrets.compare_digest(api_key, configured) for configured in settings.api_keys)


def get_current_tenant(
    request: Request,
    api_key: str | None = Depends(api_key_header),
    db: Session = Depends(get_db),
) -> Tenant:
    if not api_key or not validate_configured_api_key(api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    api_key_hash = hash_api_key(api_key)
    tenant = db.scalar(select(Tenant).where(Tenant.api_key_hash == api_key_hash))
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key is not provisioned")

    request.state.tenant_id = str(tenant.id)
    request.state.actor = f"api-key:{api_key_hash[:12]}"
    return tenant
