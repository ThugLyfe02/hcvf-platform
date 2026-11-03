from __future__ import annotations

import hashlib

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models import Tenant

api_key_header = APIKeyHeader(name=settings.api_key_header, auto_error=False)


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage.

    SHA-256 is acceptable here because keys are high-entropy random tokens, not
    user-chosen passwords. The hash is compared by the database, never in
    application code, so timing attacks are not viable against it.
    """

    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def get_current_tenant(
    request: Request,
    api_key: str | None = Depends(api_key_header),
    db: Session = Depends(get_db),
) -> Tenant:
    """Resolve the caller from the database — the only source of truth.

    Earlier versions required the key to also appear in an environment
    allowlist, which made every platform-issued key unusable. Bootstrap keys
    are now provisioned as rows and authenticated like any other key.
    """

    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    tenant = db.scalar(select(Tenant).where(Tenant.api_key_hash == hash_api_key(api_key)))
    if tenant is None or not tenant.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    request.state.tenant_id = str(tenant.id)
    request.state.scopes = list(tenant.scopes or [])
    request.state.actor = f"api-key:{tenant.role}:{tenant.name}"[:120]
    return tenant


def has_scope(tenant: Tenant, scope: str) -> bool:
    """Check a capability grant. ``*`` and prefix wildcards are supported."""

    scopes = [str(item) for item in (tenant.scopes or [])]
    if "*" in scopes:
        return True
    if scope in scopes:
        return True
    prefix = scope.split(":", 1)[0]
    return f"{prefix}:*" in scopes


def require_scope(*needed: str):
    """Dependency factory enforcing one or more capability scopes."""

    def dependency(tenant: Tenant = Depends(get_current_tenant)) -> Tenant:
        missing = [scope for scope in needed if not has_scope(tenant, scope)]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope(s): {', '.join(missing)}",
            )
        return tenant

    return dependency


def require_admin(tenant: Tenant = Depends(get_current_tenant)) -> Tenant:
    if not tenant.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required")
    return tenant
