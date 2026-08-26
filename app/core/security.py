from __future__ import annotations

import hashlib
import hmac

from fastapi import Depends
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import unauthorized
from app.db.session import get_db
from app.models.tenant import Tenant

settings = get_settings()
api_key_header = APIKeyHeader(name=settings.api_key_header, auto_error=False)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def get_current_tenant(
    api_key: str | None = Depends(api_key_header),
    db: Session = Depends(get_db),
) -> Tenant:
    if not api_key:
        raise unauthorized()

    supplied_hash = hash_api_key(api_key)
    tenant = db.scalar(
        select(Tenant).where(
            Tenant.api_key_hash == supplied_hash,
            Tenant.active.is_(True),
        )
    )
    if tenant is None or not hmac.compare_digest(tenant.api_key_hash, supplied_hash):
        raise unauthorized()
    return tenant


def actor_for_tenant(tenant: Tenant) -> str:
    return f"tenant-api-key:{tenant.id}"
