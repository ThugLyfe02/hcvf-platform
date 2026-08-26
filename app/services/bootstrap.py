from __future__ import annotations

from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_api_key
from app.db.session import SessionLocal
from app.models import Tenant


def provision_configured_tenants() -> None:
    with SessionLocal() as db:
        for index, api_key in enumerate(settings.api_keys, start=1):
            api_key_hash = hash_api_key(api_key)
            tenant = db.scalar(select(Tenant).where(Tenant.api_key_hash == api_key_hash))
            if tenant is None:
                db.add(Tenant(name=f"configured-tenant-{index}", api_key_hash=api_key_hash))
        db.commit()
