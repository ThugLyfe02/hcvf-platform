from __future__ import annotations

from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_api_key
from app.db.session import SessionLocal
from app.models import Tenant, TenantRole

_LOCAL_AUTHORIZED_TARGETS = [
    "http://127.0.0.1:8001",
    "http://localhost:8001",
    "http://127.0.0.1:8099",
]


def provision_configured_tenants() -> None:
    """Ensure every bootstrap key has an admin tenant.

    This is the only place environment keys confer authority. Everywhere else,
    the database row is the source of truth.
    """

    with SessionLocal() as db:
        for index, api_key in enumerate(settings.api_keys, start=1):
            api_key_hash = hash_api_key(api_key)
            tenant = db.scalar(select(Tenant).where(Tenant.api_key_hash == api_key_hash))
            if tenant is None:
                db.add(
                    Tenant(
                        name=f"configured-tenant-{index}",
                        api_key_hash=api_key_hash,
                        role=TenantRole.admin,
                        authorized_targets=list(_LOCAL_AUTHORIZED_TARGETS),
                    )
                )
                continue
            if tenant.role != TenantRole.admin:
                tenant.role = TenantRole.admin
            if settings.environment.lower() == "development" and not tenant.authorized_targets:
                tenant.authorized_targets = list(_LOCAL_AUTHORIZED_TARGETS)
        db.commit()
