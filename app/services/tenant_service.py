from __future__ import annotations

import secrets
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_api_key
from app.models import Tenant
from app.services.audit_service import AuditService


class TenantService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)

    def create_tenant(
        self,
        *,
        name: str,
        authorized_targets: list[str],
        actor_tenant_id: UUID,
        actor: str,
        request_id: str | None,
    ) -> tuple[Tenant, str]:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("Tenant name is required")
        existing = self.db.scalar(select(Tenant).where(Tenant.name == normalized_name))
        if existing is not None:
            raise ValueError("Tenant name already exists")

        api_key = secrets.token_urlsafe(32)
        tenant = Tenant(
            name=normalized_name,
            api_key_hash=hash_api_key(api_key),
            authorized_targets=self._normalize_targets(authorized_targets),
        )
        self.db.add(tenant)
        self.db.flush()
        self.audit.record(
            tenant_id=actor_tenant_id,
            action="tenant.create",
            details={"created_tenant_id": str(tenant.id), "name": tenant.name},
            user_id=actor,
            resource_type="tenant",
            resource_id=str(tenant.id),
            request_id=request_id,
        )
        self.db.commit()
        self.db.refresh(tenant)
        return tenant, api_key

    def list_tenants(self) -> list[Tenant]:
        return list(self.db.scalars(select(Tenant).order_by(Tenant.created_at.asc())))

    def get_tenant(self, tenant_id: UUID) -> Tenant | None:
        return self.db.get(Tenant, tenant_id)

    def update_authorized_targets(
        self,
        *,
        tenant: Tenant,
        authorized_targets: list[str],
        actor_tenant_id: UUID,
        actor: str,
        request_id: str | None,
    ) -> Tenant:
        tenant.authorized_targets = self._normalize_targets(authorized_targets)
        self.audit.record(
            tenant_id=actor_tenant_id,
            action="tenant.update_authorized_targets",
            details={
                "updated_tenant_id": str(tenant.id),
                "authorized_targets": tenant.authorized_targets,
            },
            user_id=actor,
            resource_type="tenant",
            resource_id=str(tenant.id),
            request_id=request_id,
        )
        self.db.commit()
        self.db.refresh(tenant)
        return tenant

    @staticmethod
    def _normalize_targets(targets: list[str]) -> list[str]:
        normalized = sorted({target.strip() for target in targets if target.strip()})
        return normalized
