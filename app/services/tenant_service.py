from __future__ import annotations

import secrets
from datetime import UTC
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_api_key
from app.models import Tenant, TenantRole
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
        role: str = TenantRole.member,
    ) -> tuple[Tenant, str]:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("Tenant name is required")
        if len(normalized_name) > 255:
            raise ValueError("Tenant name must be at most 255 characters")
        if role not in TenantRole.ALL:
            raise ValueError(f"role must be one of {list(TenantRole.ALL)}")
        existing = self.db.scalar(select(Tenant).where(Tenant.name == normalized_name))
        if existing is not None:
            raise ValueError("Tenant name already exists")

        api_key = secrets.token_urlsafe(32)
        default_scopes = (
            ["*"]
            if role == TenantRole.admin
            else [
                "campaigns:read",
                "campaigns:write",
                "findings:read",
                "findings:write",
                "autonomy:read",
            ]
        )
        tenant = Tenant(
            name=normalized_name,
            api_key_hash=hash_api_key(api_key),
            role=role,
            scopes=default_scopes,
            authorized_targets=self._normalize_targets(authorized_targets),
        )
        self.db.add(tenant)
        self.db.flush()
        self.audit.record(
            tenant_id=actor_tenant_id,
            action="tenant.create",
            details={"created_tenant_id": str(tenant.id), "name": tenant.name, "role": role},
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

    def rotate_api_key(self, *, tenant: Tenant) -> str:
        """Issue a new key and invalidate the old one atomically."""

        from datetime import datetime

        api_key = secrets.token_urlsafe(32)
        tenant.api_key_hash = hash_api_key(api_key)
        tenant.key_rotated_at = datetime.now(UTC)
        self.db.commit()
        self.db.refresh(tenant)
        return api_key

    @staticmethod
    def _normalize_targets(targets: list[str]) -> list[str]:
        """Normalize to origins and reject anything ambiguous."""

        from urllib.parse import urlsplit

        normalized: set[str] = set()
        for target in targets:
            cleaned = target.strip()
            if not cleaned:
                continue
            parts = urlsplit(cleaned)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise ValueError(f"authorized target must be an absolute http(s) URL: {cleaned!r}")
            if parts.username or parts.password:
                raise ValueError(f"credentials are not permitted in authorized targets: {cleaned!r}")
            default_port = 443 if parts.scheme == "https" else 80
            port = parts.port or default_port
            suffix = "" if port == default_port else f":{port}"
            normalized.add(f"{parts.scheme.lower()}://{parts.hostname.lower()}{suffix}")
        return sorted(normalized)
