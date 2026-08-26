from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from app.models import AuditLog


class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def record(
        self,
        *,
        tenant_id: UUID,
        action: str,
        details: dict,
        user_id: str,
        resource_type: str,
        resource_id: str,
        request_id: str | None = None,
    ) -> AuditLog:
        timestamp = datetime.now(timezone.utc)
        audit_log = AuditLog(
            tenant_id=tenant_id,
            actor=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            detail={**details, "timestamp": timestamp.isoformat()},
        )
        self.db.add(audit_log)
        return audit_log
