from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def record_audit_log(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str,
    request_id: str | None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append an audit event to the caller's current database transaction."""

    event = AuditLog(
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=request_id,
        details=details or {},
    )
    db.add(event)
    return event
