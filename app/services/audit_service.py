from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engine.types import canonical_json
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
        timestamp = datetime.now(UTC)
        detail = {**details, "timestamp": timestamp.isoformat()}
        last = self.db.scalar(
            select(AuditLog).where(AuditLog.tenant_id == tenant_id).order_by(AuditLog.seq.desc()).limit(1)
        )
        prev_hash = last.hash if last is not None else ""
        next_seq = (last.seq + 1) if last is not None else 1
        payload = {
            "tenant_id": str(tenant_id),
            "actor": user_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "request_id": request_id,
            "detail": detail,
            "prev_hash": prev_hash,
            "seq": next_seq,
        }
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        audit_log = AuditLog(
            tenant_id=tenant_id,
            actor=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            detail=detail,
            seq=next_seq,
            prev_hash=prev_hash,
            hash=digest,
        )
        self.db.add(audit_log)
        return audit_log

    def verify_chain(self, *, tenant_id) -> tuple[bool, int, str]:
        """Recompute the per-tenant chain; return (ok, checked, first_bad_id)."""

        rows = list(
            self.db.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant_id).order_by(AuditLog.seq.asc()))
        )
        previous = ""
        for row in rows:
            payload = {
                "tenant_id": str(row.tenant_id),
                "actor": row.actor,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "request_id": row.request_id,
                "detail": row.detail,
                "prev_hash": previous,
                "seq": row.seq,
            }
            expected = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
            if row.prev_hash != previous or row.hash != expected:
                return False, len(rows), str(row.id)
            previous = row.hash
        return True, len(rows), ""
