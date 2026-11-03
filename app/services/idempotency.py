from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import IdempotencyKey

CLAIMED = "claimed"
REPLAY = "replay"
CONFLICT = "conflict"
IN_PROGRESS = "in_progress"
NONE = "none"


def request_hash(payload: object) -> str:
    import json

    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def claim(
    db: Session,
    *,
    tenant_id: UUID,
    key: str | None,
    payload: object,
    ttl_hours: int = 24,
) -> tuple[IdempotencyKey | None, str]:
    """Claim an idempotency key before the handler runs.

    Returns the record and one of: ``none`` (no header supplied), ``claimed``
    (first use), ``replay`` (return the stored response), ``in_progress`` (a
    concurrent duplicate), ``conflict`` (same key, different body).
    """

    if not key:
        return None, NONE

    digest = request_hash(payload)
    existing = db.scalar(select(IdempotencyKey).where(IdempotencyKey.tenant_id == tenant_id, IdempotencyKey.key == key))
    if existing is not None:
        if existing.request_hash != digest:
            return existing, CONFLICT
        if existing.status_code == 0:
            return existing, IN_PROGRESS
        return existing, REPLAY

    record = IdempotencyKey(
        tenant_id=tenant_id,
        key=key[:128],
        request_hash=digest,
        status_code=0,
        response={},
        expires_at=datetime.now(UTC) + timedelta(hours=ttl_hours),
    )
    db.add(record)
    try:
        db.commit()
    except Exception:
        db.rollback()
        winner = db.scalar(
            select(IdempotencyKey).where(IdempotencyKey.tenant_id == tenant_id, IdempotencyKey.key == key)
        )
        return winner, IN_PROGRESS if winner else CONFLICT
    db.refresh(record)
    return record, CLAIMED


def complete(db: Session, record: IdempotencyKey | None, *, status_code: int, body: dict) -> None:
    if record is None:
        return
    record.status_code = status_code
    record.response = body
    db.commit()


def purge_expired(db: Session, *, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    rows = list(db.scalars(select(IdempotencyKey).where(IdempotencyKey.expires_at < now)))
    for row in rows:
        db.delete(row)
    if rows:
        db.commit()
    return len(rows)
