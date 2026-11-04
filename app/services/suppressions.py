from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import FindingSuppression


def active_rules(db: Session, tenant_id: UUID, *, now: datetime | None = None) -> list[FindingSuppression]:
    now = now or datetime.now(UTC)
    rows = db.scalars(
        select(FindingSuppression).where(
            FindingSuppression.tenant_id == tenant_id,
        )
    )
    rules: list[FindingSuppression] = []
    for row in rows:
        expires_at = row.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at is None or expires_at > now:
            rules.append(row)
    return rules


def is_suppressed(rules: list[FindingSuppression], *, kind: str, fingerprint: str) -> bool:
    """A rule matches an exact fingerprint, or its kind when fingerprint is empty."""

    for rule in rules:
        if rule.kind and rule.kind != kind:
            continue
        if rule.fingerprint and rule.fingerprint != fingerprint:
            continue
        return True
    return False


def create(
    db: Session,
    *,
    tenant_id: UUID,
    kind: str,
    fingerprint: str = "",
    reason: str = "",
    created_by: str = "",
    expires_at: datetime | None = None,
) -> FindingSuppression:
    record = FindingSuppression(
        tenant_id=tenant_id,
        kind=kind.strip()[:128],
        fingerprint=fingerprint.strip()[:64],
        reason=reason.strip()[:512],
        created_by=created_by[:255],
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def delete(db: Session, *, tenant_id: UUID, suppression_id: UUID) -> bool:
    record = db.scalar(
        select(FindingSuppression).where(
            FindingSuppression.id == suppression_id, FindingSuppression.tenant_id == tenant_id
        )
    )
    if record is None:
        return False
    db.delete(record)
    db.commit()
    return True


def list_all(db: Session, *, tenant_id: UUID) -> list[FindingSuppression]:
    return list(
        db.scalars(
            select(FindingSuppression)
            .where(FindingSuppression.tenant_id == tenant_id)
            .order_by(FindingSuppression.created_at.desc())
        )
    )
