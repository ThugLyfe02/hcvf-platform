from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Outbox

logger = logging.getLogger(__name__)

Publisher = Callable[[str, dict], None]


def enqueue(db: Session, *, topic: str, payload: dict, available_at: datetime | None = None) -> Outbox:
    """Add a dispatch intent inside the caller's transaction."""

    entry = Outbox(
        topic=topic,
        payload=payload,
        available_at=available_at or datetime.now(UTC),
    )
    db.add(entry)
    return entry


def dispatch_pending(
    db: Session,
    publish: Publisher | None = None,
    *,
    limit: int = 20,
    max_attempts: int = 5,
) -> int:
    """Publish due outbox entries. Returns the number successfully delivered.

    Claiming uses ``FOR UPDATE SKIP LOCKED`` so multiple relay instances (API
    fast path, scheduler loop, worker) never publish the same intent twice.
    """

    if publish is None:
        from worker.tasks import publish_outbox_message

        publish = publish_outbox_message

    now = datetime.now(UTC)
    entries = list(
        db.scalars(
            select(Outbox)
            .where(
                Outbox.published_at.is_(None),
                Outbox.available_at <= now,
                Outbox.attempts < max_attempts,
            )
            .order_by(Outbox.available_at.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    delivered = 0
    for entry in entries:
        try:
            publish(entry.topic, dict(entry.payload))
        except Exception as exc:
            entry.attempts += 1
            entry.last_error = f"{exc.__class__.__name__}: {exc}"[:512]
            entry.available_at = now + timedelta(seconds=min(300, 2**entry.attempts))
            logger.warning("outbox delivery failed for %s: %s", entry.topic, exc)
        else:
            entry.published_at = datetime.now(UTC)
            entry.last_error = ""
            delivered += 1
    db.commit()
    return delivered
