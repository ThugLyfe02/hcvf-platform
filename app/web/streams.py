"""Server-sent events for objective progress.

Polling the database is deliberate: objective events are already the durable,
ordered source of truth, and a stream that reads them cannot drift from what the
API reports. The stream ends when the objective is terminal and caught up, so a
browser tab does not hold a connection forever.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from uuid import UUID

from sqlalchemy import select

from app.db.session import SessionLocal
from app.models import Objective, ObjectiveEvent

TERMINAL = {"completed", "blocked", "failed", "cancelled"}


def _serialize(event: ObjectiveEvent) -> str:
    payload = {
        "type": event.type,
        "message": event.message,
        "at": event.at.isoformat(),
        "payload": event.payload,
    }
    return f"data: {json.dumps(payload, default=str)}\n\n"


async def event_stream(
    *,
    objective_id: UUID,
    tenant_id: UUID,
    interval: float = 1.5,
    max_seconds: float = 300.0,
    once: bool = False,
) -> AsyncIterator[str]:
    """Yield events as SSE frames, oldest first, then close."""

    seen: set[str] = set()
    deadline = time.monotonic() + max_seconds
    yield "retry: 3000\n\n"

    while time.monotonic() < deadline:
        with SessionLocal() as db:
            query = (
                select(ObjectiveEvent)
                .where(ObjectiveEvent.objective_id == objective_id, ObjectiveEvent.tenant_id == tenant_id)
                .order_by(ObjectiveEvent.at.asc())
                .limit(200)
            )
            events = list(db.scalars(query))
            objective = db.get(Objective, objective_id)
            status = objective.status if objective else "unknown"

        fresh = [event for event in events if str(event.id) not in seen]
        for event in fresh:
            seen.add(str(event.id))
            yield _serialize(event)

        if once:
            yield "event: end\ndata: {}\n\n"
            return

        if status in TERMINAL and not fresh:
            yield f"event: end\ndata: {json.dumps({'status': status})}\n\n"
            return

        yield ": keepalive\n\n"
        await asyncio.sleep(interval)

    yield 'event: end\ndata: {"reason": "timeout"}\n\n'
