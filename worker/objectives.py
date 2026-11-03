"""Objective worker loop.

Objectives progress outside the request path: this loop finds objectives with
ready tasks and executes one surgical step at a time. It is deliberately the
same code the API calls, so an operator can reproduce any step manually.
"""

from __future__ import annotations

import logging
import time

from app.core.config import settings
from app.core.logging import setup_logging
from app.db.session import SessionLocal
from app.services.objective_service import ObjectiveService

logger = logging.getLogger(__name__)

_last_tick: float = 0.0


def tick(*, force: bool = False, limit: int = 5) -> list[dict[str, object]]:
    with SessionLocal() as db:
        results = ObjectiveService(db).tick(limit=limit)
    if results:
        logger.info("objective tick advanced %d step(s)", len(results), extra={"steps": results})
    return results


def maybe_tick(*, force: bool = False) -> list[dict[str, object]]:
    global _last_tick
    now = time.monotonic()
    if not force and (now - _last_tick) < max(5, settings.scheduler_interval_seconds):
        return []
    _last_tick = now
    return tick(force=force)


def main() -> None:
    setup_logging()
    logger.info("objective worker started")
    while True:
        try:
            maybe_tick(force=True)
        except Exception:
            logger.exception("objective tick failed")
        time.sleep(max(5, settings.scheduler_interval_seconds))


if __name__ == "__main__":
    main()
