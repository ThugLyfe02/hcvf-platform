"""Autonomous controller loop.

Runs as its own process (``python -m worker.autonomy``) and is also called from
the scheduler loop, so a deployment only needs the scheduler to get autonomy.
The loop itself is deliberately thin: all policy lives in
``app.services.autonomy_service`` so it can be tested without a worker.
"""

from __future__ import annotations

import logging
import time

from app.core.config import settings
from app.core.logging import setup_logging
from app.db.session import SessionLocal
from app.services.autonomy_service import AutonomyService

logger = logging.getLogger(__name__)

_last_tick: float = 0.0


def tick(*, force: bool = False, now=None) -> list[dict[str, object]]:
    with SessionLocal() as db:
        reports = AutonomyService(db).tick_all(now=now, force=force)
    results = [report.to_dict() for report in reports]
    launched = [item for item in results if item["action"] == "hunt"]
    if launched:
        logger.info("autonomy launched %d hunt(s)", len(launched), extra={"launches": launched})
    return results


def maybe_tick(*, force: bool = False) -> list[dict[str, object]]:
    """Tick at most once per ``AUTONOMY_INTERVAL_SECONDS``."""

    global _last_tick
    now = time.monotonic()
    if not force and (now - _last_tick) < settings.autonomy_interval_seconds:
        return []
    _last_tick = now
    return tick(force=force)


def main() -> None:
    setup_logging()
    logger.info("autonomy controller started", extra={"interval": settings.autonomy_interval_seconds})
    while True:
        try:
            maybe_tick(force=True)
        except Exception:
            logger.exception("autonomy tick failed")
        time.sleep(max(5, settings.autonomy_interval_seconds))


if __name__ == "__main__":
    main()
