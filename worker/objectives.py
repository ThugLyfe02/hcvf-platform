"""Objective worker loop.

Objectives progress outside the request path. The loop finds objectives with
work to do and executes a bounded batch in parallel; each thread owns its
session, and the atomic claim in the service prevents double execution. The same
code path is used by the API, so any step is reproducible by an operator.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict

from app.core.config import settings
from app.core.logging import setup_logging
from app.db.session import SessionLocal
from app.services.objective_pool import due_objectives, run_batch

logger = logging.getLogger(__name__)

_last_tick: float = 0.0


def tick(*, limit: int = 8, workers: int | None = None) -> list[dict[str, object]]:
    with SessionLocal() as db:
        objective_ids = due_objectives(db, limit=limit)
    if not objective_ids:
        return []
    outcomes = run_batch(
        objective_ids,
        max_workers=workers or settings.objective_workers,
        max_tasks=settings.objective_tasks_per_batch,
    )
    results = [asdict(outcome) for outcome in outcomes]
    logger.info(
        "objective batch advanced %d objective(s)",
        len(results),
        extra={"objectives": [item["objective_id"] for item in results]},
    )
    return results


def maybe_tick(*, force: bool = False) -> list[dict[str, object]]:
    global _last_tick
    now = time.monotonic()
    if not force and (now - _last_tick) < max(5, settings.scheduler_interval_seconds):
        return []
    _last_tick = now
    return tick()


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
