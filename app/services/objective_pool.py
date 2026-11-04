"""Run independent objectives in parallel.

Each worker thread owns its own Session and calls the same ``run_to_completion``
the API uses; the atomic claim in ``ObjectiveService._claim_next`` is what makes
that safe. A failure in one objective is reported, never propagated to the rest
of the batch.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from uuid import UUID

from app.db.session import SessionLocal
from app.models import Objective
from app.services.objective_service import ObjectiveService

logger = logging.getLogger(__name__)

DEFAULT_WORKERS = 4
DEFAULT_TASKS_PER_OBJECTIVE = 8


@dataclass(frozen=True)
class BatchOutcome:
    objective_id: UUID
    status: str
    verdict: str
    error: str = ""
    tasks: int = 0


def run_objective(objective_id: UUID, *, max_tasks: int = DEFAULT_TASKS_PER_OBJECTIVE) -> BatchOutcome:
    """Execute one objective in its own session; never raises."""

    with SessionLocal() as db:
        objective = db.get(Objective, objective_id)
        if objective is None:
            return BatchOutcome(objective_id=objective_id, status="missing", verdict="")
        try:
            service = ObjectiveService(db)
            before = len(service.tasks(objective.id))
            verdict = service.run_to_completion(objective, max_tasks=max_tasks)
            after = len(service.tasks(objective.id))
            return BatchOutcome(
                objective_id=objective_id,
                status=verdict.status.value,
                verdict=verdict.reason[:400],
                tasks=max(0, after - before),
            )
        except Exception as exc:
            db.rollback()
            logger.exception("objective %s failed in batch", objective_id)
            return BatchOutcome(
                objective_id=objective_id,
                status="error",
                verdict=f"{exc.__class__.__name__}: {exc}"[:400],
                error=str(exc)[:400],
            )


def run_batch(
    objective_ids: list[UUID],
    *,
    max_workers: int = DEFAULT_WORKERS,
    max_tasks: int = DEFAULT_TASKS_PER_OBJECTIVE,
) -> list[BatchOutcome]:
    if not objective_ids:
        return []
    workers = max(1, min(max_workers, len(objective_ids)))
    outcomes: list[BatchOutcome] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="objective") as pool:
        futures = {pool.submit(run_objective, oid, max_tasks=max_tasks): oid for oid in objective_ids}
        for future in as_completed(futures):
            outcomes.append(future.result())
    return outcomes


def due_objectives(db, *, limit: int = 8) -> list[UUID]:
    """Objectives that have work to do, highest priority first."""

    from sqlalchemy import select

    rows = db.scalars(
        select(Objective.id)
        .where(Objective.status.in_(["queued", "running"]))
        .order_by(Objective.priority.desc(), Objective.created_at.asc())
        .limit(limit)
    )
    return list(rows)
