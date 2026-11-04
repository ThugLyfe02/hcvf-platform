"""Background agent runtime: durable task queue, leases, heartbeats.

The workforce previously advanced objectives synchronously from a single tick.
Production needs specialised agents running continuously, each claiming the work
it is qualified for, renewing its lease while it works, and letting a supervisor
reclaim work from a crashed process.

This module is the queue. It is deliberately a thin, atomic layer over the
objective task table:

* a claim is one conditional UPDATE, so two agents cannot win the same task;
* readiness is evaluated from the persisted dependency list, not from memory;
* leases expire, and an expired lease is reclaimed by a reaper, not by hand;
* heartbeats are rows, so the runtime can be observed from another process.

Nothing here imports the executor or the engine; it only moves tasks between
states and reports what it sees.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models import AgentHeartbeat, Objective, ObjectiveTask

LEASE_SECONDS = 300
HEARTBEAT_STALE_SECONDS = 90
TERMINAL_OBJECTIVE = ("completed", "blocked", "failed", "cancelled")
TERMINAL_TASK = ("done", "failed", "skipped", "blocked")


@dataclass(frozen=True)
class ClaimedTask:
    objective_id: UUID
    task_id: UUID
    task_key: str
    worker: str
    kind: str
    seq: int
    route: str
    probe_id: str
    attempts: int


@dataclass(frozen=True)
class QueueDepth:
    pending: int
    running: int
    leased_expired: int
    blocked: int

    def to_dict(self) -> dict[str, int]:
        return {
            "pending": self.pending,
            "running": self.running,
            "expired_leases": self.leased_expired,
            "blocked": self.blocked,
        }


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def ready_tasks(db: Session, *, worker: str | None = None, limit: int = 50) -> list[ObjectiveTask]:
    """Tasks whose dependencies are satisfied, across every active objective."""

    stmt = (
        select(ObjectiveTask, Objective)
        .join(Objective, ObjectiveTask.objective_id == Objective.id)
        .where(
            ObjectiveTask.status.in_(["pending", "ready"]),
            Objective.status.in_(["queued", "running"]),
        )
        .order_by(Objective.priority.desc(), Objective.created_at.asc(), ObjectiveTask.seq.asc())
        .limit(limit)
    )
    if worker:
        stmt = stmt.where(ObjectiveTask.worker == worker)
    rows = list(db.execute(stmt).all())
    if not rows:
        return []

    # Dependency satisfaction in one pass: load the status of every key that any
    # candidate depends on, then filter candidates whose deps are not terminal-ok.
    wanted: dict[UUID, set[str]] = {}
    for task, _objective in rows:
        for key in task.depends_on or []:
            wanted.setdefault(task.objective_id, set()).add(str(key))
    statuses: dict[tuple[UUID, str], str] = {}
    if wanted:
        for objective_id, keys in wanted.items():
            for key, status in db.execute(
                select(ObjectiveTask.key, ObjectiveTask.status).where(
                    ObjectiveTask.objective_id == objective_id, ObjectiveTask.key.in_(sorted(keys))
                )
            ).all():
                statuses[(objective_id, key)] = status

    ready: list[ObjectiveTask] = []
    for task, _objective in rows:
        deps = [str(key) for key in (task.depends_on or [])]
        if all(statuses.get((task.objective_id, key)) in ("done", "skipped") for key in deps):
            ready.append(task)
    return ready


def claim(
    db: Session,
    *,
    worker: str,
    agent_id: str,
    lease_seconds: int = LEASE_SECONDS,
) -> ClaimedTask | None:
    """Atomically claim the next task for a specialised agent."""

    for _ in range(6):
        candidates = ready_tasks(db, worker=worker, limit=12)
        if not candidates:
            return None
        task = candidates[0]
        objective = db.get(Objective, task.objective_id)
        if objective is None or objective.status in TERMINAL_OBJECTIVE:
            continue
        now = datetime.now(UTC)
        result = db.execute(
            update(ObjectiveTask)
            .where(
                ObjectiveTask.id == task.id,
                ObjectiveTask.status.in_(["pending", "ready"]),
            )
            .values(
                status="running",
                attempts=ObjectiveTask.attempts + 1,
                started_at=func.coalesce(ObjectiveTask.started_at, now),
                lease_expires_at=now + timedelta(seconds=lease_seconds),
            )
        )
        db.commit()
        if result.rowcount != 1:
            continue
        db.refresh(task)
        if objective.status == "queued":
            objective.status = "running"
            objective.started_at = objective.started_at or now
            db.commit()
        return ClaimedTask(
            objective_id=task.objective_id,
            task_id=task.id,
            task_key=task.key,
            worker=worker,
            kind=task.kind,
            seq=task.seq,
            route=task.route,
            probe_id=task.probe_id,
            attempts=task.attempts,
        )
    return None


def renew(db: Session, task_id: UUID, *, lease_seconds: int = LEASE_SECONDS) -> bool:
    result = db.execute(
        update(ObjectiveTask)
        .where(ObjectiveTask.id == task_id, ObjectiveTask.status == "running")
        .values(lease_expires_at=datetime.now(UTC) + timedelta(seconds=lease_seconds))
    )
    db.commit()
    return result.rowcount == 1


def release(db: Session, task_id: UUID) -> bool:
    """Drop a lease without executing (used when execution cannot start)."""

    result = db.execute(
        update(ObjectiveTask)
        .where(ObjectiveTask.id == task_id, ObjectiveTask.status == "running")
        .values(status="pending", lease_expires_at=None)
    )
    db.commit()
    return result.rowcount == 1


def reclaim_expired(db: Session, *, limit: int = 20) -> list[str]:
    """Return stale leases to the queue; report the keys recovered."""

    now = datetime.now(UTC)
    rows = list(
        db.scalars(
            select(ObjectiveTask)
            .where(ObjectiveTask.status == "running", ObjectiveTask.lease_expires_at.is_not(None))
            .order_by(ObjectiveTask.lease_expires_at.asc())
            .limit(limit)
        )
    )
    recovered: list[str] = []
    for task in rows:
        expires = _aware(task.lease_expires_at)
        if expires is not None and expires > now:
            continue
        task.status = "pending"
        task.lease_expires_at = None
        task.error = "lease expired; returned to the queue"
        recovered.append(task.key)
    if recovered:
        db.commit()
    return recovered


def depth(db: Session) -> QueueDepth:
    now = datetime.now(UTC)
    pending = int(
        db.scalar(
            select(func.count())
            .select_from(ObjectiveTask)
            .join(Objective, ObjectiveTask.objective_id == Objective.id)
            .where(
                ObjectiveTask.status.in_(["pending", "ready"]),
                Objective.status.in_(["queued", "running"]),
            )
        )
        or 0
    )
    running = int(
        db.scalar(select(func.count()).select_from(ObjectiveTask).where(ObjectiveTask.status == "running")) or 0
    )
    expired = int(
        db.scalar(
            select(func.count())
            .select_from(ObjectiveTask)
            .where(ObjectiveTask.status == "running", ObjectiveTask.lease_expires_at.is_not(None))
        )
        or 0
    )
    blocked = int(
        db.scalar(select(func.count()).select_from(ObjectiveTask).where(ObjectiveTask.status == "blocked")) or 0
    )
    if expired:
        expired = int(
            db.scalar(
                select(func.count())
                .select_from(ObjectiveTask)
                .where(ObjectiveTask.status == "running", ObjectiveTask.lease_expires_at < now)
            )
            or 0
        )
    return QueueDepth(pending=pending, running=running, leased_expired=expired, blocked=blocked)


# -- heartbeats --------------------------------------------------------------
def beat(
    db: Session,
    *,
    agent_id: str,
    worker: str,
    state: str,
    objective_id: UUID | None = None,
    task_key: str = "",
    completed_tasks: int | None = None,
    failed_tasks: int | None = None,
) -> AgentHeartbeat:
    now = datetime.now(UTC)
    row = db.scalar(select(AgentHeartbeat).where(AgentHeartbeat.agent_id == agent_id))
    if row is None:
        row = AgentHeartbeat(
            id=uuid4(),
            agent_id=agent_id,
            worker=worker,
            state=state,
            objective_id=objective_id,
            task_key=task_key,
            completed_tasks=completed_tasks or 0,
            failed_tasks=failed_tasks or 0,
            started_at=now,
            last_seen_at=now,
        )
        db.add(row)
    else:
        row.state = state
        row.objective_id = objective_id
        row.task_key = task_key
        row.last_seen_at = now
        if completed_tasks is not None:
            row.completed_tasks = completed_tasks
        if failed_tasks is not None:
            row.failed_tasks = failed_tasks
    db.flush()
    return row


def agents(db: Session, *, worker: str | None = None) -> list[dict[str, object]]:
    now = datetime.now(UTC)
    stmt = select(AgentHeartbeat).order_by(AgentHeartbeat.last_seen_at.desc())
    if worker:
        stmt = stmt.where(AgentHeartbeat.worker == worker)
    result: list[dict[str, object]] = []
    for row in db.scalars(stmt):
        seen = _aware(row.last_seen_at) or now
        result.append(
            {
                "agent_id": row.agent_id,
                "worker": row.worker,
                "state": row.state,
                "objective_id": str(row.objective_id) if row.objective_id else "",
                "task_key": row.task_key,
                "completed_tasks": row.completed_tasks,
                "failed_tasks": row.failed_tasks,
                "last_seen_at": seen.isoformat(),
                "stale": (now - seen).total_seconds() > HEARTBEAT_STALE_SECONDS,
            }
        )
    return result
