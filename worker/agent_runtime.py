"""Background agent runtime.

Specialised agents run in this process as independent threads, each claiming only
the work it is qualified for. The queue (``app.services.task_queue``) provides
the atomic claim and the lease; this module provides the long-lived loop,
heartbeats, lease renewal, crash recovery and graceful shutdown.

Production properties:

* every agent has a stable id (host + pid + worker + index) and a heartbeat row;
* a lease is renewed while a task executes, so a slow probe is not mistaken for a
  crashed agent;
* an expired lease is reclaimed by a reaper thread and the task returns to the
  queue (bounded by ``max_attempts`` when it next fails);
* SIGTERM/SIGINT set a stop event; loops finish their current task and exit;
* a failing task is reported on the heartbeat and never kills the pool.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import threading
import time
from dataclasses import dataclass, field
from uuid import UUID

from app.core.logging import setup_logging
from app.db.session import SessionLocal
from app.models import Objective
from app.services import agent_pools, task_queue
from app.services.objective_service import ObjectiveService

logger = logging.getLogger(__name__)

#: Default fleet. Counts are deliberately small and explicit; scale by env.
DEFAULT_POOLS: dict[str, int] = {
    "recon-worker": 1,
    "config-worker": 2,
    "auth-worker": 2,
    "exposure-worker": 1,
    "surface-worker": 1,
    "verifier-worker": 2,
    "auditor-worker": 1,
    "diagnose-worker": 1,
    "report-worker": 1,
}

RENEW_SECONDS = 30.0
REAP_SECONDS = 15.0
IDLE_SECONDS = 1.5


def pools_from_env() -> dict[str, int]:
    raw = os.environ.get("HCVF_AGENT_POOL", "").strip()
    if not raw:
        return dict(DEFAULT_POOLS)
    pools: dict[str, int] = {}
    for item in raw.split(","):
        if "=" not in item:
            continue
        worker, count = item.split("=", 1)
        try:
            pools[worker.strip()] = max(0, int(count))
        except ValueError:
            continue
    return pools or dict(DEFAULT_POOLS)


@dataclass
class AgentStats:
    completed: int = 0
    failed: int = 0
    idle: int = 0


class Renewer:
    """Renew one task lease while the agent executes it."""

    def __init__(self, task_id: UUID, *, interval: float = RENEW_SECONDS) -> None:
        self.task_id = task_id
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"renew-{task_id}", daemon=True)

    def __enter__(self) -> Renewer:
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                with SessionLocal() as db:
                    task_queue.renew(db, self.task_id)
            except Exception:
                logger.debug("lease renewal failed for %s", self.task_id, exc_info=True)


@dataclass
class AgentShot:
    agent_id: str
    worker: str
    task_key: str
    objective_id: UUID | None
    executed: bool
    error: str = ""


def run_once(worker: str, *, agent_id: str | None = None, lease_seconds: int = task_queue.LEASE_SECONDS) -> AgentShot:
    """Claim and execute exactly one task. Used by tests and by ``--once``."""

    agent_id = agent_id or f"{worker}:once:{os.getpid()}"
    with SessionLocal() as db:
        claimed = task_queue.claim(db, worker=worker, agent_id=agent_id, lease_seconds=lease_seconds)
        task_queue.beat(db, agent_id=agent_id, worker=worker, state="idle")
        db.commit()
    if claimed is None:
        return AgentShot(agent_id=agent_id, worker=worker, task_key="", objective_id=None, executed=False)

    with SessionLocal() as db:
        objective = db.get(Objective, claimed.objective_id)
        if objective is None:
            task_queue.release(db, claimed.task_id)
            return AgentShot(
                agent_id=agent_id,
                worker=worker,
                task_key=claimed.task_key,
                objective_id=claimed.objective_id,
                executed=False,
                error="objective disappeared",
            )
        task_queue.beat(
            db,
            agent_id=agent_id,
            worker=worker,
            state="running",
            objective_id=claimed.objective_id,
            task_key=claimed.task_key,
        )
        db.commit()
        try:
            with Renewer(claimed.task_id):
                result = ObjectiveService(db).execute_claimed(objective, claimed.task_key)
            executed = result is not None
            error = ""
        except Exception as exc:
            db.rollback()
            executed = False
            error = f"{exc.__class__.__name__}: {exc}"[:400]
            try:
                task_queue.release(db, claimed.task_id)
            except Exception:
                logger.exception("could not release task %s", claimed.task_key)
            logger.exception("agent %s failed task %s", agent_id, claimed.task_key)
        task_queue.beat(
            db,
            agent_id=agent_id,
            worker=worker,
            state="idle",
            task_key="",
            completed_tasks=None,
            failed_tasks=None,
        )
        db.commit()
    return AgentShot(
        agent_id=agent_id,
        worker=worker,
        task_key=claimed.task_key,
        objective_id=claimed.objective_id,
        executed=executed,
        error=error,
    )


@dataclass
class AgentRuntime:
    pools: dict[str, int] = field(default_factory=pools_from_env)
    stop_event: threading.Event = field(default_factory=threading.Event)
    stats: dict[str, AgentStats] = field(default_factory=dict)
    threads: list[threading.Thread] = field(default_factory=list)

    def start(self) -> None:
        if self.threads:
            return
        reaper = threading.Thread(target=self._reap_loop, name="lease-reaper", daemon=True)
        reaper.start()
        self.threads.append(reaper)
        for worker, count in self.pools.items():
            for index in range(int(count)):
                name = f"{worker}-{index}"
                thread = threading.Thread(target=self._loop, args=(worker, name), name=f"agent-{name}", daemon=True)
                thread.start()
                self.threads.append(thread)
        agent_pools.register_pools(self.pools)
        logger.info(
            "agent runtime started",
            extra={"pools": self.pools, "threads": len(self.threads)},
        )

    def stop(self, timeout: float = 15.0) -> None:
        self.stop_event.set()
        deadline = time.monotonic() + timeout
        for thread in self.threads:
            remaining = max(0.1, deadline - time.monotonic())
            thread.join(timeout=remaining)
        self.threads.clear()
        agent_pools.clear()
        logger.info("agent runtime stopped", extra={"stats": {k: vars(v) for k, v in self.stats.items()}})

    def wait(self) -> None:
        while not self.stop_event.wait(1.0):
            continue

    # -- internals -------------------------------------------------------
    def _loop(self, worker: str, slot: str) -> None:
        agent_id = f"{worker}:{socket.gethostname()}:{os.getpid()}:{slot}"
        stats = self.stats.setdefault(agent_id, AgentStats())
        while not self.stop_event.is_set():
            try:
                shot = run_once(worker, agent_id=agent_id)
            except Exception:
                logger.exception("agent loop crashed", extra={"agent": agent_id})
                self.stop_event.wait(IDLE_SECONDS)
                continue
            if shot.executed:
                stats.completed += 1
                logger.info("task complete", extra={"agent": agent_id, "task": shot.task_key})
            elif shot.error:
                stats.failed += 1
                logger.warning("task failed", extra={"agent": agent_id, "task": shot.task_key})
            else:
                stats.idle += 1
                self.stop_event.wait(IDLE_SECONDS)

    def _reap_loop(self) -> None:
        while not self.stop_event.wait(REAP_SECONDS):
            try:
                with SessionLocal() as db:
                    recovered = task_queue.reclaim_expired(db)
                if recovered:
                    logger.warning("reclaimed expired leases", extra={"tasks": recovered})
            except Exception:
                logger.exception("lease reaper iteration failed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run specialised validation agents in the background")
    parser.add_argument("--workers", default="", help="override pools, e.g. recon-worker=1,config-worker=2")
    parser.add_argument("--once", action="store_true", help="run one task per configured worker and exit")
    args = parser.parse_args(argv)

    if args.workers:
        os.environ["HCVF_AGENT_POOL"] = args.workers
    setup_logging()
    runtime = AgentRuntime(pools=pools_from_env())

    if args.once:
        for worker in runtime.pools:
            shot = run_once(worker)
            print(f"{worker}: {shot.task_key or '-'} executed={shot.executed} error={shot.error}")
        return 0

    def _stop(_signum, _frame) -> None:
        logger.info("shutdown signal received")
        runtime.stop_event.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    runtime.start()
    runtime.wait()
    runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
