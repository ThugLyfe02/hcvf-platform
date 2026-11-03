"""Workers: narrow specialists that complete one task and stop.

Each worker knows exactly one discipline. It does not choose its own work, it
does not widen its own scope, and it cannot mark its own output as accepted —
verification is a separate task with a separate worker. That separation is what
makes completion meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.engine.workforce.types import (
    FindingLite,
    TaskKind,
    TaskOutcome,
    TaskSpec,
    TaskStatus,
)


@dataclass(frozen=True, slots=True)
class TaskObservation:
    """Raw result of executing a task, before the worker judges it."""

    findings: tuple[FindingLite, ...] = ()
    probes_run: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    risk: float = 0.0
    requests: int = 0
    skipped: str = ""
    error: str = ""
    confirmed: bool | None = None
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "findings": len(self.findings),
            "probes_run": list(self.probes_run),
            "endpoints": len(self.endpoints),
            "risk": self.risk,
            "requests": self.requests,
            "skipped": self.skipped,
            "error": self.error,
            "confirmed": self.confirmed,
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    """What the service must actually run for a task."""

    target_url: str
    probe_ids: tuple[str, ...]
    budget_requests: int
    is_verification: bool = False
    expect_kind: str = ""
    expect_fingerprint: str = ""


class Worker:
    name: str = "worker"
    description: str = ""
    kinds: tuple[TaskKind, ...] = (TaskKind.probe,)

    def accepts(self, task: TaskSpec) -> bool:
        return task.kind in self.kinds

    def plan(self, task: TaskSpec) -> ExecutionRequest:
        probes: tuple[str, ...] = (task.probe_id,) if task.probe_id else ()
        return ExecutionRequest(
            target_url=task.route,
            probe_ids=probes,
            budget_requests=task.budget_requests,
            is_verification=task.kind is TaskKind.verify,
            expect_kind=task.verify_kind,
            expect_fingerprint=str(task.payload.get("fingerprint", "")),
        )

    def judge(self, task: TaskSpec, observation: TaskObservation) -> TaskOutcome:
        if observation.error:
            return TaskOutcome(
                task_key=task.key,
                status=TaskStatus.failed,
                findings=observation.findings,
                probes_run=observation.probes_run,
                endpoints=observation.endpoints,
                risk=observation.risk,
                requests=observation.requests,
                error=observation.error,
            )
        if observation.skipped and not observation.probes_run:
            return TaskOutcome(
                task_key=task.key,
                status=TaskStatus.skipped,
                notes=(observation.skipped,),
                requests=observation.requests,
            )
        return TaskOutcome(
            task_key=task.key,
            status=TaskStatus.done,
            findings=observation.findings,
            probes_run=observation.probes_run,
            endpoints=observation.endpoints,
            risk=observation.risk,
            requests=observation.requests,
            confirmed=observation.confirmed,
        )


class ReconWorker(Worker):
    """Map the surface. A recon task with no endpoints is a failed recon."""

    name = "recon-worker"
    description = "Bounded surface discovery"
    kinds = (TaskKind.recon,)

    def judge(self, task: TaskSpec, observation: TaskObservation) -> TaskOutcome:
        outcome = super().judge(task, observation)
        if outcome.status is TaskStatus.done and not observation.endpoints:
            return TaskOutcome(
                task_key=task.key,
                status=TaskStatus.failed,
                findings=observation.findings,
                probes_run=observation.probes_run,
                risk=observation.risk,
                requests=observation.requests,
                error="discovery produced no endpoints; the surface is unmeasured",
            )
        return TaskOutcome(
            task_key=outcome.task_key,
            status=outcome.status,
            findings=outcome.findings,
            probes_run=outcome.probes_run,
            endpoints=outcome.endpoints,
            risk=outcome.risk,
            requests=outcome.requests,
            error=outcome.error,
            notes=(f"{len(observation.endpoints)} endpoints discovered",),
        )


class ConfigWorker(Worker):
    name = "config-worker"
    description = "Configuration, transport and error-handling posture"
    kinds = (TaskKind.probe,)


class AuthWorker(Worker):
    name = "auth-worker"
    description = "Token, cookie and cross-origin trust"
    kinds = (TaskKind.probe,)


class ExposureWorker(Worker):
    name = "exposure-worker"
    description = "Static exposure and published API surface"
    kinds = (TaskKind.probe,)


class SurfaceWorker(Worker):
    name = "surface-worker"
    description = "Request-shape probes (redirects, GraphQL)"
    kinds = (TaskKind.probe,)


class VerifierWorker(Worker):
    """Re-run a claim in isolation. This worker can refute, and refutation wins."""

    name = "verifier-worker"
    description = "Independent reproduction of a serious claim"
    kinds = (TaskKind.verify,)

    def judge(self, task: TaskSpec, observation: TaskObservation) -> TaskOutcome:
        if observation.error:
            return TaskOutcome(
                task_key=task.key,
                status=TaskStatus.failed,
                requests=observation.requests,
                error=f"verification failed: {observation.error}",
            )
        confirmed = bool(observation.confirmed)
        if not confirmed:
            return TaskOutcome(
                task_key=task.key,
                status=TaskStatus.done,
                findings=observation.findings,
                probes_run=observation.probes_run,
                endpoints=observation.endpoints,
                requests=observation.requests,
                confirmed=False,
                notes=(f"could not reproduce {task.verify_kind} at {task.route}; the claim is refuted",),
            )
        return TaskOutcome(
            task_key=task.key,
            status=TaskStatus.done,
            findings=observation.findings,
            probes_run=observation.probes_run,
            endpoints=observation.endpoints,
            requests=observation.requests,
            confirmed=True,
            notes=(f"reproduced {task.verify_kind} at {task.route}",),
        )


class ReportWorker(Worker):
    """Assemble the deliverable. It never invents conclusions."""

    name = "report-worker"
    description = "Completion report assembly"
    kinds = (TaskKind.report,)

    def plan(self, task: TaskSpec) -> ExecutionRequest:
        return ExecutionRequest(target_url=task.route, probe_ids=(), budget_requests=0)

    def judge(self, task: TaskSpec, observation: TaskObservation) -> TaskOutcome:
        return TaskOutcome(
            task_key=task.key,
            status=TaskStatus.done,
            notes=observation.notes or ("report assembled from task evidence",),
        )


_REGISTRY: dict[str, Worker] = {
    worker.name: worker
    for worker in (
        ReconWorker(),
        ConfigWorker(),
        AuthWorker(),
        ExposureWorker(),
        SurfaceWorker(),
        VerifierWorker(),
        ReportWorker(),
    )
}


def get_worker(name: str) -> Worker:
    return _REGISTRY.get(name, ConfigWorker())


def worker_catalog() -> list[dict[str, object]]:
    return [
        {"name": worker.name, "description": worker.description, "kinds": [kind.value for kind in worker.kinds]}
        for worker in sorted(_REGISTRY.values(), key=lambda item: item.name)
    ]


def workers_for(task: TaskSpec) -> Worker:
    worker = get_worker(task.worker)
    if not worker.accepts(task):
        raise ValueError(f"{worker.name} does not accept {task.kind.value} tasks")
    return worker
