"""Supervisor: the only component allowed to say "done".

The supervisor owns task state, decides what may run next, injects verification
tasks when a serious claim appears, retries within limits, and refuses completion
while a required acceptance criterion is unmet.

It is a pure state machine. The service layer feeds it outcomes; it never touches
a database or a socket.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.engine.workforce.criteria import (
    EvidenceBundle,
    evaluate,
    needs_verification,
    summarise,
    unmet,
)
from app.engine.workforce.decompose import retarget, verification_task
from app.engine.workforce.types import (
    Criterion,
    CriterionResult,
    FindingLite,
    ObjectiveSpec,
    ObjectiveStatus,
    PlanResult,
    SurfaceSnapshot,
    TaskKind,
    TaskOutcome,
    TaskSpec,
    TaskStatus,
    Verdict,
)

TERMINAL = {TaskStatus.done, TaskStatus.failed, TaskStatus.skipped, TaskStatus.blocked}


@dataclass
class TaskState:
    spec: TaskSpec
    status: TaskStatus = TaskStatus.pending
    attempts: int = 0
    outcome: TaskOutcome | None = None
    error: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "key": self.spec.key,
            "seq": self.spec.seq,
            "kind": self.spec.kind.value,
            "title": self.spec.title,
            "worker": self.spec.worker,
            "route": self.spec.route,
            "probe_id": self.spec.probe_id,
            "status": self.status.value,
            "attempts": self.attempts,
            "error": self.error,
            "depends_on": list(self.spec.depends_on),
            "outcome": self.outcome.to_dict() if self.outcome else None,
        }


@dataclass(frozen=True, slots=True)
class SupervisorEvent:
    """What changed as a result of recording an outcome."""

    task_key: str
    status: TaskStatus
    retried: bool = False
    added_tasks: tuple[TaskSpec, ...] = ()
    notes: tuple[str, ...] = ()


def outcome_from_row(row: dict) -> TaskOutcome | None:
    """Rebuild a task outcome from its persisted JSON.

    Evidence must survive the boundary between process steps: each step loads a
    fresh supervisor, and a supervisor that forgets past outcomes cannot judge
    the objective's acceptance criteria.
    """

    payload = row.get("outcome") or {}
    if not payload:
        return None
    findings = tuple(
        FindingLite(
            fingerprint=str(item.get("fingerprint", "")),
            kind=str(item.get("kind", "")),
            severity=str(item.get("severity", "info")),
            confidence=float(item.get("confidence", 0.0) or 0.0),
            probe_id=str(item.get("probe_id", "")),
            route=str(item.get("route", "")),
        )
        for item in payload.get("findings", [])
        if isinstance(item, dict)
    )
    return TaskOutcome(
        task_key=str(payload.get("task_key", row.get("key", ""))),
        status=TaskStatus(str(payload.get("status", "done"))),
        findings=findings,
        probes_run=tuple(str(item) for item in payload.get("probes_run", [])),
        endpoints=tuple(str(item) for item in payload.get("endpoints", [])),
        risk=float(payload.get("risk", 0.0) or 0.0),
        requests=int(payload.get("requests", 0) or 0),
        confirmed=payload.get("confirmed"),
        error=str(payload.get("error", "") or ""),
        notes=tuple(str(item) for item in payload.get("notes", [])),
        route=str(payload.get("route", "") or ""),
    )


@dataclass
class Supervisor:
    spec: ObjectiveSpec
    states: dict[str, TaskState] = field(default_factory=dict)
    started: bool = False

    @classmethod
    def from_plan(cls, plan: PlanResult) -> Supervisor:
        supervisor = cls(spec=plan.spec)
        for task in plan.tasks:
            supervisor.states[task.key] = TaskState(spec=task)
        return supervisor

    @classmethod
    def from_persisted(cls, spec: ObjectiveSpec, tasks: list[dict]) -> Supervisor:
        supervisor = cls(spec=spec)
        for row in tasks:
            task = TaskSpec(
                key=str(row["key"]),
                seq=int(row.get("seq", 0)),
                kind=TaskKind(str(row.get("kind", "probe"))),
                title=str(row.get("title", "")),
                worker=str(row.get("worker", "config-worker")),
                probe_id=str(row.get("probe_id", "") or ""),
                route=str(row.get("route", "") or ""),
                depends_on=tuple(str(item) for item in row.get("depends_on", [])),
                budget_requests=int(row.get("budget_requests", 10) or 10),
                max_attempts=int(row.get("max_attempts", 2) or 2),
                verify_kind=str(row.get("verify_kind", "") or ""),
                payload=dict(row.get("payload", {}) or {}),
            )
            state = TaskState(
                spec=task,
                status=TaskStatus(str(row.get("status", "pending"))),
                attempts=int(row.get("attempts", 0) or 0),
                outcome=outcome_from_row(row),
                error=str(row.get("error", "") or ""),
            )
            supervisor.states[task.key] = state
        return supervisor

    # -- queries ---------------------------------------------------------
    def get(self, key: str) -> TaskState:
        return self.states[key]

    def ordered(self) -> list[TaskState]:
        return sorted(self.states.values(), key=lambda state: (state.spec.seq, state.spec.key))

    def ready(self, *, mark: bool = False) -> list[TaskState]:
        """Tasks whose dependencies are satisfied and that may run now.

        A query by default. ``mark=True`` promotes pending tasks to ready, which
        is how a task is claimed. Mutating on every call would let a task that
        was marked ready in an earlier round become invisible to later rounds.
        """

        ready: list[TaskState] = []
        for state in self.ordered():
            if state.status not in {TaskStatus.pending, TaskStatus.ready}:
                continue
            deps = [self.states.get(key) for key in state.spec.depends_on]
            if any(dep is None for dep in deps):
                continue
            if all(dep.status in {TaskStatus.done, TaskStatus.skipped} for dep in deps):  # type: ignore[union-attr]
                ready.append(state)
        if mark:
            for state in ready:
                if state.status is TaskStatus.pending:
                    state.status = TaskStatus.ready
        ready.sort(key=lambda state: (len(state.spec.depends_on), state.spec.seq))
        return ready

    def next_task(self) -> TaskState | None:
        candidates = self.ready(mark=True)
        return candidates[0] if candidates else None

    def evidence(self) -> EvidenceBundle:
        bundle = EvidenceBundle()
        for state in self.ordered():
            if state.outcome is not None and state.status is TaskStatus.done:
                bundle.absorb(state.outcome)
        return bundle

    def criteria_results(self, criteria: tuple[Criterion, ...] | None = None) -> list[CriterionResult]:
        return evaluate(criteria or self.spec.criteria, self.evidence())

    def progress(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for state in self.states.values():
            counts[state.status.value] = counts.get(state.status.value, 0) + 1
        return counts

    def add_tasks(self, tasks) -> tuple[TaskSpec, ...]:
        """Adopt newly planned tasks (coverage expansion, diagnosis)."""

        added: list[TaskSpec] = []
        for task in tasks:
            if task.key in self.states:
                continue
            self.states[task.key] = TaskState(spec=task)
            added.append(task)
        return tuple(added)

    # -- transitions -----------------------------------------------------
    def mark_running(self, key: str) -> TaskState:
        state = self.states[key]
        if state.status not in {TaskStatus.pending, TaskStatus.ready}:
            raise ValueError(f"task {key} is {state.status.value}, not startable")
        state.status = TaskStatus.running
        state.attempts += 1
        self.started = True
        return state

    def record(self, outcome: TaskOutcome) -> SupervisorEvent:
        state = self.states.get(outcome.task_key)
        if state is None:
            raise ValueError(f"unknown task {outcome.task_key}")

        state.outcome = outcome
        state.error = outcome.error
        added: list[TaskSpec] = []
        notes = list(outcome.notes)

        if outcome.status is TaskStatus.failed:
            if state.attempts < state.spec.max_attempts:
                state.status = TaskStatus.pending
                notes.append(f"attempt {state.attempts} failed; retrying")
                return SupervisorEvent(outcome.task_key, state.status, retried=True, notes=tuple(notes))
            state.status = TaskStatus.blocked
            notes.append(f"blocked after {state.attempts} attempt(s)")
            added: list[TaskSpec] = []
            if state.spec.kind in {TaskKind.recon, TaskKind.probe, TaskKind.verify}:
                added = list(self._schedule_diagnosis(state))
            return SupervisorEvent(outcome.task_key, state.status, added_tasks=tuple(added), notes=tuple(notes))

        if outcome.status is TaskStatus.skipped:
            state.status = TaskStatus.skipped
            return SupervisorEvent(outcome.task_key, state.status, notes=tuple(notes))

        state.status = TaskStatus.done
        # Serious claims must be reproduced by an independent task before they
        # can contribute to "min_verified" or a finding-based criterion.
        if state.spec.kind is TaskKind.probe:
            for finding in needs_verification(outcome.findings):
                if any(
                    other.spec.kind is TaskKind.verify and other.spec.payload.get("fingerprint") == finding.fingerprint
                    for other in self.states.values()
                ):
                    continue
                task = verification_task(
                    parent=state.spec,
                    fingerprint=finding.fingerprint,
                    finding_kind=finding.kind,
                    seq=max(item.spec.seq for item in self.states.values()) + 1,
                )
                self.states[task.key] = TaskState(spec=task)
                added.append(task)
                notes.append(f"queued verification for {finding.kind} ({finding.severity})")

        return SupervisorEvent(outcome.task_key, state.status, added_tasks=tuple(added), notes=tuple(notes))

    def retarget_pending(self, snapshot: SurfaceSnapshot) -> int:
        """Re-aim pending probe tasks after recon discovers better routes."""

        updated = 0
        tasks = tuple(state.spec for state in self.ordered())
        reaimed = {task.key: task for task in retarget(tasks, snapshot)}
        for key, task in reaimed.items():
            state = self.states[key]
            if state.spec.route != task.route and state.status is TaskStatus.pending:
                state.spec = task
                updated += 1
        return updated

    # -- diagnosis -------------------------------------------------------
    def _schedule_diagnosis(self, failed: TaskState) -> tuple[TaskSpec, ...]:
        exists = any(
            other.spec.kind is TaskKind.diagnose and other.spec.payload.get("failed_task") == failed.spec.key
            for other in self.states.values()
        )
        if exists:
            return ()
        task = TaskSpec(
            key=f"d{failed.spec.seq:02d}-diagnose",
            seq=max(item.spec.seq for item in self.states.values()) + 1,
            kind=TaskKind.diagnose,
            title=f"Diagnose the failure of {failed.spec.title}",
            worker="diagnose-worker",
            route=failed.spec.route,
            probe_id="",
            depends_on=(failed.spec.key,),
            budget_requests=3,
            max_attempts=1,
            safety=failed.spec.safety,
            payload={
                "failed_task": failed.spec.key,
                "error": (failed.error or "")[:400],
                "probe_id": failed.spec.probe_id,
            },
        )
        self.states[task.key] = TaskState(spec=task)
        return (task,)

    def _diagnosis(self, failed: TaskState) -> TaskState | None:
        for state in self.states.values():
            if state.spec.kind is TaskKind.diagnose and state.spec.payload.get("failed_task") == failed.spec.key:
                return state
        return None

    def _diagnosis_pending(self, failed: TaskState) -> bool:
        diagnosis = self._diagnosis(failed)
        return diagnosis is not None and diagnosis.status not in TERMINAL

    def _diagnosis_notes(self, failed: TaskState) -> list[str]:
        diagnosis = self._diagnosis(failed)
        if diagnosis is None or diagnosis.outcome is None:
            return []
        return [f"{failed.spec.title}: {note}" for note in diagnosis.outcome.notes]

    # -- verdict ---------------------------------------------------------
    def verdict(self, criteria: tuple[Criterion, ...] | None = None) -> Verdict:
        actual = criteria or self.spec.criteria
        results = self.criteria_results(actual)
        failed_tasks = [state for state in self.states.values() if state.status is TaskStatus.blocked]
        done_tasks = [state for state in self.states.values() if state.status is TaskStatus.done]
        pending = [state for state in self.states.values() if state.status not in TERMINAL]

        under_diagnosis = [state for state in failed_tasks if self._diagnosis_pending(state)]
        if under_diagnosis:
            return Verdict(
                ObjectiveStatus.running,
                f"{len(under_diagnosis)} failure(s) under diagnosis",
                unmet=tuple(unmet(results)),
                completed_tasks=len(done_tasks),
            )

        if failed_tasks:
            diagnosis_notes = [note for state in failed_tasks for note in self._diagnosis_notes(state)]
            reason = f"{len(failed_tasks)} task(s) blocked: " + "; ".join(
                state.error or state.spec.title for state in failed_tasks
            )
            if diagnosis_notes:
                reason += " | diagnosis: " + "; ".join(diagnosis_notes[:3])
            return Verdict(
                ObjectiveStatus.blocked,
                reason,
                unmet=tuple(unmet(results)),
                completed_tasks=len(done_tasks),
                failed_tasks=len(failed_tasks),
            )

        if pending:
            return Verdict(
                ObjectiveStatus.running,
                f"{len(pending)} task(s) still outstanding",
                unmet=tuple(unmet(results)),
                completed_tasks=len(done_tasks),
            )

        missing = unmet(results)
        if missing:
            return Verdict(
                ObjectiveStatus.blocked,
                "acceptance criteria not met: " + "; ".join(missing),
                unmet=tuple(missing),
                completed_tasks=len(done_tasks),
            )

        return Verdict(
            ObjectiveStatus.completed,
            "all acceptance criteria satisfied: " + summarise(results),
            completed_tasks=len(done_tasks),
        )

    def report(self) -> dict[str, object]:
        verdict = self.verdict()
        evidence = self.evidence()
        return {
            "objective": self.spec.to_dict(),
            "verdict": verdict.to_dict(),
            "criteria": [result.to_dict() for result in self.criteria_results()],
            "evidence": evidence.to_dict(),
            "tasks": [state.to_dict() for state in self.ordered()],
            "progress": self.progress(),
            "findings": [finding.to_dict() for finding in evidence.findings.values()],
        }

    def replan_verification(self) -> tuple[TaskSpec, ...]:
        """Safety net: queue verification for any serious finding still unverified."""

        added: list[TaskSpec] = []
        for state in self.ordered():
            if state.outcome is None or state.spec.kind is not TaskKind.probe:
                continue
            for finding in needs_verification(state.outcome.findings):
                already = any(
                    other.spec.kind is TaskKind.verify and other.spec.payload.get("fingerprint") == finding.fingerprint
                    for other in self.states.values()
                )
                if already:
                    continue
                task = verification_task(
                    parent=state.spec,
                    fingerprint=finding.fingerprint,
                    finding_kind=finding.kind,
                    seq=max(item.spec.seq for item in self.states.values()) + 1,
                )
                self.states[task.key] = TaskState(spec=task)
                added.append(task)
        return tuple(added)
