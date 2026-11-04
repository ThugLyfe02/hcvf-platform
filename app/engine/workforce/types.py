"""Objective-driven workforce: shared vocabulary.

An *objective* is a piece of delegated work with observable acceptance criteria.
It is decomposed into a DAG of *tasks*; each task is claimed by a *worker* that
knows one narrow discipline, executed surgically, and verified before its result
counts.

Everything in this package is pure: no database, no network, no HTTP client. The
service layer turns objectives into engine runs and feeds outcomes back in, which
is what makes the whole thing testable without infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.engine.types import SafetyClass


class ObjectiveStatus(StrEnum):
    draft = "draft"
    queued = "queued"
    running = "running"
    completed = "completed"
    blocked = "blocked"
    failed = "failed"
    cancelled = "cancelled"


class TaskStatus(StrEnum):
    pending = "pending"
    ready = "ready"
    running = "running"
    done = "done"
    failed = "failed"
    blocked = "blocked"
    skipped = "skipped"


class TaskKind(StrEnum):
    recon = "recon"
    probe = "probe"
    verify = "verify"
    audit = "audit"
    diagnose = "diagnose"
    report = "report"


class CriterionKind(StrEnum):
    finding_present = "finding_present"
    finding_absent = "finding_absent"
    min_probes = "min_probes"
    min_endpoints = "min_endpoints"
    risk_below = "risk_below"
    risk_above = "risk_above"
    min_verified = "min_verified"
    min_route_coverage = "min_route_coverage"


TEMPLATES = ("posture", "auth", "exposure", "coverage", "custom")


@dataclass(frozen=True, slots=True)
class Criterion:
    """One observable condition the delegated work must satisfy."""

    kind: CriterionKind
    value: float | str = 0.0
    key: str = ""
    label: str = ""
    required: bool = True

    @property
    def description(self) -> str:
        if self.label:
            return self.label
        if self.kind in {CriterionKind.finding_present, CriterionKind.finding_absent}:
            return (
                f"{'must observe' if self.kind == CriterionKind.finding_present else 'must not observe'} {self.key!r}"
            )
        return f"{self.kind.value} {self.value}"


@dataclass(frozen=True, slots=True)
class CriterionResult:
    criterion: Criterion
    satisfied: bool
    observed: str
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.criterion.kind.value,
            "value": self.criterion.value,
            "key": self.criterion.key,
            "required": self.criterion.required,
            "satisfied": self.satisfied,
            "observed": self.observed,
            "detail": self.detail,
            "description": self.criterion.description,
        }


@dataclass(frozen=True, slots=True)
class FindingLite:
    """A finding as the workforce needs to see it — no ORM, no blobs."""

    fingerprint: str
    kind: str
    severity: str
    confidence: float
    probe_id: str
    route: str
    title: str = ""
    cwe: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "kind": self.kind,
            "severity": self.severity,
            "confidence": self.confidence,
            "probe_id": self.probe_id,
            "route": self.route,
            "title": self.title,
            "cwe": self.cwe,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """A single surgical unit of work."""

    key: str
    seq: int
    kind: TaskKind
    title: str
    worker: str
    probe_id: str = ""
    route: str = ""
    depends_on: tuple[str, ...] = ()
    budget_requests: int = 20
    max_attempts: int = 2
    safety: SafetyClass = SafetyClass.read_only
    #: For verify tasks: the finding kind that must be independently confirmed.
    verify_kind: str = ""
    payload: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "seq": self.seq,
            "kind": self.kind.value,
            "title": self.title,
            "worker": self.worker,
            "probe_id": self.probe_id,
            "route": self.route,
            "depends_on": list(self.depends_on),
            "budget_requests": self.budget_requests,
            "max_attempts": self.max_attempts,
            "safety": self.safety.name,
            "verify_kind": self.verify_kind,
        }


@dataclass(frozen=True, slots=True)
class TaskOutcome:
    """What a worker produced for one task."""

    task_key: str
    status: TaskStatus
    findings: tuple[FindingLite, ...] = ()
    probes_run: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    risk: float = 0.0
    requests: int = 0
    #: verify tasks only: did the re-run reproduce the claim?
    confirmed: bool | None = None
    error: str = ""
    notes: tuple[str, ...] = ()
    #: Route this outcome was produced against, for coverage accounting.
    route: str = ""

    @property
    def ok(self) -> bool:
        return self.status is TaskStatus.done

    def to_dict(self) -> dict[str, object]:
        return {
            "task_key": self.task_key,
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "probes_run": list(self.probes_run),
            "endpoints": list(self.endpoints),
            "risk": self.risk,
            "requests": self.requests,
            "confirmed": self.confirmed,
            "error": self.error,
            "notes": list(self.notes),
            "route": self.route,
        }


@dataclass(frozen=True, slots=True)
class SurfaceSnapshot:
    """What is already known about the target when the objective is planned."""

    origin: str
    routes: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    #: Probes already executed recently; used to avoid re-running the same work.
    covered_probes: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, object]:
        return {
            "origin": self.origin,
            "routes": list(self.routes),
            "endpoints": list(self.endpoints),
            "covered_probes": sorted(self.covered_probes),
        }


@dataclass(frozen=True, slots=True)
class ObjectiveSpec:
    """The delegated work order."""

    key: str
    title: str
    target: str
    template: str
    #: surface | standard | deep - declared thoroughness, drives planner caps.
    depth: str = "standard"
    safety: SafetyClass = SafetyClass.read_only
    budget_requests: int = 120
    per_task_budget: int = 20
    criteria: tuple[Criterion, ...] = ()
    priority: int = 5
    deadline_minutes: int = 120
    description: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "title": self.title,
            "target": self.target,
            "template": self.template,
            "depth": self.depth,
            "safety": self.safety.name,
            "budget_requests": self.budget_requests,
            "per_task_budget": self.per_task_budget,
            "criteria": [criterion.description for criterion in self.criteria],
            "priority": self.priority,
            "deadline_minutes": self.deadline_minutes,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class PlanResult:
    spec: ObjectiveSpec
    tasks: tuple[TaskSpec, ...]
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "spec": self.spec.to_dict(),
            "tasks": [task.to_dict() for task in self.tasks],
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    """The supervisor's decision about the objective as a whole."""

    status: ObjectiveStatus
    reason: str
    unmet: tuple[str, ...] = ()
    completed_tasks: int = 0
    failed_tasks: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "unmet": list(self.unmet),
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
        }
