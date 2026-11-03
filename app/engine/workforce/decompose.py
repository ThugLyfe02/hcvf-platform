"""Decomposition: turn a delegated objective into a surgical task DAG.

The planner is deliberately conservative. It does not invent work it cannot
justify: every probe task names one probe, one route and one budget, and every
dependency exists so that later work can use a better surface map.

Templates encode doctrine; criteria encode acceptance. A caller can override
either.
"""

from __future__ import annotations

import re
from dataclasses import replace

from app.engine.probes import registry
from app.engine.types import SafetyClass, stable_hash
from app.engine.workforce.coverage import plan_coverage
from app.engine.workforce.types import (
    Criterion,
    CriterionKind,
    ObjectiveSpec,
    PlanResult,
    SurfaceSnapshot,
    TaskKind,
    TaskSpec,
)

#: Which probes each doctrine bundles.
TEMPLATE_PROBES: dict[str, tuple[str, ...]] = {
    "posture": ("security-headers", "tls-posture", "cookie-flags", "http-methods", "error-disclosure"),
    "auth": ("jwt-posture", "cors-policy", "cookie-flags"),
    "exposure": ("exposed-config", "openapi-surface", "security-txt"),
    "coverage": ("security-headers", "cookie-flags", "cors-policy", "exposed-config"),
    # Seed only: after recon the adaptive planner picks by expected
    # information gain instead of following this list.
    "adaptive": ("security-headers", "cors-policy", "jwt-posture"),
}

#: Default acceptance: the work must actually have been performed, with evidence.
TEMPLATE_CRITERIA: dict[str, tuple[Criterion, ...]] = {
    "posture": (
        Criterion(CriterionKind.min_probes, 4, label="at least four posture probes executed"),
        Criterion(CriterionKind.min_endpoints, 1, label="surface discovery produced an endpoint"),
    ),
    "auth": (
        Criterion(CriterionKind.min_probes, 3, label="at least three identity probes executed"),
        Criterion(CriterionKind.min_endpoints, 1, label="surface discovery produced an endpoint"),
    ),
    "exposure": (
        Criterion(CriterionKind.min_probes, 2, label="at least two exposure probes executed"),
        Criterion(CriterionKind.min_endpoints, 1, label="surface discovery produced an endpoint"),
    ),
    "coverage": (
        Criterion(CriterionKind.min_probes, 4, label="at least four probes executed"),
        Criterion(CriterionKind.min_endpoints, 2, label="at least two endpoints discovered"),
        Criterion(CriterionKind.min_route_coverage, 0.5, label="at least half of discovered routes probed"),
    ),
    "adaptive": (
        Criterion(CriterionKind.min_probes, 3, label="at least three probes executed"),
        Criterion(CriterionKind.min_endpoints, 1, label="surface discovery produced an endpoint"),
    ),
    "custom": (Criterion(CriterionKind.min_probes, 1, label="at least one probe executed"),),
}

#: Doctrine-specific route preferences, mirroring the deliberation layer.
ROUTE_AFFINITY: dict[str, tuple[str, ...]] = {
    "jwt-posture": ("login", "auth", "token", "oauth", "session", "sso"),
    "cors-policy": ("api", "graphql"),
    "cookie-flags": ("login", "auth", "session"),
    "http-methods": ("admin", "internal", "api", "actuator"),
    "exposed-config": ("",),
    "openapi-surface": ("",),
    "security-txt": ("",),
    "error-disclosure": ("api", "admin", "search"),
}

WORKER_BY_PROBE: dict[str, str] = {
    "security-headers": "config-worker",
    "tls-posture": "config-worker",
    "cookie-flags": "config-worker",
    "http-methods": "config-worker",
    "error-disclosure": "config-worker",
    "jwt-posture": "auth-worker",
    "cors-policy": "auth-worker",
    "rate-limit": "auth-worker",
    "exposed-config": "exposure-worker",
    "openapi-surface": "exposure-worker",
    "security-txt": "exposure-worker",
    "surface-crawl": "recon-worker",
    "graphql-introspection": "surface-worker",
    "open-redirect": "surface-worker",
}

#: Findings that must be independently reproduced before an objective can complete.
VERIFY_SEVERITIES = ("high", "critical")


class DecompositionError(ValueError):
    pass


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned[:48] or "objective"


def _probe_spec(probe_id: str):
    cls = registry().get(probe_id)
    return cls.spec if cls else None


def choose_route(snapshot: SurfaceSnapshot, probe_id: str) -> str:
    """Pick a route that suits the doctrine, defaulting to the entry point."""

    candidates = list(snapshot.routes) or [snapshot.origin + "/"]
    tokens = ROUTE_AFFINITY.get(probe_id, ())
    if not tokens or not any(tokens):
        return candidates[0]

    def score(url: str) -> int:
        lowered = url.lower()
        return sum(1 for token in tokens if token and token in lowered)

    ranked = sorted(candidates, key=score, reverse=True)
    best = score(ranked[0])
    near = [url for url in ranked if score(url) == best]
    # Spread probes across equally-good routes deterministically, so an
    # objective does not spend its whole budget on one endpoint.
    return near[int(stable_hash(probe_id)[:8], 16) % len(near)]


def _budget_split(spec: ObjectiveSpec, probe_count: int) -> tuple[int, int]:
    recon_budget = max(8, min(spec.per_task_budget, spec.budget_requests // 5))
    probe_budget = max(4, min(spec.per_task_budget, spec.budget_requests // max(1, probe_count + 1)))
    return recon_budget, probe_budget


def plan_objective(spec: ObjectiveSpec, snapshot: SurfaceSnapshot) -> PlanResult:
    """Build the DAG for one objective."""

    if spec.template not in TEMPLATE_PROBES and spec.template != "custom":
        raise DecompositionError(f"unknown template {spec.template!r}")
    if spec.budget_requests < 10:
        raise DecompositionError("budget must be at least 10 requests")
    if spec.per_task_budget < 4:
        raise DecompositionError("per-task budget must be at least 4 requests")

    probe_ids = list(TEMPLATE_PROBES.get(spec.template, ()))
    if spec.template == "custom":
        probe_ids = _probes_from_criteria(spec.criteria)

    # Never plan a probe the grant's safety ceiling forbids.
    allowed = [
        probe_id
        for probe_id in probe_ids
        if _probe_spec(probe_id) is not None and _probe_spec(probe_id).safety <= spec.safety
    ]
    if not allowed:
        raise DecompositionError("no probe in this template is permitted by the safety ceiling")

    recon_budget, probe_budget = _budget_split(spec, len(allowed))
    tasks: list[TaskSpec] = []
    notes: list[str] = []

    recon = TaskSpec(
        key=f"t00-recon-{slugify(spec.template)}",
        seq=0,
        kind=TaskKind.recon,
        title=f"Map the surface of {snapshot.origin}",
        worker="recon-worker",
        probe_id="surface-crawl",
        route=choose_route(snapshot, "surface-crawl"),
        budget_requests=recon_budget,
        max_attempts=2,
        safety=SafetyClass.read_only,
    )
    tasks.append(recon)

    for index, probe_id in enumerate(allowed, start=1):
        probe_spec = _probe_spec(probe_id)
        assert probe_spec is not None
        route = choose_route(snapshot, probe_id)
        tasks.append(
            TaskSpec(
                key=f"t{index:02d}-{slugify(probe_id)}",
                seq=index,
                kind=TaskKind.probe,
                title=f"{probe_spec.name} at {route}",
                worker=WORKER_BY_PROBE.get(probe_id, "config-worker"),
                probe_id=probe_id,
                route=route,
                depends_on=(recon.key,),
                budget_requests=probe_budget,
                max_attempts=2,
                safety=probe_spec.safety,
            )
        )

    if spec.template == "coverage":
        plan = plan_coverage(
            origin=snapshot.origin,
            routes=tuple(snapshot.routes),
            endpoints=(),
            allowed_probes=tuple(allowed),
            max_routes=4,
            max_tasks=max(4, spec.budget_requests // max(1, probe_budget) - 2),
        )
        start_seq = len(tasks)
        for offset, (route, probe_id) in enumerate(plan.assignments):
            probe_spec = _probe_spec(probe_id)
            if probe_spec is None:
                continue
            seq = start_seq + offset
            tasks.append(
                TaskSpec(
                    key=f"t{seq:02d}-cov-{slugify(probe_id)}-{slugify(route.rsplit('/', 1)[-1]) or 'entry'}",
                    seq=seq,
                    kind=TaskKind.probe,
                    title=f"{probe_spec.name} at {route}",
                    worker=WORKER_BY_PROBE.get(probe_id, "config-worker"),
                    probe_id=probe_id,
                    route=route,
                    depends_on=(recon.key,),
                    budget_requests=probe_budget,
                    max_attempts=1,
                    safety=probe_spec.safety,
                    payload={"coverage": True},
                )
            )
        if plan.assignments:
            notes.append(
                f"coverage plan assigned {len(plan.assignments)} route-specific task(s) across "
                f"{len(plan.routes)} route(s)"
            )
        if plan.skipped_reasons:
            notes.append("; ".join(plan.skipped_reasons))

    audit = TaskSpec(
        key=f"t{len(tasks):02d}-audit",
        seq=len(tasks),
        kind=TaskKind.audit,
        title="Verify the integrity of every captured evidence manifest",
        worker="auditor-worker",
        route=snapshot.origin + "/",
        depends_on=tuple(task.key for task in tasks if task.kind in {TaskKind.recon, TaskKind.probe}),
        budget_requests=0,
        max_attempts=1,
        safety=SafetyClass.read_only,
    )
    tasks.append(audit)

    report = TaskSpec(
        key=f"t{len(tasks):02d}-report",
        seq=len(tasks),
        kind=TaskKind.report,
        title="Assemble the completion report",
        worker="report-worker",
        route=snapshot.origin + "/",
        depends_on=tuple(task.key for task in tasks if task.kind is not TaskKind.report),
        budget_requests=0,
        max_attempts=1,
        safety=SafetyClass.read_only,
    )
    tasks.append(report)

    if snapshot.covered_probes:
        for task in tasks:
            if task.kind is TaskKind.probe and task.probe_id in snapshot.covered_probes:
                notes.append(f"{task.probe_id} was recently executed; still re-running for a fresh proof")

    return PlanResult(spec=spec, tasks=tuple(tasks), notes=tuple(notes))


def _probes_from_criteria(criteria: tuple[Criterion, ...]) -> list[str]:
    """Map finding-kind criteria back to the probes that could produce them."""

    mapping = {
        "missing-content-security-policy": "security-headers",
        "weak-content-security-policy": "security-headers",
        "missing-hsts": "security-headers",
        "missing-nosniff": "security-headers",
        "missing-frame-protection": "security-headers",
        "missing-referrer-policy": "security-headers",
        "missing-permissions-policy": "security-headers",
        "deprecated-tls-version": "tls-posture",
        "invalid-tls-certificate": "tls-posture",
        "cookie-attributes:session": "cookie-flags",
        "jwt-alg-none": "jwt-posture",
        "jwt-missing-exp": "jwt-posture",
        "cors-reflected-origin-with-credentials": "cors-policy",
        "cors-reflected-origin": "cors-policy",
        "trace-method-enabled": "http-methods",
        "verbose-error-page": "error-disclosure",
        "vcs-metadata": "exposed-config",
        "env-file": "exposed-config",
        "path-traversal": "exposed-config",
        "openapi-specification-exposed": "openapi-surface",
        "missing-security-txt": "security-txt",
        "graphql-introspection-enabled": "graphql-introspection",
        "open-redirect": "open-redirect",
    }
    probes: list[str] = []
    for criterion in criteria:
        if criterion.kind is not CriterionKind.finding_present:
            continue
        probe_id = mapping.get(str(criterion.value))
        if probe_id and probe_id not in probes:
            probes.append(probe_id)
    return probes or ["security-headers"]


def retarget(tasks: tuple[TaskSpec, ...], snapshot: SurfaceSnapshot) -> tuple[TaskSpec, ...]:
    """Re-aim pending probe tasks at better routes discovered by recon."""

    if not snapshot.routes:
        return tasks
    updated: list[TaskSpec] = []
    for task in tasks:
        if task.kind is not TaskKind.probe:
            updated.append(task)
            continue
        better = choose_route(snapshot, task.probe_id)
        if better and better != task.route:
            updated.append(replace(task, route=better, title=f"{task.title.split(' at ')[0]} at {better}"))
        else:
            updated.append(task)
    return tuple(updated)


def verification_task(*, parent: TaskSpec, fingerprint: str, finding_kind: str, seq: int) -> TaskSpec:
    """A surgical re-run that must reproduce the finding at the same route."""

    return TaskSpec(
        key=f"t{seq:02d}-verify-{slugify(finding_kind)}",
        seq=seq,
        kind=TaskKind.verify,
        title=f"Confirm {finding_kind} at {parent.route}",
        worker="verifier-worker",
        probe_id=parent.probe_id,
        route=parent.route,
        depends_on=(parent.key,),
        budget_requests=max(2, parent.budget_requests // 2),
        max_attempts=2,
        safety=parent.safety,
        verify_kind=finding_kind,
        payload={"fingerprint": fingerprint, "finding_kind": finding_kind},
    )


def dynamic_coverage_tasks(
    *,
    origin: str,
    discovered_routes: tuple[str, ...],
    allowed_probes: tuple[str, ...],
    start_seq: int,
    per_task_budget: int,
    max_routes: int = 6,
    max_tasks: int = 12,
    recon_key: str = "",
) -> tuple[TaskSpec, ...]:
    """Expand an objective after discovery: one probe per valuable route.

    This is how the workforce finds an avenue mid-run: the plan is not frozen at
    delegation time, it grows with the surface it has measured.
    """

    plan = plan_coverage(
        origin=origin,
        routes=discovered_routes,
        allowed_probes=allowed_probes,
        max_routes=max_routes,
        max_tasks=max_tasks,
    )
    tasks: list[TaskSpec] = []
    for offset, (route, probe_id) in enumerate(plan.assignments):
        probe_spec = _probe_spec(probe_id)
        if probe_spec is None:
            continue
        seq = start_seq + offset
        tasks.append(
            TaskSpec(
                key=f"t{seq:02d}-dyn-{slugify(probe_id)}-{seq}",
                seq=seq,
                kind=TaskKind.probe,
                title=f"{probe_spec.name} at {route}",
                worker=WORKER_BY_PROBE.get(probe_id, "config-worker"),
                probe_id=probe_id,
                route=route,
                depends_on=(recon_key,) if recon_key else (),
                budget_requests=per_task_budget,
                max_attempts=1,
                safety=probe_spec.safety,
                payload={"coverage": True, "dynamic": True},
            )
        )
    return tuple(tasks)
