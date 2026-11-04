"""Objective lifecycle: delegation → decomposition → execution → verification.

This is the bridge between the durable work ledger and the pure workforce state
machine. It owns leases, persistence, evidence directories and the mapping from
an engine ``HuntResult`` to a worker observation.

Design rules enforced here:

* a task is leased before it runs, so two workers cannot execute it twice;
* an objective never exceeds its request budget or its deadline;
* a task's outcome is persisted with its evidence before the next task starts;
* "completed" is only written by the supervisor's verdict, never by the worker.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core import metrics
from app.core.config import settings
from app.engine.budget import Budget
from app.engine.errors import EngineError
from app.engine.evidence import (
    FileEvidenceStore,
    MerkleTree,
    verification_key_from_env,
    verify_manifest,
    write_manifest,
)
from app.engine.executor import HuntExecutor
from app.engine.http import GuardedHttpClient
from app.engine.policy import EgressPolicy
from app.engine.probes import registry
from app.engine.target import build_grant, parse_target
from app.engine.types import SafetyClass
from app.engine.workforce.coverage import normalize_route
from app.engine.workforce.criteria import parse_criteria
from app.engine.workforce.decompose import (
    TEMPLATE_CRITERIA,
    DecompositionError,
    dynamic_coverage_tasks,
    plan_objective,
    slugify,
)
from app.engine.workforce.replan import belief_from_outcomes, plan_adaptive
from app.engine.workforce.supervisor import Supervisor, TaskState
from app.engine.workforce.surface import build_surface
from app.engine.workforce.types import (
    Criterion,
    FindingLite,
    ObjectiveSpec,
    ObjectiveStatus,
    SurfaceSnapshot,
    TaskKind,
    TaskStatus,
    Verdict,
)
from app.engine.workforce.workers import TaskObservation, workers_for
from app.models import Campaign, Objective, ObjectiveEvent, ObjectiveTask, Run, Tenant
from app.services import asset_service, findings_ingest, memory_service, risk
from app.services.audit_service import AuditService
from app.services.campaign_service import CampaignService
from app.services.objective_artifacts import objective_diff, write_artifacts

LEASE_SECONDS = 300
MAX_TASKS_PER_TICK = 3


class ObjectiveError(ValueError):
    pass


@dataclass
class StepResult:
    objective_id: UUID
    task_key: str
    task_status: str
    verdict: Verdict
    requests_used: int

    def to_dict(self) -> dict[str, object]:
        return {
            "objective_id": str(self.objective_id),
            "task": self.task_key,
            "task_status": self.task_status,
            "verdict": self.verdict.to_dict(),
            "requests_used": self.requests_used,
        }


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


class ObjectiveService:
    def __init__(self, db: Session, *, evidence_root: Path | str | None = None) -> None:
        self.db = db
        self.evidence_root = Path(evidence_root or settings.evidence_dir)
        self.policy = EgressPolicy(
            allow_private=settings.allow_private_targets or settings.environment.lower() == "development"
        )

    # -- creation --------------------------------------------------------
    def create(
        self,
        *,
        tenant: Tenant,
        title: str,
        target_url: str,
        template: str,
        budget_requests: int,
        per_task_budget: int,
        criteria_payload: list[dict] | None,
        safety_ceiling: str,
        priority: int,
        deadline_minutes: int,
        description: str,
        actor: str,
        request_id: str | None = None,
        origin: str = "delegated",
    ) -> Objective:
        cleaned_title = title.strip()
        if not cleaned_title:
            raise ObjectiveError("objective title is required")
        if len(cleaned_title) > 255:
            raise ObjectiveError("objective title must be at most 255 characters")
        if safety_ceiling not in {"read_only", "state_changing"}:
            raise ObjectiveError("safety_ceiling must be read_only or state_changing")
        if not 1 <= priority <= 10:
            raise ObjectiveError("priority must be between 1 and 10")
        if not 5 <= deadline_minutes <= 10080:
            raise ObjectiveError("deadline_minutes must be between 5 and 10080")
        if not 10 <= budget_requests <= 5000:
            raise ObjectiveError("budget_requests must be between 10 and 5000")
        if not 4 <= per_task_budget <= 500:
            raise ObjectiveError("per_task_budget must be between 4 and 500")

        if not CampaignService._is_authorized_target(target_url, tenant.authorized_targets):
            raise ObjectiveError("objective target is not authorized for this tenant")

        target = parse_target(target_url)
        snapshot = self._snapshot(tenant.id, target.origin)
        template_criteria = TEMPLATE_CRITERIA.get(template, TEMPLATE_CRITERIA["custom"])
        criteria = parse_criteria(criteria_payload, template_criteria=template_criteria)
        if not criteria:
            raise ObjectiveError("at least one acceptance criterion is required")

        # A per-objective suffix is required: two delegations in the same
        # second for the same tenant would otherwise collide on the key.
        key = f"{slugify(template)}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{tenant.id.hex[:4]}-{uuid4().hex[:6]}"
        spec = ObjectiveSpec(
            key=key,
            title=cleaned_title,
            target=target.origin,
            template=template,
            safety=SafetyClass[safety_ceiling],
            budget_requests=budget_requests,
            per_task_budget=per_task_budget,
            criteria=criteria,
            priority=priority,
            deadline_minutes=deadline_minutes,
            description=description.strip()[:2000],
        )

        try:
            plan = plan_objective(spec, snapshot)
        except DecompositionError as exc:
            raise ObjectiveError(str(exc)) from exc

        objective = Objective(
            tenant_id=tenant.id,
            key=key,
            title=cleaned_title,
            description=spec.description,
            target_url=target.url,
            template=template,
            status=ObjectiveStatus.queued.value,
            safety_ceiling=safety_ceiling,
            budget_requests=budget_requests,
            per_task_budget=per_task_budget,
            priority=priority,
            deadline_at=datetime.now(UTC) + timedelta(minutes=deadline_minutes),
            criteria=[
                {
                    "kind": criterion.kind.value,
                    "value": criterion.value,
                    "key": criterion.key,
                    "label": criterion.label,
                    "required": criterion.required,
                }
                for criterion in criteria
            ],
            plan=plan.to_dict(),
            created_by=actor[:255],
            origin=origin,
        )
        self.db.add(objective)
        self.db.flush()

        for task in plan.tasks:
            self.db.add(
                ObjectiveTask(
                    objective_id=objective.id,
                    tenant_id=tenant.id,
                    key=task.key,
                    seq=task.seq,
                    kind=task.kind.value,
                    title=task.title,
                    worker=task.worker,
                    probe_id=task.probe_id,
                    route=task.route,
                    depends_on=list(task.depends_on),
                    budget_requests=task.budget_requests,
                    max_attempts=task.max_attempts,
                    safety=task.safety.name,
                    verify_kind=task.verify_kind,
                    payload=dict(task.payload),
                    status=TaskStatus.pending.value,
                )
            )

        self._event(
            objective,
            "objective.created",
            f"Objective {key} planned with {len(plan.tasks)} task(s) across template {template}.",
            {"template": template, "tasks": len(plan.tasks), "snapshot": snapshot.to_dict(), "notes": list(plan.notes)},
        )
        self.db.commit()
        self.db.refresh(objective)
        return objective

    def _event(self, objective: Objective, event_type: str, message: str, payload: dict) -> None:
        self.db.add(
            ObjectiveEvent(
                objective_id=objective.id,
                tenant_id=objective.tenant_id,
                type=event_type[:48],
                message=message[:2000],
                payload=payload,
                at=datetime.now(UTC),
            )
        )

    # -- queries ---------------------------------------------------------
    def get(self, *, tenant_id: UUID, objective_id: UUID) -> Objective | None:
        return self.db.scalar(select(Objective).where(Objective.id == objective_id, Objective.tenant_id == tenant_id))

    def list(self, *, tenant_id: UUID, status: str | None = None, limit: int = 50) -> list[Objective]:
        query = select(Objective).where(Objective.tenant_id == tenant_id)
        if status:
            query = query.where(Objective.status == status)
        return list(
            self.db.scalars(query.order_by(Objective.priority.desc(), Objective.created_at.desc()).limit(limit))
        )

    def tasks(self, objective_id: UUID) -> list[ObjectiveTask]:
        return list(
            self.db.scalars(
                select(ObjectiveTask).where(ObjectiveTask.objective_id == objective_id).order_by(ObjectiveTask.seq)
            )
        )

    def events(self, objective_id: UUID, limit: int = 100) -> list[ObjectiveEvent]:
        return list(
            self.db.scalars(
                select(ObjectiveEvent)
                .where(ObjectiveEvent.objective_id == objective_id)
                .order_by(ObjectiveEvent.at.desc())
                .limit(limit)
            )
        )

    # -- supervision helpers --------------------------------------------
    def _spec(self, objective: Objective) -> ObjectiveSpec:
        criteria = tuple(
            Criterion(
                kind=_criterion_kind(item),
                value=item.get("value", 0.0),
                key=str(item.get("key", "") or ""),
                label=str(item.get("label", "") or ""),
                required=bool(item.get("required", True)),
            )
            for item in objective.criteria
        )
        target = parse_target(objective.target_url)
        return ObjectiveSpec(
            key=objective.key,
            title=objective.title,
            target=target.origin,
            template=objective.template,
            safety=SafetyClass[objective.safety_ceiling],
            budget_requests=objective.budget_requests,
            per_task_budget=objective.per_task_budget,
            criteria=criteria,
            priority=objective.priority,
            description=objective.description,
        )

    def _supervisor(self, objective: Objective) -> Supervisor:
        rows = [
            {
                "key": task.key,
                "seq": task.seq,
                "kind": task.kind,
                "title": task.title,
                "worker": task.worker,
                "probe_id": task.probe_id,
                "route": task.route,
                "depends_on": list(task.depends_on or []),
                "budget_requests": task.budget_requests,
                "max_attempts": task.max_attempts,
                "verify_kind": task.verify_kind,
                "payload": dict(task.payload or {}),
                "status": task.status,
                "attempts": task.attempts,
                "error": task.error,
                "outcome": dict(task.outcome or {}),
            }
            for task in self.tasks(objective.id)
        ]
        return Supervisor.from_persisted(self._spec(objective), rows)

    def _snapshot(self, tenant_id: UUID, origin: str, *, extra_routes: tuple[str, ...] = ()) -> SurfaceSnapshot:
        runs = list(
            self.db.scalars(
                select(Run)
                .join(Campaign, Run.campaign_id == Campaign.id)
                .where(
                    Campaign.tenant_id == tenant_id,
                    Campaign.target_url.like(f"{origin}%"),
                    Run.plan.is_not(None),
                )
                .order_by(Run.created_at.desc())
                .limit(3)
            )
        )
        routes: list[str] = list(extra_routes)
        covered: set[str] = set()
        endpoints: set[str] = set()
        for run in runs:
            plan = run.plan or {}
            for route in plan.get("routes", []) or []:
                target = str(route.get("target", ""))
                if target:
                    endpoints.add(target)
                    if target not in routes:
                        routes.append(target)
            for probe in plan.get("probes", []) or []:
                covered.add(str(probe))
        return SurfaceSnapshot(
            origin=origin,
            routes=tuple(routes),
            endpoints=tuple(sorted(endpoints)),
            covered_probes=frozenset(covered),
        )

    # -- execution -------------------------------------------------------
    def _claim_next(self, objective: Objective) -> tuple[Supervisor, TaskState, ObjectiveTask] | None:
        """Atomically take the next ready task.

        Two workers, or two ticks in the same second, must never execute the same
        task. The candidate is chosen from a supervisor snapshot, but the claim
        is a conditional UPDATE: only the statement that changes the row from
        pending/ready to running wins. The loser re-reads and tries the next
        candidate instead of reporting a phantom success.
        """

        for _ in range(4):
            supervisor = self._supervisor(objective)
            state = supervisor.next_task()
            if state is None:
                return None
            row = self.db.scalar(
                select(ObjectiveTask).where(
                    ObjectiveTask.objective_id == objective.id,
                    ObjectiveTask.key == state.spec.key,
                )
            )
            if row is None:
                continue
            now = datetime.now(UTC)
            result = self.db.execute(
                update(ObjectiveTask)
                .where(
                    ObjectiveTask.id == row.id,
                    ObjectiveTask.status.in_([TaskStatus.pending.value, TaskStatus.ready.value]),
                )
                .values(
                    status=TaskStatus.running.value,
                    attempts=ObjectiveTask.attempts + 1,
                    started_at=func.coalesce(ObjectiveTask.started_at, now),
                    lease_expires_at=now + timedelta(seconds=LEASE_SECONDS),
                )
            )
            self.db.commit()
            if result.rowcount != 1:
                continue
            self.db.refresh(row)
            # Align the in-memory snapshot with what the database now holds.
            state.status = TaskStatus.running
            state.attempts = row.attempts
            return supervisor, state, row
        return None

    def run_step(self, objective: Objective) -> StepResult:
        if objective.status in {
            ObjectiveStatus.completed.value,
            ObjectiveStatus.blocked.value,
            ObjectiveStatus.failed.value,
            ObjectiveStatus.cancelled.value,
        }:
            supervisor = self._supervisor(objective)
            return StepResult(objective.id, "", objective.status, supervisor.verdict(), objective.requests_used)

        deadline = _aware(objective.deadline_at)
        if deadline is not None and datetime.now(UTC) > deadline:
            objective.status = ObjectiveStatus.blocked.value
            objective.verdict = "deadline exceeded before the work could be completed"
            self._event(objective, "objective.blocked", objective.verdict, {"deadline": deadline.isoformat()})
            self.db.commit()
            supervisor = self._supervisor(objective)
            return StepResult(objective.id, "", objective.status, supervisor.verdict(), objective.requests_used)

        claimed = self._claim_next(objective)
        if claimed is None:
            supervisor = self._supervisor(objective)
            if supervisor.next_task() is None:
                return self._finalise(objective, supervisor)
            # Every ready task was claimed by another worker a moment ago.
            return StepResult(objective.id, "", TaskStatus.running.value, supervisor.verdict(), objective.requests_used)
        supervisor, task, task_row = claimed

        if objective.status == ObjectiveStatus.queued.value:
            objective.status = ObjectiveStatus.running.value
            objective.started_at = objective.started_at or datetime.now(UTC)
            self._event(objective, "objective.started", "Workforce began executing the plan.", {})

        remaining = objective.budget_requests - objective.requests_used
        if remaining <= 0 and task_row.kind != TaskKind.report.value:
            task_row.status = TaskStatus.blocked.value
            task_row.error = "objective request budget exhausted"
            self.db.commit()
            return self._finalise(objective, self._supervisor(objective))

        objective.status = ObjectiveStatus.running.value
        self.db.commit()

        worker = workers_for(task.spec)
        request = worker.plan(task.spec)
        observation = self._execute(
            objective,
            tenant_id=objective.tenant_id,
            request=request,
            task_key=task_row.key,
            kind=task.spec.kind,
        )
        outcome = replace(worker.judge(task.spec, observation), route=task_row.route)

        task_row.error = outcome.error
        task_row.risk = observation.risk
        task_row.outcome = outcome.to_dict()
        task_row.lease_expires_at = None
        task_row.completed_at = datetime.now(UTC) if outcome.status in {TaskStatus.done, TaskStatus.skipped} else None
        objective.requests_used += observation.requests

        event = supervisor.record(outcome)
        for new_task in event.added_tasks:
            self.db.add(
                ObjectiveTask(
                    objective_id=objective.id,
                    tenant_id=objective.tenant_id,
                    key=new_task.key,
                    seq=new_task.seq,
                    kind=new_task.kind.value,
                    title=new_task.title,
                    worker=new_task.worker,
                    probe_id=new_task.probe_id,
                    route=new_task.route,
                    depends_on=list(new_task.depends_on),
                    budget_requests=new_task.budget_requests,
                    max_attempts=new_task.max_attempts,
                    safety=new_task.safety.name,
                    verify_kind=new_task.verify_kind,
                    payload=dict(new_task.payload),
                    status=TaskStatus.pending.value,
                )
            )

        task_row.status = task.status.value
        metrics.OBJECTIVE_TASKS.labels(worker=task_row.worker, status=task_row.status).inc()
        self._event(
            objective,
            f"task.{task.status.value}",
            f"{task_row.title} → {task.status.value}",
            {"task": task_row.key, "worker": task_row.worker, "notes": list(event.notes), **outcome.to_dict()},
        )

        if task.spec.kind is TaskKind.recon and outcome.status is TaskStatus.done:
            refreshed = self._snapshot(
                objective.tenant_id,
                parse_target(objective.target_url).origin,
                extra_routes=outcome.endpoints,
            )
            moved = supervisor.retarget_pending(refreshed)
            if moved:
                for state in supervisor.ordered():
                    row = self.db.scalar(
                        select(ObjectiveTask).where(
                            ObjectiveTask.objective_id == objective.id, ObjectiveTask.key == state.spec.key
                        )
                    )
                    if row is not None and row.route != state.spec.route:
                        row.route = state.spec.route
                self._event(
                    objective,
                    "task.retargeted",
                    f"Re-aimed {moved} pending task(s) at the discovered surface.",
                    {"routes": list(refreshed.routes[:8])},
                )

            # Discovery is a plan-changing event: grow the objective with the
            # route-specific work the template implied but could not name.
            self._expand_coverage(objective, supervisor, outcome.endpoints)
            self._expand_adaptive(objective, supervisor, outcome.endpoints, max_new=3)

        elif task.spec.kind in {TaskKind.probe, TaskKind.verify} and outcome.status is TaskStatus.done:
            # Re-plan after every result: the posterior moved, so the best next
            # request may be a different probe on a different route.
            self._expand_adaptive(objective, supervisor, outcome.endpoints, max_new=1)

        self.db.commit()
        verdict = supervisor.verdict()
        if verdict.status is not ObjectiveStatus.running:
            return self._finalise(objective, supervisor)
        return StepResult(objective.id, task_row.key, task_row.status, verdict, objective.requests_used)

    def _execute(
        self, objective: Objective, *, tenant_id: UUID, request, task_key: str, kind: TaskKind
    ) -> TaskObservation:
        if kind is TaskKind.audit:
            return self._audit_evidence(objective)
        if kind is TaskKind.diagnose:
            return self._diagnose(objective, request)

        target = parse_target(request.target_url)
        grant = build_grant(
            target,
            safety=SafetyClass[objective.safety_ceiling],
            approver=f"objective:{objective.key}",
            evidence_sha256=hashlib.sha256(f"{objective.id}|{task_key}".encode()).hexdigest(),
        )
        store = FileEvidenceStore(self.evidence_root / str(objective.id) / task_key)
        executor = HuntExecutor(policy=self.policy, store=store, signer_key=verification_key_from_env())
        seed = int(hashlib.sha256(f"{objective.id}|{task_key}".encode()).hexdigest()[:8], 16) % 1_000_000

        try:
            result = executor.run(
                target,
                grant,
                seed=seed,
                budget_requests=min(request.budget_requests, max(4, objective.budget_requests)),
                requested_probes=list(request.probe_ids),
            )
        except Exception as exc:
            return TaskObservation(error=f"{exc.__class__.__name__}: {exc}", requests=0)

        write_manifest(store.root / "manifest.json", result.manifest)

        findings = tuple(
            FindingLite(
                fingerprint=finding.fingerprint,
                kind=finding.kind,
                severity=finding.severity.value,
                confidence=finding.confidence,
                probe_id=finding.probe_id,
                route=finding.location or request.target_url,
                title=finding.title,
                cwe=finding.cwe,
                remediation=finding.remediation,
            )
            for finding in result.findings
        )
        probes_run = tuple(run.probe_id for run in result.probe_runs if run.status in {"ok", "skipped"})
        skipped = ""
        if result.probe_runs and all(run.status in {"skipped", "budget"} for run in result.probe_runs):
            skipped = "; ".join(run.skipped or run.error for run in result.probe_runs) or "probe skipped"

        error = ""
        if result.halted:
            error = f"halted: {result.halted}"
        elif result.probe_runs and all(run.status == "error" for run in result.probe_runs):
            error = result.probe_runs[0].error or "probe failed"

        confirmed: bool | None = None
        if request.is_verification:
            confirmed = any(
                finding.kind == request.expect_kind
                and (not request.expect_fingerprint or finding.fingerprint == request.expect_fingerprint)
                for finding in findings
            )

        return TaskObservation(
            findings=findings,
            probes_run=probes_run,
            endpoints=tuple(endpoint.url for endpoint in result.endpoints),
            risk=risk.score([(finding.severity, finding.confidence) for finding in findings]),
            requests=int(result.budget.get("used_requests", 0) or 0),
            skipped=skipped,
            error=error,
            confirmed=confirmed,
        )

    def _audit_evidence(self, objective: Objective) -> TaskObservation:
        """Re-verify every manifest this objective produced.

        This is the difference between "we ran things" and "we can prove what we
        ran". Any missing blob, altered leaf or bad signature fails the audit,
        which blocks the objective instead of shipping a report.
        """

        key = verification_key_from_env()
        verified = 0
        empty = 0
        problems: list[str] = []
        for task in self.tasks(objective.id):
            if task.status != TaskStatus.done.value:
                continue
            if task.kind not in {TaskKind.recon.value, TaskKind.probe.value, TaskKind.verify.value}:
                continue
            outcome = task.outcome or {}
            if not outcome.get("probes_run"):
                continue
            manifest_path = self.evidence_root / str(objective.id) / task.key / "manifest.json"
            if not manifest_path.exists():
                problems.append(f"{task.key}: manifest missing")
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                problems.append(f"{task.key}: unreadable manifest ({exc})")
                continue
            if manifest.get("format") != "hcvf-evidence/v1":
                problems.append(f"{task.key}: unknown evidence format")
                continue
            entries = manifest.get("entries", [])
            if not entries:
                # A probe can legitimately capture nothing (skipped, no body).
                # There is no evidence to tamper with, but it is not proof either.
                empty += 1
                continue
            signature = manifest.get("signature") or {}
            signature_value = signature.get("value", "") if isinstance(signature, dict) else str(signature)
            if not verify_manifest(manifest, signature_value, key):
                problems.append(f"{task.key}: signature mismatch")
                continue
            if entries:
                leaves = [bytes.fromhex(str(entry["digest"])) for entry in entries]
                if MerkleTree(leaves).root != manifest.get("root"):
                    problems.append(f"{task.key}: Merkle root does not match its leaves")
                    continue
                store = FileEvidenceStore(self.evidence_root / str(objective.id) / task.key)
                missing = []
                for entry in entries:
                    try:
                        store.get(str(entry["digest"]))
                    except Exception:
                        missing.append(str(entry["digest"])[:12])
                if missing:
                    problems.append(f"{task.key}: {len(missing)} blob(s) missing or corrupt")
                    continue
            verified += 1

        if problems:
            return TaskObservation(error="; ".join(problems[:5]))
        return TaskObservation(
            requests=0,
            notes=(
                f"{verified} evidence manifest(s) verified" + (f", {empty} with no captured evidence" if empty else ""),
            ),
        )

    def _diagnose(self, objective: Objective, request) -> TaskObservation:
        """One HEAD request, classified: why did the previous task fail?"""

        target = parse_target(request.target_url)
        grant = build_grant(
            target,
            safety=SafetyClass[objective.safety_ceiling],
            approver=f"objective:{objective.key}:diagnose",
            evidence_sha256=hashlib.sha256(f"{objective.id}|diagnose".encode()).hexdigest(),
        )
        budget = Budget(max_requests=1, max_bytes=64_000, max_seconds=15.0)
        client = GuardedHttpClient(self.policy, grant, budget)
        try:
            response = client.head(request.target_url, safety=SafetyClass.read_only)
        except EngineError as exc:
            return TaskObservation(
                requests=budget.used_requests,
                notes=(f"transport failure ({exc.__class__.__name__}): {exc}"[:300],),
            )
        except Exception as exc:
            return TaskObservation(
                requests=budget.used_requests,
                notes=(f"unexpected failure ({exc.__class__.__name__}): {exc}"[:300],),
            )

        status = response.status
        if status in {401, 403}:
            note = f"authentication wall (HTTP {status}); the probe needs credentials it does not have"
        elif status == 404:
            note = "route no longer resolves (HTTP 404); discovery may be stale"
        elif status == 429:
            note = "upstream throttled the request (HTTP 429); backoff is warranted"
        elif status >= 500:
            note = f"origin is failing (HTTP {status}); this is a target-side outage"
        elif status >= 300:
            note = f"route redirects (HTTP {status}); the probe followed the authorized hop"
        else:
            note = f"route is reachable (HTTP {status}); the earlier failure may be transient"
        return TaskObservation(requests=budget.used_requests, notes=(note,))

    def _expand_coverage(self, objective: Objective, supervisor: Supervisor, discovered: tuple[str, ...]) -> int:
        """Grow the plan with route-specific work after discovery.

        An objective is a hypothesis about where risk lives; recon is the
        experiment that can move it. When the criterion asks for coverage, the
        supervisor plans probes against the routes that were actually found.
        """

        wanted = objective.template == "coverage" or any(
            str(item.get("kind")) == "min_route_coverage" for item in objective.criteria
        )
        if not wanted or not discovered:
            return 0
        existing = self.tasks(objective.id)
        if any((task.payload or {}).get("dynamic") for task in existing):
            return 0
        known = {(task.route, task.probe_id) for task in existing}

        ceiling = SafetyClass[objective.safety_ceiling]
        allowed = tuple(probe_id for probe_id, probe_class in registry().items() if probe_class.spec.safety <= ceiling)
        remaining_seq = max(task.seq for task in self.tasks(objective.id)) + 1
        budget_left = max(0, objective.budget_requests - objective.requests_used)
        max_tasks = min(12, budget_left // max(4, objective.per_task_budget))
        if max_tasks < 1:
            return 0
        origin = parse_target(objective.target_url).origin
        tasks = dynamic_coverage_tasks(
            origin=origin,
            discovered_routes=discovered,
            allowed_probes=allowed,
            start_seq=remaining_seq,
            per_task_budget=objective.per_task_budget,
            max_routes=6,
            max_tasks=max_tasks,
            recon_key="",
        )
        tasks = tuple(task for task in tasks if (task.route, task.probe_id) not in known)
        added = supervisor.add_tasks(tasks)
        for task in added:
            self.db.add(
                ObjectiveTask(
                    objective_id=objective.id,
                    tenant_id=objective.tenant_id,
                    key=task.key,
                    seq=task.seq,
                    kind=task.kind.value,
                    title=task.title,
                    worker=task.worker,
                    probe_id=task.probe_id,
                    route=task.route,
                    depends_on=list(task.depends_on),
                    budget_requests=task.budget_requests,
                    max_attempts=task.max_attempts,
                    safety=task.safety.name,
                    verify_kind=task.verify_kind,
                    payload=dict(task.payload),
                    status=TaskStatus.pending.value,
                )
            )
        if added:
            self._event(
                objective,
                "plan.expanded",
                f"Coverage expansion added {len(added)} route-specific task(s) after discovery.",
                {"routes": list(discovered[:10]), "tasks": [task.key for task in added]},
            )
        return len(added)

    def _expand_adaptive(
        self, objective: Objective, supervisor: Supervisor, discovered: tuple[str, ...], *, max_new: int
    ) -> int:
        """Add the next best request by expected information gain.

        Called after discovery and after every completed probe, so the plan is a
        sequence of decisions rather than a fixed script. The cap keeps an
        adaptive objective from turning into an unbounded crawler.
        """

        if objective.template != "adaptive":
            return 0
        existing = self.tasks(objective.id)
        adaptive_so_far = [task for task in existing if (task.payload or {}).get("adaptive")]
        if len(adaptive_so_far) >= 10:
            return 0
        budget_left = objective.budget_requests - objective.requests_used
        max_tasks = min(max_new, 10 - len(adaptive_so_far), budget_left // max(4, objective.per_task_budget))
        if max_tasks < 1:
            return 0

        outcomes = [state.outcome for state in supervisor.ordered() if state.outcome is not None]
        observations = tuple(
            (
                normalize_route(outcome.route or objective.target_url),
                tuple(outcome.probes_run),
                tuple(finding.kind for finding in outcome.findings),
                float(outcome.risk),
            )
            for outcome in outcomes
            if outcome.probes_run
        )
        graph = build_surface(
            parse_target(objective.target_url).origin,
            discovered=discovered,
            observations=observations,
        )
        belief = belief_from_outcomes(outcomes)
        ceiling = SafetyClass[objective.safety_ceiling]
        allowed = tuple(probe_id for probe_id, probe_class in registry().items() if probe_class.spec.safety <= ceiling)
        known = {(normalize_route(task.route), task.probe_id) for task in existing if task.probe_id}
        memory = memory_service.boosts(
            self.db,
            tenant_id=objective.tenant_id,
            host=memory_service.host_of(objective.target_url),
            template=objective.template,
        )
        start_seq = max((task.seq for task in existing), default=0) + 1
        recon_key = next((task.key for task in existing if task.kind == TaskKind.recon.value), "")
        tasks = plan_adaptive(
            graph=graph,
            belief=belief,
            allowed_probes=allowed,
            known=known,
            memory=memory,
            per_task_budget=objective.per_task_budget,
            max_tasks=max_tasks,
            start_seq=start_seq,
            safety=ceiling,
            recon_key=recon_key,
        )
        added = supervisor.add_tasks(tasks)
        for task in added:
            self.db.add(
                ObjectiveTask(
                    objective_id=objective.id,
                    tenant_id=objective.tenant_id,
                    key=task.key,
                    seq=task.seq,
                    kind=task.kind.value,
                    title=task.title,
                    worker=task.worker,
                    probe_id=task.probe_id,
                    route=task.route,
                    depends_on=list(task.depends_on),
                    budget_requests=task.budget_requests,
                    max_attempts=task.max_attempts,
                    safety=task.safety.name,
                    verify_kind=task.verify_kind,
                    payload=dict(task.payload),
                    status=TaskStatus.pending.value,
                )
            )
            metrics.OBJECTIVE_INFORMATION_GAIN.observe(float(task.payload.get("expected_information_gain", 0.0) or 0.0))
        if added:
            self._event(
                objective,
                "plan.adaptive",
                f"Adaptive planner added {len(added)} task(s) by expected information gain.",
                {
                    "tasks": [task.to_dict() for task in added],
                    "belief": belief.to_dict(),
                    "surface": {"nodes": len(graph.nodes), "unprobed": len(graph.unprobed_routes())},
                    "memory_boosted": sum(1 for task in added if task.payload.get("adaptive")),
                },
            )
        return len(added)

    def diff(self, objective: Objective) -> dict[str, object]:
        previous = self.db.scalar(
            select(Objective)
            .where(
                Objective.tenant_id == objective.tenant_id,
                Objective.target_url == objective.target_url,
                Objective.id != objective.id,
                Objective.status == ObjectiveStatus.completed.value,
                Objective.created_at < objective.created_at,
            )
            .order_by(Objective.created_at.desc())
            .limit(1)
        )
        return objective_diff(objective, previous)

    def run_to_completion(self, objective: Objective, *, max_tasks: int = 25) -> Verdict:
        verdict = self._supervisor(objective).verdict()
        for _ in range(max_tasks):
            if verdict.status is not ObjectiveStatus.running:
                break
            step = self.run_step(objective)
            verdict = step.verdict
            if step.task_key == "" and verdict.status is ObjectiveStatus.running:
                break
        return verdict

    def _finalise(self, objective: Objective, supervisor: Supervisor) -> StepResult:
        verdict = supervisor.verdict()
        objective.status = verdict.status.value
        objective.verdict = verdict.reason[:512]
        objective.result = supervisor.report()
        if verdict.status is ObjectiveStatus.completed:
            objective.completed_at = datetime.now(UTC)
        self._event(
            objective,
            f"objective.{verdict.status.value}",
            verdict.reason,
            {"verdict": verdict.to_dict()},
        )
        self.db.commit()

        evidence = supervisor.evidence()
        metrics.OBJECTIVES_COMPLETED.labels(template=objective.template, status=verdict.status.value).inc()
        metrics.OBJECTIVE_COVERAGE.observe(evidence.coverage.ratio())
        refuted = len(evidence.refuted)
        if refuted:
            metrics.VERIFICATION_REFUTED.inc(refuted)
        try:
            paths = write_artifacts(objective, self.evidence_root, objective.result)
            self._event(
                objective,
                "objective.artifacts",
                "Signed SARIF and Markdown reports written.",
                {"paths": paths},
            )
            self.db.commit()
        except OSError:
            self.db.rollback()

        try:
            ingested = findings_ingest.record_objective(self.db, objective, supervisor)
            self._event(
                objective,
                "findings.persisted",
                f"Findings ledger updated: {ingested.created} new, {ingested.updated} observed again, "
                f"{ingested.reopened} reopened.",
                ingested.to_dict(),
            )
            self.db.commit()
        except Exception:
            self.db.rollback()

        try:
            assets = asset_service.record_objective(self.db, objective, supervisor)
            if assets:
                self._event(
                    objective,
                    "assets.recorded",
                    f"Inventory updated with {assets} route(s).",
                    {"assets": assets},
                )
                self.db.commit()
        except Exception:
            self.db.rollback()

        try:
            updated = memory_service.record_objective(self.db, objective, supervisor)
            if updated:
                metrics.MEMORY_RECIPES.inc(updated)
                self._event(
                    objective,
                    "memory.updated",
                    f"Recorded {updated} recipe outcome(s) for this host.",
                    {"recipes": updated},
                )
            self.db.commit()
        except Exception:
            self.db.rollback()
        if objective.origin == "autonomy":
            try:
                from app.services.autonomy_service import AutonomyService

                AutonomyService(self.db).record_objective_outcome(objective)
            except Exception:
                self.db.rollback()

        self._publish_outcome(objective, verdict)
        return StepResult(objective.id, "", verdict.status.value, verdict, objective.requests_used)

    def _publish_outcome(self, objective: Objective, verdict: Verdict) -> None:
        """Notify subscribed webhooks. Notification failure never changes a verdict."""

        from app.services import webhooks

        try:
            webhooks.publish(
                self.db,
                tenant_id=objective.tenant_id,
                event=("objective.completed" if verdict.status is ObjectiveStatus.completed else "objective.failed"),
                payload={
                    "objective_id": str(objective.id),
                    "key": objective.key,
                    "title": objective.title,
                    "target": objective.target_url,
                    "status": verdict.status.value,
                    "verdict": verdict.reason,
                    "findings": int((objective.result or {}).get("evidence", {}).get("findings", 0) or 0),
                    "verified": int((objective.result or {}).get("evidence", {}).get("verified", 0) or 0),
                    "requests_used": objective.requests_used,
                    "unmet": list(verdict.unmet),
                },
            )
            self.db.commit()
        except Exception:
            self.db.rollback()

    # -- operator actions -------------------------------------------------
    def cancel(self, objective: Objective, *, actor: str, request_id: str | None = None) -> Objective:
        if objective.status in {ObjectiveStatus.completed.value, ObjectiveStatus.cancelled.value}:
            raise ObjectiveError(f"objective is already {objective.status}")
        objective.status = ObjectiveStatus.cancelled.value
        objective.verdict = f"cancelled by {actor}"[:512]
        for task in self.tasks(objective.id):
            if task.status in {TaskStatus.pending.value, TaskStatus.ready.value, TaskStatus.running.value}:
                task.status = TaskStatus.skipped.value
                task.error = "objective cancelled"
        self._event(objective, "objective.cancelled", objective.verdict, {"actor": actor})
        AuditService(self.db).record(
            tenant_id=objective.tenant_id,
            action="objective.cancel",
            details={"objective": objective.key},
            user_id=actor,
            resource_type="objective",
            resource_id=str(objective.id),
            request_id=request_id,
        )
        self.db.commit()
        self.db.refresh(objective)
        return objective

    def report(self, objective: Objective) -> dict[str, object]:
        supervisor = self._supervisor(objective)
        report = supervisor.report()
        report["stored"] = {
            "status": objective.status,
            "verdict": objective.verdict,
            "requests_used": objective.requests_used,
            "budget_requests": objective.budget_requests,
        }
        report["events"] = [
            {"type": event.type, "message": event.message, "at": event.at.isoformat()}
            for event in self.events(objective.id, limit=50)
        ]
        return report

    def tick(self, *, tenant_id: UUID | None = None, limit: int = 5) -> list[dict[str, object]]:
        query = select(Objective).where(
            Objective.status.in_([ObjectiveStatus.queued.value, ObjectiveStatus.running.value])
        )
        if tenant_id is not None:
            query = query.where(Objective.tenant_id == tenant_id)
        objectives = list(
            self.db.scalars(query.order_by(Objective.priority.desc(), Objective.created_at.asc()).limit(limit))
        )
        results: list[dict[str, object]] = []
        for objective in objectives:
            for _ in range(MAX_TASKS_PER_TICK):
                step = self.run_step(objective)
                results.append(step.to_dict())
                if step.verdict.status is not ObjectiveStatus.running:
                    break
        return results


def _criterion_kind(item: dict):
    from app.engine.workforce.types import CriterionKind

    try:
        return CriterionKind(str(item.get("kind", "")))
    except ValueError:
        return CriterionKind.min_probes
