"""Pure workforce tests: decomposition, criteria, supervision, worker judgement."""

from __future__ import annotations

import unittest

from app.engine.types import SafetyClass
from app.engine.workforce.criteria import (
    CriterionError,
    EvidenceBundle,
    evaluate,
    needs_verification,
    parse_criteria,
    unmet,
)
from app.engine.workforce.decompose import (
    TEMPLATE_CRITERIA,
    DecompositionError,
    choose_route,
    plan_objective,
    retarget,
    verification_task,
)
from app.engine.workforce.supervisor import Supervisor
from app.engine.workforce.types import (
    Criterion,
    CriterionKind,
    FindingLite,
    ObjectiveSpec,
    ObjectiveStatus,
    SurfaceSnapshot,
    TaskKind,
    TaskOutcome,
    TaskStatus,
)
from app.engine.workforce.workers import (
    ReconWorker,
    TaskObservation,
    VerifierWorker,
    worker_catalog,
    workers_for,
)

SNAPSHOT = SurfaceSnapshot(
    origin="https://app.example.test",
    routes=("https://app.example.test/", "https://app.example.test/login", "https://app.example.test/api/v1/users"),
    endpoints=("https://app.example.test/", "https://app.example.test/login"),
    covered_probes=frozenset({"security-headers"}),
)


def spec(**overrides) -> ObjectiveSpec:
    base = {
        "key": "posture-test",
        "title": "Posture",
        "target": "https://app.example.test",
        "template": "posture",
        "safety": SafetyClass.read_only,
        "budget_requests": 120,
        "per_task_budget": 20,
        "criteria": TEMPLATE_CRITERIA["posture"],
    }
    base.update(overrides)
    return ObjectiveSpec(**base)


class TestDecomposition(unittest.TestCase):
    def test_posture_plan_has_recon_probes_and_report(self) -> None:
        plan = plan_objective(spec(), SNAPSHOT)
        kinds = [task.kind for task in plan.tasks]
        self.assertEqual(kinds[0], TaskKind.recon)
        self.assertEqual(kinds[-1], TaskKind.report)
        probes = [task for task in plan.tasks if task.kind is TaskKind.probe]
        self.assertGreaterEqual(len(probes), 4)
        recon_key = plan.tasks[0].key
        for probe in probes:
            self.assertEqual(probe.depends_on, (recon_key,))
        for task in plan.tasks:
            self.assertGreaterEqual(task.budget_requests, 0)
            self.assertTrue(task.key)

    def test_report_depends_on_everything_else(self) -> None:
        plan = plan_objective(spec(), SNAPSHOT)
        report = plan.tasks[-1]
        self.assertEqual(len(report.depends_on), len(plan.tasks) - 1)

    def test_routes_follow_doctrine(self) -> None:
        self.assertIn("login", choose_route(SNAPSHOT, "jwt-posture"))
        self.assertIn("api", choose_route(SNAPSHOT, "cors-policy"))

    def test_safety_ceiling_filters_probes(self) -> None:
        with self.assertRaises(DecompositionError):
            plan_objective(
                spec(
                    template="custom",
                    criteria=(Criterion(CriterionKind.finding_present, "graphql-introspection-enabled"),),
                ),
                SNAPSHOT,
            )

    def test_budget_floor_is_enforced(self) -> None:
        with self.assertRaises(DecompositionError):
            plan_objective(spec(budget_requests=4), SNAPSHOT)

    def test_retarget_moves_pending_probe_tasks(self) -> None:
        # An auth objective planned before discovery aims at the entry point;
        # after recon finds /login, the JWT task must re-aim there.
        plan = plan_objective(
            spec(template="auth", criteria=TEMPLATE_CRITERIA["auth"]),
            SurfaceSnapshot(origin="https://app.example.test"),
        )
        probe = next(task for task in plan.tasks if task.probe_id == "jwt-posture")
        self.assertEqual(probe.route, "https://app.example.test/")
        moved = retarget(plan.tasks, SNAPSHOT)
        updated = next(task for task in moved if task.key == probe.key)
        self.assertIn("login", updated.route)
        self.assertIn(" at ", updated.title)

    def test_verification_task_is_surgical(self) -> None:
        parent = next(task for task in plan_objective(spec(), SNAPSHOT).tasks if task.kind is TaskKind.probe)
        verify = verification_task(parent=parent, fingerprint="abc", finding_kind="missing-hsts", seq=99)
        self.assertEqual(verify.kind, TaskKind.verify)
        self.assertEqual(verify.route, parent.route)
        self.assertEqual(verify.probe_id, parent.probe_id)
        self.assertLessEqual(verify.budget_requests, parent.budget_requests)
        self.assertEqual(verify.payload["fingerprint"], "abc")

    def test_worker_catalog_covers_every_kind(self) -> None:
        catalog = worker_catalog()
        self.assertGreaterEqual(len(catalog), 6)
        names = {item["name"] for item in catalog}
        self.assertIn("verifier-worker", names)
        self.assertIn("report-worker", names)


class TestCriteria(unittest.TestCase):
    def _evidence(self) -> EvidenceBundle:
        bundle = EvidenceBundle()
        bundle.add_findings(
            (
                FindingLite("fp1", "missing-hsts", "low", 0.97, "security-headers", "https://x/"),
                FindingLite("fp2", "jwt-alg-none", "critical", 0.97, "jwt-posture", "https://x/login"),
            )
        )
        bundle.probes_run.update({"security-headers", "jwt-posture"})
        bundle.endpoints.update({"https://x/", "https://x/login"})
        bundle.risk = 42.0
        bundle.verified.add("fp2")
        return bundle

    def test_each_criterion_kind(self) -> None:
        evidence = self._evidence()
        cases = [
            (Criterion(CriterionKind.finding_present, "missing-hsts"), True),
            (Criterion(CriterionKind.finding_present, "nope"), False),
            (Criterion(CriterionKind.finding_absent, "nope"), True),
            (Criterion(CriterionKind.finding_absent, "missing-hsts"), False),
            (Criterion(CriterionKind.min_probes, 2), True),
            (Criterion(CriterionKind.min_probes, 5), False),
            (Criterion(CriterionKind.min_endpoints, 2), True),
            (Criterion(CriterionKind.risk_below, 50), True),
            (Criterion(CriterionKind.risk_below, 10), False),
            (Criterion(CriterionKind.risk_above, 40), True),
            (Criterion(CriterionKind.min_verified, 1), True),
            (Criterion(CriterionKind.min_verified, 2), False),
        ]
        for criterion, expected in cases:
            result = evaluate((criterion,), evidence)[0]
            self.assertEqual(result.satisfied, expected, criterion.description)

    def test_unmet_lists_required_failures_only(self) -> None:
        results = [
            evaluate((Criterion(CriterionKind.min_probes, 9),), self._evidence())[0],
            evaluate((Criterion(CriterionKind.finding_present, "nope", required=False),), self._evidence())[0],
        ]
        self.assertEqual(len(unmet(results)), 1)

    def test_parse_criteria_validates(self) -> None:
        with self.assertRaises(CriterionError):
            parse_criteria([{"kind": "nonsense"}], template_criteria=())
        with self.assertRaises(CriterionError):
            parse_criteria([{"kind": "finding_present"}], template_criteria=())
        parsed = parse_criteria(
            [{"kind": "min_probes", "value": 3}, {"kind": "finding_present", "key": "missing-hsts"}],
            template_criteria=(),
        )
        self.assertEqual(parsed[0].value, 3)
        self.assertEqual(parsed[1].key, "missing-hsts")

    def test_needs_verification_targets_serious_confidence(self) -> None:
        findings = (
            FindingLite("a", "x", "critical", 0.9, "p", "r"),
            FindingLite("b", "y", "low", 0.9, "p", "r"),
            FindingLite("c", "z", "high", 0.2, "p", "r"),
        )
        self.assertEqual([finding.fingerprint for finding in needs_verification(findings)], ["a"])


class TestSupervisor(unittest.TestCase):
    def _supervisor(self) -> Supervisor:
        return Supervisor.from_plan(plan_objective(spec(), SNAPSHOT))

    def _done(self, task_key: str, findings=()) -> TaskOutcome:
        return TaskOutcome(task_key=task_key, status=TaskStatus.done, findings=findings)

    def test_ready_respects_dependencies(self) -> None:
        supervisor = self._supervisor()
        first = supervisor.next_task()
        assert first is not None
        self.assertEqual(first.spec.kind, TaskKind.recon)
        self.assertEqual(len(supervisor.ready()), 1)

    def test_failure_retries_then_blocks(self) -> None:
        supervisor = self._supervisor()
        recon = supervisor.next_task()
        assert recon is not None
        supervisor.mark_running(recon.spec.key)
        supervisor.record(TaskOutcome(recon.spec.key, TaskStatus.failed, error="timeout"))
        self.assertEqual(recon.status, TaskStatus.pending)
        supervisor.mark_running(recon.spec.key)
        supervisor.record(TaskOutcome(recon.spec.key, TaskStatus.failed, error="timeout"))
        self.assertEqual(recon.status, TaskStatus.blocked)
        verdict = supervisor.verdict()
        self.assertEqual(verdict.status, ObjectiveStatus.blocked)
        self.assertTrue(verdict.reason)

    def test_critical_finding_queues_verification(self) -> None:
        supervisor = self._supervisor()
        recon = supervisor.next_task()
        assert recon is not None
        supervisor.mark_running(recon.spec.key)
        supervisor.record(
            self._done(
                recon.spec.key, findings=(FindingLite("ep1", "vcs-metadata", "high", 0.95, "exposed-config", "u"),)
            )
        )
        probe = supervisor.next_task()
        assert probe is not None
        supervisor.mark_running(probe.spec.key)
        event = supervisor.record(
            self._done(
                probe.spec.key, findings=(FindingLite("fp9", "env-file", "critical", 0.99, "exposed-config", "u"),)
            )
        )
        self.assertTrue(event.added_tasks)
        verify = event.added_tasks[0]
        self.assertEqual(verify.kind, TaskKind.verify)
        self.assertEqual(verify.payload["fingerprint"], "fp9")

    def test_verdict_completes_only_when_criteria_met(self) -> None:
        supervisor = self._supervisor()
        while True:
            task = supervisor.next_task()
            if task is None:
                break
            supervisor.mark_running(task.spec.key)
            supervisor.record(
                TaskOutcome(
                    task.spec.key,
                    TaskStatus.done,
                    probes_run=(task.spec.probe_id or "recon",),
                    endpoints=("https://app.example.test/",),
                    risk=10.0,
                )
            )
        verdict = supervisor.verdict()
        self.assertEqual(verdict.status, ObjectiveStatus.completed, verdict.reason)
        self.assertEqual(verdict.unmet, ())

    def test_blocked_when_finding_criterion_unmet(self) -> None:
        supervisor = Supervisor.from_plan(
            plan_objective(
                spec(criteria=(Criterion(CriterionKind.finding_present, "missing-hsts"),)),
                SNAPSHOT,
            )
        )
        while True:
            task = supervisor.next_task()
            if task is None:
                break
            supervisor.mark_running(task.spec.key)
            supervisor.record(TaskOutcome(task.spec.key, TaskStatus.done, probes_run=("x",), endpoints=("e",)))
        verdict = supervisor.verdict()
        self.assertEqual(verdict.status, ObjectiveStatus.blocked)
        self.assertTrue(verdict.unmet)

    def test_report_contains_evidence_and_tasks(self) -> None:
        supervisor = self._supervisor()
        report = supervisor.report()
        self.assertIn("objective", report)
        self.assertIn("criteria", report)
        self.assertIn("tasks", report)
        self.assertEqual(report["evidence"]["findings"], 0)


class TestWorkers(unittest.TestCase):
    def test_recon_without_endpoints_fails(self) -> None:
        worker = ReconWorker()
        task = plan_objective(spec(), SNAPSHOT).tasks[0]
        outcome = worker.judge(task, TaskObservation(probes_run=("surface-crawl",)))
        self.assertEqual(outcome.status, TaskStatus.failed)
        self.assertIn("no endpoints", outcome.error)

    def test_recon_with_endpoints_is_done(self) -> None:
        worker = ReconWorker()
        task = plan_objective(spec(), SNAPSHOT).tasks[0]
        outcome = worker.judge(task, TaskObservation(endpoints=("https://x/",), probes_run=("surface-crawl",)))
        self.assertEqual(outcome.status, TaskStatus.done)

    def test_verifier_refutes_when_not_reproduced(self) -> None:
        parent = plan_objective(spec(), SNAPSHOT).tasks[1]
        verify = verification_task(parent=parent, fingerprint="fp", finding_kind="missing-hsts", seq=99)
        outcome = VerifierWorker().judge(verify, TaskObservation(confirmed=False))
        self.assertEqual(outcome.status, TaskStatus.done)
        self.assertFalse(outcome.confirmed)
        self.assertIn("refuted", " ".join(outcome.notes))

    def test_workers_for_respects_task_kind(self) -> None:
        plan = plan_objective(spec(), SNAPSHOT)
        self.assertEqual(workers_for(plan.tasks[0]).name, "recon-worker")
        verify = verification_task(parent=plan.tasks[1], fingerprint="x", finding_kind="y", seq=99)
        self.assertEqual(workers_for(verify).name, "verifier-worker")

    def test_workers_for_rejects_a_mismatched_worker(self) -> None:
        from dataclasses import replace

        task = replace(plan_objective(spec(), SNAPSHOT).tasks[1], worker="recon-worker", kind=TaskKind.probe)
        with self.assertRaises(ValueError):
            workers_for(task)


if __name__ == "__main__":
    unittest.main()
