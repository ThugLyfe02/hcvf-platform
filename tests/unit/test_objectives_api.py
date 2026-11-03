"""End-to-end objective delegation: plan, execute, verify, complete, escalate."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
BUILD.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(BUILD / 'test_api.db').as_posix()}")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("EVIDENCE_DIR", (BUILD / "test-evidence").as_posix())
os.environ.setdefault("HCVF_API_KEYS", "dev-hcvf-key")

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.core.config import settings
from app.db.session import SessionLocal, engine
from app.models import Base, HuntTarget, Objective, ObjectiveTask, Tenant
from app.services.autonomy_service import AutonomyService
from app.services.objective_service import ObjectiveService
from tests.fixtures.vulnerable_app import running_fixture

HEADERS = {settings.api_key_header: "dev-hcvf-key"}


class ObjectiveApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()

        from app.main import app

        cls.client = TestClient(app)
        cls.client.__enter__()

        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant).where(Tenant.name == "configured-tenant-1"))
            assert tenant is not None
            authorized = set(tenant.authorized_targets or [])
            authorized.add(cls.target)
            tenant.authorized_targets = sorted(authorized)
            db.commit()
            cls.tenant_id = tenant.id

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    def setUp(self) -> None:
        with SessionLocal() as db:
            for task in db.scalars(select(ObjectiveTask)):
                db.delete(task)
            for objective in db.scalars(select(Objective)):
                db.delete(objective)
            db.commit()

    # -- helpers ---------------------------------------------------------
    def _delegate(self, *, criteria: list[dict] | None = None, template: str = "posture", budget: int = 120) -> dict:
        response = self.client.post(
            "/api/v1/objectives",
            headers=HEADERS,
            json={
                "title": f"objective-{os.urandom(3).hex()}",
                "target_url": f"{self.target}/",
                "template": template,
                "budget_requests": budget,
                "per_task_budget": 20,
                "criteria": criteria,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def _tasks(self, objective_id: str) -> list[dict]:
        response = self.client.get(f"/api/v1/objectives/{objective_id}/tasks", headers=HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _run(self, objective_id: str, max_tasks: int = 20) -> dict:
        response = self.client.post(
            f"/api/v1/objectives/{objective_id}/run", headers=HEADERS, params={"max_tasks": max_tasks}
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    # -- delegation ------------------------------------------------------
    def test_delegation_creates_a_plan(self) -> None:
        objective = self._delegate()
        self.assertEqual(objective["status"], "queued")
        tasks = self._tasks(objective["id"])
        self.assertGreaterEqual(len(tasks), 7)
        self.assertEqual(tasks[0]["kind"], "recon")
        self.assertEqual(tasks[-1]["kind"], "report")
        self.assertTrue(all(task["status"] == "pending" for task in tasks))

    def test_catalogs_are_exposed(self) -> None:
        workers = self.client.get("/api/v1/workers", headers=HEADERS)
        self.assertEqual(workers.status_code, 200)
        self.assertIn("verifier-worker", {worker["name"] for worker in workers.json()})
        templates = self.client.get("/api/v1/objective-templates", headers=HEADERS)
        self.assertEqual(templates.status_code, 200)
        self.assertIn("posture", {template["name"] for template in templates.json()})

    def test_objective_cannot_escape_tenant_scope(self) -> None:
        response = self.client.post(
            "/api/v1/objectives",
            headers=HEADERS,
            json={
                "title": "outside",
                "target_url": "https://not-owned.example.test/",
                "template": "posture",
            },
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("not authorized", response.text)

    # -- execution -------------------------------------------------------
    def test_objective_runs_to_completion_with_verified_findings(self) -> None:
        # The auth template produces a critical finding (alg=none), which must be
        # independently reproduced before the objective can complete.
        objective = self._delegate(template="auth", budget=200)
        report = self._run(objective["id"], max_tasks=25)
        verdict = report["verdict"]
        self.assertEqual(verdict["status"], "completed", verdict)
        self.assertEqual(verdict["unmet"], [])
        self.assertGreater(verdict["completed_tasks"], 5)

        tasks = self._tasks(objective["id"])
        self.assertTrue(all(task["status"] in {"done", "skipped"} for task in tasks), tasks)
        verify_tasks = [task for task in tasks if task["kind"] == "verify"]
        self.assertTrue(verify_tasks, "serious findings were not independently verified")

        body = self.client.get(f"/api/v1/objectives/{objective['id']}/report", headers=HEADERS).json()
        self.assertEqual(body["stored"]["status"], "completed")
        self.assertGreater(body["evidence"]["findings"], 0)
        self.assertGreater(len(body["criteria"]), 0)
        self.assertTrue(all(item["satisfied"] for item in body["criteria"] if item["required"]))

        events = self.client.get(f"/api/v1/objectives/{objective['id']}/events", headers=HEADERS).json()
        self.assertTrue(any(event["type"] == "objective.completed" for event in events))

    def test_unmet_criterion_blocks_with_a_reason(self) -> None:
        objective = self._delegate(
            criteria=[{"kind": "finding_present", "key": "definitely-not-a-real-finding"}],
            budget=80,
        )
        report = self._run(objective["id"], max_tasks=25)
        verdict = report["verdict"]
        self.assertEqual(verdict["status"], "blocked", verdict)
        self.assertTrue(any("definitely-not-a-real-finding" in item for item in verdict["unmet"]))

    def test_single_step_advances_exactly_one_task(self) -> None:
        objective = self._delegate(budget=60)
        step = self.client.post(f"/api/v1/objectives/{objective['id']}/step", headers=HEADERS)
        self.assertEqual(step.status_code, 200, step.text)
        body = step.json()
        self.assertTrue(body["task"].startswith("t00-recon"))
        self.assertEqual(body["task_status"], "done")
        tasks = self._tasks(objective["id"])
        done = [task for task in tasks if task["status"] == "done"]
        self.assertEqual(len(done), 1)

    def test_cancel_skips_outstanding_tasks(self) -> None:
        objective = self._delegate(budget=60)
        cancelled = self.client.post(f"/api/v1/objectives/{objective['id']}/cancel", headers=HEADERS)
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.assertEqual(cancelled.json()["status"], "cancelled")
        tasks = self._tasks(objective["id"])
        self.assertTrue(all(task["status"] == "skipped" for task in tasks))

    # -- autonomy on objectives -----------------------------------------
    def test_autonomy_delegates_an_objective_in_objective_mode(self) -> None:
        policy = self.client.put(
            "/api/v1/autonomy",
            headers=HEADERS,
            json={
                "enabled": True,
                "target_allowlist": [self.target],
                "mode": "objective",
                "objective_template": "posture",
                "objective_budget_requests": 120,
                "max_objectives_per_day": 4,
                "safety_ceiling": "read_only",
                "approved_by": "unit-test",
                "approval_statement": "Authorized objective delegation for continuous validation.",
            },
        )
        self.assertEqual(policy.status_code, 200, policy.text)
        self.assertEqual(policy.json()["mode"], "objective")

        with SessionLocal() as db:
            db.execute(update(HuntTarget).values(next_eligible_at=None, enabled=True, consecutive_failures=0))
            db.commit()

        tick = self.client.post("/api/v1/autonomy/tick", headers=HEADERS).json()
        self.assertEqual(tick["action"], "delegate", tick)
        self.assertIn("objective", tick["reason"], tick)

        with SessionLocal() as db:
            objective = db.scalar(select(Objective).where(Objective.origin == "autonomy"))
            assert objective is not None
            self.assertEqual(objective.template, "posture")
            self.assertEqual(objective.status, "queued")
            self.assertGreater(len(list(db.scalars(select(ObjectiveTask)))), 3)

    def test_blocked_objective_triggers_an_escalation_cooldown(self) -> None:
        policy = self.client.put(
            "/api/v1/autonomy",
            headers=HEADERS,
            json={
                "enabled": True,
                "target_allowlist": [self.target],
                "mode": "objective",
                "objective_template": "posture",
                "escalation_cooldown_minutes": 120,
                "approved_by": "unit-test",
                "approval_statement": "Authorized objective delegation.",
            },
        )
        self.assertEqual(policy.status_code, 200, policy.text)

        with SessionLocal() as db:
            tenant = db.get(Tenant, self.tenant_id)
            assert tenant is not None
            service = ObjectiveService(db)
            objective = service.create(
                tenant=tenant,
                title="cooldown probe",
                target_url=f"{self.target}/",
                template="posture",
                budget_requests=40,
                per_task_budget=10,
                criteria_payload=[{"kind": "finding_present", "key": "never-happens"}],
                safety_ceiling="read_only",
                priority=5,
                deadline_minutes=60,
                description="",
                actor="unit-test",
                origin="delegation-test",
            )
            service.run_to_completion(objective, max_tasks=15)
            self.assertEqual(objective.status, "blocked")
            policy_row = AutonomyService(db).get_policy(self.tenant_id)
            assert policy_row is not None
            AutonomyService(db).record_objective_outcome(objective)

        with SessionLocal() as db:
            target = db.scalar(select(HuntTarget))
            if target is not None:
                target.next_eligible_at = None
                target.enabled = True
                target.consecutive_failures = 0
                db.commit()

        tick = self.client.post("/api/v1/autonomy/tick", headers=HEADERS).json()
        self.assertEqual(tick["action"], "skip", tick)
        self.assertIn("cooling down", tick["reason"])


class ObjectiveTenantIsolationTests(unittest.TestCase):
    def test_objective_is_not_visible_to_another_tenant(self) -> None:
        Base.metadata.create_all(bind=engine)
        with TestClient(__import__("app.main", fromlist=["app"]).app) as client:
            created = client.post(
                "/api/v1/tenants",
                headers=HEADERS,
                json={"name": "objective-iso", "authorized_targets": []},
            )
            other = {settings.api_key_header: created.json()["api_key"]}
            response = client.get("/api/v1/objectives", headers=other)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), [])
            self.assertEqual(client.get(f"/api/v1/objectives/{UUID(int=1)}", headers=other).status_code, 404)


if __name__ == "__main__":
    unittest.main()
