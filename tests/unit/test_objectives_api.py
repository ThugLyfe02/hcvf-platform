"""End-to-end objective delegation: plan, execute, verify, complete, escalate."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import unittest
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
from app.models import AutonomyDecision, Base, HuntTarget, Objective, ObjectiveTask, Tenant
from app.services import webhooks
from app.services.autonomy_service import AutonomyService
from app.services.objective_service import ObjectiveService
from app.services.outbox import dispatch_pending
from tests.fixtures.vulnerable_app import running_fixture

HEADERS = {settings.api_key_header: "dev-hcvf-key"}


RECEIVED: list[dict] = []


class _Receiver(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        RECEIVED.append(
            {
                "body": body,
                "signature": self.headers.get("X-HCVF-Signature", ""),
                "event": self.headers.get("X-HCVF-Event", ""),
                "timestamp": self.headers.get("X-HCVF-Timestamp", ""),
            }
        )
        self.send_response(204)
        self.end_headers()


class ObjectiveApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        cls.receiver = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
        threading.Thread(target=cls.receiver.serve_forever, daemon=True).start()
        cls.receiver_url = f"http://127.0.0.1:{cls.receiver.server_address[1]}/hook"

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
        cls.receiver.shutdown()
        cls.receiver.server_close()
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    def setUp(self) -> None:
        with SessionLocal() as db:
            for task in db.scalars(select(ObjectiveTask)):
                db.delete(task)
            for objective in db.scalars(select(Objective)):
                db.delete(objective)
            for decision in db.scalars(select(AutonomyDecision)):
                db.delete(decision)
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

    def test_completion_emits_a_signed_objective_webhook(self) -> None:
        RECEIVED.clear()
        hook = self.client.post(
            "/api/v1/webhooks",
            headers=HEADERS,
            json={"url": self.receiver_url, "events": ["objective.completed"]},
        )
        self.assertEqual(hook.status_code, 201, hook.text)
        secret = hook.json()["secret"]

        objective = self._delegate(budget=120)
        self._run(objective["id"], max_tasks=20)

        with SessionLocal() as db:
            delivered = dispatch_pending(
                db,
                lambda topic, payload: webhooks.deliver_payload(payload) if topic == "webhook.deliver" else None,
                limit=50,
            )
        self.assertGreaterEqual(delivered, 1)
        self.assertTrue(RECEIVED, "objective completion did not reach the webhook")
        message = RECEIVED[-1]
        self.assertEqual(message["event"], "objective.completed")
        expected = hmac.new(
            secret.encode(),
            f"{message['timestamp']}.".encode() + message["body"],
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(message["signature"], f"sha256={expected}")
        payload = json.loads(message["body"])
        self.assertEqual(payload["key"], objective["key"])
        self.assertIn("verdict", payload)

    # -- coverage and evidence integrity --------------------------------
    def test_coverage_objective_expands_and_reaches_its_coverage_target(self) -> None:
        objective = self._delegate(
            template="coverage",
            budget=240,
            criteria=[
                {"kind": "min_endpoints", "value": 2},
                {"kind": "min_route_coverage", "value": 0.4},
            ],
        )
        report = self._run(objective["id"], max_tasks=40)
        verdict = report["verdict"]
        self.assertEqual(verdict["status"], "completed", verdict)
        coverage = report["report"]["evidence"]["coverage"]
        self.assertGreaterEqual(coverage["ratio"], 0.4, coverage)
        self.assertGreater(coverage["discovered"], 1)

        events = self.client.get(f"/api/v1/objectives/{objective['id']}/events", headers=HEADERS).json()
        self.assertTrue(any(event["type"] == "plan.expanded" for event in events), events)

        view = self.client.get(f"/api/v1/objectives/{objective['id']}/coverage", headers=HEADERS)
        self.assertEqual(view.status_code, 200, view.text)
        self.assertIn("ratio", view.json()["coverage"])

    def test_tampered_evidence_blocks_the_objective(self) -> None:
        created = self._delegate(template="auth", budget=200)
        with SessionLocal() as db:
            objective = db.get(Objective, UUID(created["id"]))
            assert objective is not None
            service = ObjectiveService(db)
            audit_ready = False
            for _ in range(30):
                tasks = service.tasks(objective.id)
                audit = next(task for task in tasks if task.kind == "audit")
                if audit.status == "pending" and all(
                    task.status == "done" for task in tasks if task.kind in {"recon", "probe", "verify"}
                ):
                    audit_ready = True
                    break
                step = service.run_step(objective)
                if step.verdict.status.value != "running":
                    break
            self.assertTrue(audit_ready, "audit never became ready")

            probe_task = next(
                task
                for task in service.tasks(objective.id)
                if task.kind == "probe" and (task.outcome or {}).get("probes_run")
            )
            manifest = service.evidence_root / str(objective.id) / probe_task.key / "manifest.json"
            self.assertTrue(manifest.exists(), manifest)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertTrue(data["entries"], "tamper target has no entries")
            data["entries"][0]["digest"] = "00" * 32
            manifest.write_text(json.dumps(data), encoding="utf-8")

            step = service.run_step(objective)
            self.assertIn(step.task_status, {"failed", "blocked"})
            self.assertEqual(step.verdict.status.value, "blocked")
            self.assertIn("evidence audit failed", step.verdict.reason)

    # -- autonomy rules v2 ----------------------------------------------
    def _objective_policy(self, **overrides) -> dict:
        payload = {
            "enabled": True,
            "target_allowlist": [self.target],
            "mode": "objective",
            "objective_template": "posture",
            "template_auto": False,
            "max_objectives_per_day": 8,
            "escalation_cooldown_minutes": 15,
            "narrow_on_retry": True,
            "approved_by": "unit-test",
            "approval_statement": "Authorized objective delegation for continuous validation.",
        }
        payload.update(overrides)
        response = self.client.put("/api/v1/autonomy", headers=HEADERS, json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_fleet_limit_stops_delegation(self) -> None:
        self._objective_policy(max_active_objectives=1)
        with SessionLocal() as db:
            db.execute(update(HuntTarget).values(next_eligible_at=None, enabled=True, consecutive_failures=0))
            db.commit()
        first = self.client.post("/api/v1/autonomy/tick", headers=HEADERS).json()
        self.assertEqual(first["action"], "delegate", first)
        second = self.client.post("/api/v1/autonomy/tick", headers=HEADERS).json()
        self.assertEqual(second["action"], "skip", second)
        self.assertIn("fleet is full", second["reason"])

    def test_blocked_objective_is_retried_narrowly(self) -> None:
        self._objective_policy(max_objectives_per_day=8, narrow_on_retry=True)
        with SessionLocal() as db:
            db.execute(update(HuntTarget).values(next_eligible_at=None, enabled=True, consecutive_failures=0))
            db.commit()

            tenant = db.get(Tenant, self.tenant_id)
            assert tenant is not None
            service = ObjectiveService(db)
            blocked = service.create(
                tenant=tenant,
                title="narrow source",
                target_url=f"{self.target}/",
                template="posture",
                budget_requests=60,
                per_task_budget=10,
                criteria_payload=[
                    {"kind": "finding_present", "key": "definitely-not-a-real-finding"},
                    {"kind": "min_probes", "value": 2},
                ],
                safety_ceiling="read_only",
                priority=6,
                deadline_minutes=120,
                description="",
                actor="unit-test",
                origin="autonomy",
            )
            verdict = service.run_to_completion(blocked, max_tasks=25)
            self.assertEqual(verdict.status.value, "blocked", verdict)
            self.assertEqual(blocked.status, "blocked")

            policy = AutonomyService(db).get_policy(self.tenant_id)
            assert policy is not None
            db.execute(update(HuntTarget).values(next_eligible_at=None, enabled=True, consecutive_failures=0))
            db.commit()
            report = AutonomyService(db).tick_policy(policy, now=datetime.now(UTC) + timedelta(hours=4), force=True)

        self.assertEqual(report.action, "delegate-narrow", report)
        self.assertIn("narrow retry", report.reason)

        with SessionLocal() as db:
            narrow = db.scalars(
                select(Objective).where(Objective.origin == "autonomy").order_by(Objective.created_at.desc())
            ).first()
            assert narrow is not None
            kinds = {str(item.get("kind")) for item in narrow.criteria}
            # Only the criterion that actually failed is retried; the one that
            # passed is not requested again.
            self.assertEqual(kinds, {"finding_present"})
            self.assertIn("retry", narrow.title)

    # -- adaptive planning, artifacts, memory ---------------------------
    def test_adaptive_objective_replans_by_information_gain(self) -> None:
        objective = self._delegate(template="adaptive", budget=200)
        report = self._run(objective["id"], max_tasks=40)
        self.assertEqual(report["verdict"]["status"], "completed", report["verdict"])

        events = self.client.get(f"/api/v1/objectives/{objective['id']}/events", headers=HEADERS).json()
        adaptive = [event for event in events if event["type"] == "plan.adaptive"]
        self.assertTrue(adaptive, "adaptive planner never ran")
        payload = adaptive[0]["payload"]
        self.assertIn("belief", payload)
        self.assertIn("posterior", payload["belief"])
        self.assertGreater(payload["surface"]["nodes"], 0)

        tasks = self._tasks(objective["id"])
        scored = [task for task in tasks if "-eig-" in task["key"]]
        self.assertTrue(scored, "no expected-information-gain tasks were planned")
        self.assertTrue(all(task["kind"] == "probe" for task in scored))

    def test_objective_artifacts_are_signed_and_diffable(self) -> None:
        first = self._delegate(template="posture", budget=120)
        self._run(first["id"], max_tasks=25)

        sarif = self.client.get(f"/api/v1/objectives/{first['id']}/report.sarif", headers=HEADERS)
        self.assertEqual(sarif.status_code, 200, sarif.text)
        self.assertTrue(sarif.headers["x-hcvf-signature"].startswith("sha256="))
        self.assertEqual(len(sarif.headers["x-hcvf-sha256"]), 64)
        body = sarif.json()
        self.assertEqual(body["version"], "2.1.0")
        run = body["runs"][0]
        self.assertEqual(run["properties"]["objective"], first["key"])
        self.assertIsInstance(run["results"], list)

        markdown = self.client.get(f"/api/v1/objectives/{first['id']}/report.md", headers=HEADERS)
        self.assertEqual(markdown.status_code, 200)
        self.assertIn("# Objective report", markdown.text)
        self.assertIn("Acceptance criteria", markdown.text)
        self.assertTrue(markdown.headers["x-hcvf-signature"].startswith("sha256="))

        second = self._delegate(template="posture", budget=120)
        self._run(second["id"], max_tasks=25)
        diff = self.client.get(f"/api/v1/objectives/{second['id']}/diff", headers=HEADERS)
        self.assertEqual(diff.status_code, 200, diff.text)
        payload = diff.json()
        for key in ("new", "fixed", "recurring", "current_total", "previous_total"):
            self.assertIn(key, payload)
        self.assertEqual(payload["previous"], first["key"])

        memory = self.client.get("/api/v1/memory", headers=HEADERS)
        self.assertEqual(memory.status_code, 200)
        rows = memory.json()
        self.assertTrue(rows, "no recipes were learned")
        self.assertIn("score", rows[0])
        self.assertIn("probe", rows[0])

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
                "template_auto": False,
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
                "template_auto": False,
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
