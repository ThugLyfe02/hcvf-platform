"""Background agent runtime: queue semantics, depth, and fleet visibility."""

from __future__ import annotations

import os
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
BUILD.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(BUILD / 'test_api.db').as_posix()}")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("EVIDENCE_DIR", (BUILD / "test-evidence").as_posix())
os.environ.setdefault("HCVF_API_KEYS", "dev-hcvf-key")

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.db.session import SessionLocal, engine
from app.engine.workforce.depth import profile
from app.models import Base, Objective, ObjectiveTask, Tenant
from app.services import task_queue
from app.services.bootstrap import provision_configured_tenants
from app.services.objective_service import ObjectiveService
from tests.fixtures.vulnerable_app import running_fixture
from worker import agent_runtime

HEADERS = {settings.api_key_header: "dev-hcvf-key"}


class AgentRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        provision_configured_tenants()
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        from app.main import app

        cls.client = TestClient(app)
        cls.client.__enter__()
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant))
            assert tenant is not None
            tenant.authorized_targets = sorted({*tenant.authorized_targets, cls.target})
            db.commit()

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
            for heartbeat in db.scalars(select(__import__("app.models", fromlist=["AgentHeartbeat"]).AgentHeartbeat)):
                db.delete(heartbeat)
            db.commit()

    def _objective(self, *, depth: str = "standard") -> str:
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant))
            assert tenant is not None
            objective = ObjectiveService(db).create(
                tenant=tenant,
                title=f"runtime {depth}",
                target_url=self.target + "/",
                template="posture",
                budget_requests=120,
                per_task_budget=12,
                criteria_payload=None,
                safety_ceiling="read_only",
                priority=6,
                deadline_minutes=120,
                description="",
                actor="test",
                origin="test",
                depth=depth,
            )
            return str(objective.id)

    def test_claim_respects_worker_and_dependencies(self) -> None:
        objective_id = self._objective()
        with SessionLocal() as db:
            self.assertIsNone(
                task_queue.claim(db, worker="config-worker", agent_id="test-config"),
                "a dependent task must not be claimable before recon",
            )
            first = task_queue.claim(db, worker="recon-worker", agent_id="test-recon")
            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(first.kind, "recon")
        shot = agent_runtime.run_once("recon-worker", agent_id="test-recon-2")
        self.assertFalse(shot.executed, "no recon task left to claim")
        with SessionLocal() as db:
            objective = db.get(Objective, __import__("uuid").UUID(objective_id))
            assert objective is not None
            ObjectiveService(db).run_step(objective)  # completes the claimed recon task? already running
        # The claimed recon task is still running (claimed by test-recon), so
        # config probe remains blocked until it completes.
        with SessionLocal() as db:
            self.assertIsNone(task_queue.claim(db, worker="config-worker", agent_id="test-config-2"))

    def test_runtime_drains_an_objective(self) -> None:
        objective_id = self._objective()
        executed = 0
        for _ in range(60):
            for worker in agent_runtime.DEFAULT_POOLS:
                shot = agent_runtime.run_once(worker, agent_id=f"test-{worker}")
                if shot.executed:
                    executed += 1
            with SessionLocal() as db:
                objective = db.get(Objective, __import__("uuid").UUID(objective_id))
                assert objective is not None
                if objective.status in {"completed", "blocked", "failed"}:
                    break
        self.assertGreater(executed, 3)
        with SessionLocal() as db:
            objective = db.get(Objective, __import__("uuid").UUID(objective_id))
            assert objective is not None
            self.assertEqual(objective.status, "completed", objective.verdict)

    def test_expired_lease_is_reclaimed(self) -> None:
        self._objective()
        with SessionLocal() as db:
            claimed = task_queue.claim(db, worker="recon-worker", agent_id="lease-test")
            assert claimed is not None
            row = db.get(ObjectiveTask, claimed.task_id)
            assert row is not None
            row.lease_expires_at = datetime.now(UTC) - timedelta(minutes=5)
            db.commit()
            recovered = task_queue.reclaim_expired(db)
        self.assertIn(claimed.task_key, recovered)
        with SessionLocal() as db:
            row = db.get(ObjectiveTask, claimed.task_id)
            assert row is not None
            self.assertEqual(row.status, "pending")
            self.assertIsNone(row.lease_expires_at)

    def test_agents_and_queue_endpoint(self) -> None:
        self._objective()
        agent_runtime.run_once("recon-worker", agent_id="api-agent")
        response = self.client.get("/api/v1/admin/agents", headers=HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertIn("queue", body)
        self.assertIn("agents", body)
        self.assertTrue(any(agent["agent_id"] == "api-agent" for agent in body["agents"]))
        queue = self.client.get("/api/v1/admin/queue", headers=HEADERS)
        self.assertEqual(queue.status_code, 200)
        self.assertIn("pending", queue.json())

    def test_depth_profiles_and_api(self) -> None:
        self.assertGreater(profile("deep").adaptive_max_tasks, profile("surface").adaptive_max_tasks)
        self.assertIn("medium", profile("deep").verify_severities)
        self.assertNotIn("medium", profile("standard").verify_severities)
        created = self.client.post(
            "/api/v1/objectives",
            headers=HEADERS,
            json={
                "title": "deep objective",
                "target_url": self.target + "/",
                "template": "adaptive",
                "depth": "deep",
                "budget_requests": 150,
                "per_task_budget": 15,
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["depth"], "deep")
        with SessionLocal() as db:
            objective = db.get(Objective, __import__("uuid").UUID(created.json()["id"]))
            assert objective is not None
            self.assertEqual(objective.depth, "deep")


if __name__ == "__main__":
    unittest.main()
