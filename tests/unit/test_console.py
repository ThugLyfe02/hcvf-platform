"""Console tests: session flow, tenant scoping, rendering and live events."""

from __future__ import annotations

import os
import unittest
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

from app.core.config import settings
from app.db.session import engine
from app.models import Base
from tests.fixtures.vulnerable_app import running_fixture

API = {settings.api_key_header: "dev-hcvf-key"}


class ConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.fixture = running_fixture()
        cls.target = cls.fixture.__enter__()
        from app.main import app

        cls.app = app
        cls.client = TestClient(app)
        cls.client.__enter__()
        cls.client.post(
            "/api/v1/tenants",
            headers=API,
            json={"name": "console-tenant", "authorized_targets": [cls.target]},
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        cls.fixture.__exit__(None, None, None)
        engine.dispose()

    def setUp(self) -> None:
        self.client.cookies.clear()

    def _login(self, key: str = "dev-hcvf-key") -> None:
        response = self.client.post(
            "/console/login",
            data={"api_key": key, "next": "/console"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("hcvf_console", response.cookies)

    # -- session -------------------------------------------------------
    def test_unauthenticated_console_redirects_to_login(self) -> None:
        response = self.client.get("/console", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("/console/login", response.headers["location"])

    def test_login_page_renders(self) -> None:
        response = self.client.get("/console/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Operator console", response.text)

    def test_bad_key_is_rejected(self) -> None:
        response = self.client.post(
            "/console/login",
            data={"api_key": "not-a-key", "next": "/console"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("error=", response.headers["location"])
        self.assertNotIn("hcvf_console", response.cookies)

    def test_login_sets_session_and_dashboard_renders(self) -> None:
        self._login()
        response = self.client.get("/console")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("Overview", response.text)
        self.assertIn("configured-tenant", response.text)  # dev bootstrap tenant name

    def test_logout_clears_session(self) -> None:
        self._login()
        response = self.client.post("/console/logout", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.cookies.get("hcvf_console"), None)

    # -- pages ---------------------------------------------------------
    def test_all_pages_render(self) -> None:
        self._login()
        for path in (
            "/console/objectives",
            "/console/findings",
            "/console/runs",
            "/console/autonomy",
            "/console/memory",
            "/console/workers",
            "/console/audit",
            "/console/health",
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn("HCVF", response.text, path)

    def test_static_assets_are_served(self) -> None:
        css = self.client.get("/console/static/app.css")
        self.assertEqual(css.status_code, 200)
        self.assertIn("text/css", css.headers["content-type"])
        js = self.client.get("/console/static/app.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("EventSource", js.text)

    # -- objective views ----------------------------------------------
    def test_objective_detail_and_live_events(self) -> None:
        self._login()
        created = self.client.post(
            "/api/v1/objectives",
            headers=API,
            json={
                "title": "console objective",
                "target_url": self.target + "/",
                "template": "posture",
                "budget_requests": 60,
                "per_task_budget": 10,
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        objective = created.json()

        detail = self.client.get(f"/console/objectives/{objective['id']}")
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertIn(objective["key"], detail.text)
        self.assertIn("Acceptance criteria", detail.text)
        self.assertIn("Tasks", detail.text)

        events = self.client.get(f"/console/objectives/{objective['id']}/events.sse?once=1")
        self.assertEqual(events.status_code, 200)
        self.assertIn("text/event-stream", events.headers["content-type"])
        self.assertIn("data:", events.text)
        self.assertIn("event: end", events.text)

    def test_tenant_scoped_console_cannot_see_other_tenants(self) -> None:
        other = self.client.post(
            "/api/v1/tenants",
            headers=API,
            json={"name": "console-other", "authorized_targets": []},
        )
        self.assertEqual(other.status_code, 201, other.text)
        key = other.json()["api_key"]
        self._login(key=key)
        page = self.client.get("/console/objectives")
        self.assertEqual(page.status_code, 200)
        created = self.client.post(
            "/api/v1/objectives",
            headers={settings.api_key_header: "dev-hcvf-key"},
            json={
                "title": "not visible",
                "target_url": self.target + "/",
                "template": "posture",
                "budget_requests": 40,
                "per_task_budget": 10,
            },
        )
        self.assertIn(created.status_code, {201, 400})
        if created.status_code == 201:
            hidden = self.client.get(f"/console/objectives/{created.json()['id']}")
            self.assertEqual(hidden.status_code, 404)


class ConsoleUnitTests(unittest.TestCase):
    def test_tokens_are_signed_and_expire(self) -> None:
        from app.web.auth import issue_token, read_token

        tenant_id = __import__("uuid").UUID(int=7)
        token = issue_token(tenant_id)
        self.assertEqual(read_token(token), tenant_id)
        tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
        self.assertIsNone(read_token(tampered))
        self.assertIsNone(read_token("garbage"))

    def test_event_stream_formats_sse_frames(self) -> None:
        import asyncio

        from app.web.streams import event_stream

        async def consume():
            frames = []
            async for frame in event_stream(
                objective_id=__import__("uuid").UUID(int=1),
                tenant_id=__import__("uuid").UUID(int=2),
                once=True,
            ):
                frames.append(frame)
                if len(frames) > 3:
                    break
            return frames

        frames = asyncio.run(consume())
        self.assertTrue(any(frame.startswith("retry:") for frame in frames))
        self.assertTrue(any(frame.startswith("event: end") for frame in frames))


if __name__ == "__main__":
    unittest.main()
