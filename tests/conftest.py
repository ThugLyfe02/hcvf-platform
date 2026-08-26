from __future__ import annotations

import os
import tempfile
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

STACK_TEST_ENABLED = os.getenv("HCVF_STACK_TEST", "").lower() in {"1", "true", "yes"}
_TEST_DATABASE_FILE: Path | None = None

if STACK_TEST_ENABLED:
    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql+psycopg://hcvf:password@127.0.0.1:5432/hcvf",
    )
    os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6379/15")
    os.environ.setdefault("CELERY_BROKER_URL", os.environ["REDIS_URL"])
    os.environ.setdefault("CELERY_RESULT_BACKEND", os.environ["REDIS_URL"])
    os.environ["CELERY_TASK_ALWAYS_EAGER"] = "false"
else:
    database_file = tempfile.NamedTemporaryFile(
        prefix="hcvf-tests-",
        suffix=".db",
        delete=False,
    )
    database_file.close()
    _TEST_DATABASE_FILE = Path(database_file.name)
    os.environ["DATABASE_URL"] = f"sqlite+pysqlite:///{_TEST_DATABASE_FILE}"
    os.environ["REDIS_URL"] = "redis://127.0.0.1:6399/15"
    os.environ["CELERY_BROKER_URL"] = "memory://"
    os.environ["CELERY_RESULT_BACKEND"] = "cache+memory://"
    os.environ["CELERY_TASK_ALWAYS_EAGER"] = "true"

os.environ["ENVIRONMENT"] = "test"
os.environ["CELERY_TASK_EAGER_PROPAGATES"] = "true"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["JSON_LOGS"] = "false"
os.environ["BOOTSTRAP_TENANT_NAME"] = "Integration Test Tenant"
os.environ["HCVF_API_KEYS"] = "integration-test-api-key"
os.environ.pop("BOOTSTRAP_API_KEY", None)
os.environ["ALLOW_PUBLIC_TARGETS"] = "false"
os.environ["ALLOWED_TARGET_CIDRS"] = "127.0.0.0/8,::1/128"

import app.models  # noqa: E402,F401
from app.core.security import hash_api_key  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models.tenant import Tenant  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

TEST_API_KEY = "integration-test-api-key"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_database_file() -> Generator[None, None, None]:
    yield
    engine.dispose()
    if _TEST_DATABASE_FILE is not None:
        _TEST_DATABASE_FILE.unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def reset_database() -> Generator[None, None, None]:
    if STACK_TEST_ENABLED:
        engine.dispose()
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        alembic_config = Config(str(PROJECT_ROOT / "alembic.ini"))
        alembic_config.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
        alembic_config.attributes["configure_logger"] = False
        command.upgrade(alembic_config, "head")
    else:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        db.add(
            Tenant(
                name="Integration Test Tenant",
                api_key_hash=hash_api_key(TEST_API_KEY),
                active=True,
            )
        )
        db.commit()

    yield

    if not STACK_TEST_ENABLED:
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"X-API-Key": TEST_API_KEY}


class _AuthorizedTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        probe = parse_qs(urlsplit(self.path).query).get("hcvf_probe", [None])[0]
        if probe == "trigger-500":
            body = b"bounded failure"
            status_code = 500
        else:
            body = f"ok:{probe or 'baseline'}".encode("utf-8")
            status_code = 200

        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _: str, *__: object) -> None:
        return


@pytest.fixture
def authorized_target_url() -> Generator[str, None, None]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthorizedTargetHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}/validate"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
