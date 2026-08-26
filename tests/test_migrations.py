from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect


def test_initial_migration_applies_and_matches_metadata(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "migration-test.db"
    database_url = f"sqlite+pysqlite:///{database_path}"
    environment = {
        **os.environ,
        "DATABASE_URL": database_url,
        "RATE_LIMIT_ENABLED": "false",
    }

    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=project_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [sys.executable, "-m", "alembic", "check"],
        cwd=project_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    inspector = inspect(create_engine(database_url))
    assert {
        "alembic_version",
        "tenants",
        "campaigns",
        "runs",
        "findings",
        "audit_logs",
    } <= set(inspector.get_table_names())
