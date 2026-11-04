#!/usr/bin/env python3
"""Create the non-superuser role used by the RLS integration gate.

RLS is bypassed by superusers and (without FORCE) by table owners, so a test that
runs as the database owner proves nothing. This script creates a dedicated login
role with only DML privileges, which is exactly the role the policies are meant
to constrain.

    python scripts/rls_ci_setup.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import text

from app.db.session import engine

ROLE = "hcvf_rls"
PASSWORD = "rls-password"


def main() -> int:
    if engine.dialect.name != "postgresql":
        print("[FAIL] RLS setup requires PostgreSQL", file=sys.stderr)
        return 1

    with engine.begin() as connection:
        exists = connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :name"), {"name": ROLE}).scalar()
        if not exists:
            connection.execute(text(f"CREATE ROLE {ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE"))
        connection.execute(text(f"ALTER ROLE {ROLE} PASSWORD '{PASSWORD}'"))
        connection.execute(text(f"GRANT CONNECT ON DATABASE {connection.engine.url.database} TO {ROLE}"))
        connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {ROLE}"))
        connection.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {ROLE}"))
        connection.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {ROLE}"))
    print(f"role {ROLE} ready for the RLS gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
