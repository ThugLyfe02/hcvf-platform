#!/usr/bin/env python3
"""Enable PostgreSQL row-level security for tenant-scoped tables.

Policies are created as normal DDL, but RLS is only *enabled* when an operator
runs this deliberately: enabling it without setting ``app.tenant_id`` on every
connection would make the application return empty result sets.

    python scripts/enable_rls.py --dry-run
    python scripts/enable_rls.py --apply
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import text

from app.core.rls import policy_sql, tenant_scoped_tables
from app.db.session import engine


def main() -> int:
    parser = argparse.ArgumentParser(description="Enable per-tenant row-level security")
    parser.add_argument("--apply", action="store_true", help="execute the DDL (default is dry run)")
    parser.add_argument("--table", action="append", default=None, help="limit to specific tables")
    args = parser.parse_args()

    tables = args.table or tenant_scoped_tables()
    statements: list[str] = []
    for table in tables:
        statements.extend(policy_sql(table))

    if not args.apply:
        print("\n".join(f"{statement};" for statement in statements))
        return 0

    if engine.dialect.name != "postgresql":
        print("[FAIL] RLS requires PostgreSQL", file=sys.stderr)
        return 1

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
    print(f"RLS enabled on {len(tables)} tables. Set app.tenant_id per transaction.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
