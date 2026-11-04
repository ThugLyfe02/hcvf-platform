"""PostgreSQL row-level security helpers.

Isolation is currently enforced in the query layer plus denormalized tenant
columns. RLS is the defence-in-depth layer: with it enabled, even a query that
forgets ``WHERE tenant_id`` returns nothing across tenants.

The application sets ``app.tenant_id`` with ``SET LOCAL`` inside the request
transaction; policies compare against ``current_setting('app.tenant_id', true)``.
SQLite has no RLS, so the helper is a no-op there and tests stay portable.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

SETTING = "app.tenant_id"

RLS_TABLES = (
    "campaigns",
    "runs",
    "findings",
    "finding_notes",
    "audit_logs",
    "autonomy_policies",
    "autonomy_decisions",
    "hunt_targets",
    "webhooks",
    "idempotency_keys",
    "finding_suppressions",
    "probe_stats",
    "objectives",
    "objective_tasks",
    "objective_events",
    "objective_memory",
    "assets",
)


def tenant_scoped_tables() -> list[str]:
    """Every table carrying a tenant_id column, derived from the metadata.

    Deriving beats a hand-maintained list: a new tenant-scoped table cannot
    silently ship without a policy.
    """

    from app.models import Base

    tables = [table.name for table in Base.metadata.sorted_tables if "tenant_id" in table.c]
    return sorted(tables)


def rls_session_sql(tenant_id: str | uuid.UUID) -> str:
    """Build the SET LOCAL statement. The UUID is validated, so injection is impossible."""

    value = str(uuid.UUID(str(tenant_id)))
    return f"SET LOCAL {SETTING} = '{value}'"


def apply_tenant_context(db: Session, tenant_id: str | uuid.UUID) -> bool:
    """Bind the tenant to the current transaction. Returns True when applied."""

    if db.bind is None or db.bind.dialect.name != "postgresql":
        return False
    db.execute(text(rls_session_sql(tenant_id)))
    return True


def reset_tenant_context(db: Session) -> bool:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return False
    db.execute(text(f"RESET {SETTING}"))
    return True


def policy_sql(table: str, *, owner_column: str = "tenant_id", policy_prefix: str = "hcvf") -> list[str]:
    """DDL for one table. Kept in code so it can be reviewed and asserted on."""

    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS {policy_prefix}_tenant_isolation ON {table}",
        (
            f"CREATE POLICY {policy_prefix}_tenant_isolation ON {table} "
            f"USING ({owner_column} = current_setting('{SETTING}', true)::uuid) "
            f"WITH CHECK ({owner_column} = current_setting('{SETTING}', true)::uuid)"
        ),
    ]
