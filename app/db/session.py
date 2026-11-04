from __future__ import annotations

from collections.abc import Generator
from uuid import UUID

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

_IS_SQLITE = settings.database_url.startswith("sqlite")

engine = create_engine(
    settings.database_url,
    pool_pre_ping=not _IS_SQLITE,
    future=True,
    connect_args=({"check_same_thread": False, "timeout": 30} if _IS_SQLITE else {}),
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, class_=Session)


def bind_tenant(db: Session, tenant_id: UUID | str) -> bool:
    """Bind the tenant to this session for RLS. No-op unless RLS is enabled.

    The value is validated as a UUID, so the SET statement cannot be
    injected. The session info is set even when RLS is off so the context is
    available to callers and tests.
    """

    value = str(UUID(str(tenant_id)))
    db.info["tenant_id"] = value
    if not settings.rls_enabled or db.bind is None or db.bind.dialect.name != "postgresql":
        return False
    db.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": value})
    return True


@event.listens_for(Session, "after_begin")
def _apply_rls_context(session: Session, transaction, connection) -> None:
    """Re-apply the tenant setting on every new transaction.

    SET LOCAL is transaction-scoped: after a commit the next statement starts a
    new transaction, which would see no tenant and (under RLS) zero rows. The
    listener makes binding a property of the session, not of the first query.
    """

    if not settings.rls_enabled:
        return
    tenant_id = session.info.get("tenant_id")
    if not tenant_id or connection.dialect.name != "postgresql":
        return
    connection.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(tenant_id)})


def get_db() -> Generator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.models import Base

    Base.metadata.create_all(bind=engine)
