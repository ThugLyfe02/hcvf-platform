from __future__ import annotations

import time
from pathlib import Path

import structlog
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

import app.models  # noqa: F401 - registers complete model metadata
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.security import hash_api_key
from app.db.session import SessionLocal, engine
from app.models.tenant import Tenant

logger = structlog.get_logger(__name__)
settings = get_settings()
PROJECT_ROOT = Path(__file__).resolve().parents[2]
_INSECURE_API_KEYS = {
    "",
    "change-me-before-use",
    "replace-with-a-long-random-api-key",
    "dev-hcvf-key",
}


def wait_for_database() -> None:
    last_error: Exception | None = None
    for attempt in range(1, settings.database_connect_retries + 1):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            logger.info("database_available", attempt=attempt)
            return
        except SQLAlchemyError as exc:
            last_error = exc
            logger.warning(
                "database_unavailable",
                attempt=attempt,
                max_attempts=settings.database_connect_retries,
                error_type=exc.__class__.__name__,
            )
            time.sleep(settings.database_connect_retry_seconds)
    raise RuntimeError("Database did not become available before the retry limit.") from last_error


def run_migrations() -> None:
    alembic_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    alembic_config.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    alembic_config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    alembic_config.attributes["configure_logger"] = False
    command.upgrade(alembic_config, "head")
    logger.info("database_migrations_applied")


def bootstrap_tenants() -> list[Tenant]:
    api_keys = settings.configured_api_keys
    if not api_keys:
        raise RuntimeError(
            "At least one API key must be configured with HCVF_API_KEYS or "
            "BOOTSTRAP_API_KEY before database initialization."
        )

    if settings.environment == "production":
        insecure = [key for key in api_keys if key in _INSECURE_API_KEYS or len(key) < 32]
        if insecure:
            raise RuntimeError(
                "Every production HCVF API key must be non-placeholder and at least "
                "32 characters long."
            )

    provisioned: list[Tenant] = []
    with SessionLocal() as db:
        total = len(api_keys)
        for index, api_key in enumerate(api_keys, start=1):
            tenant_name = _configured_tenant_name(index=index, total=total)
            api_key_hash = hash_api_key(api_key)

            tenant_by_hash = db.scalar(
                select(Tenant).where(Tenant.api_key_hash == api_key_hash)
            )
            tenant_by_name = db.scalar(select(Tenant).where(Tenant.name == tenant_name))
            if (
                tenant_by_hash is not None
                and tenant_by_name is not None
                and tenant_by_hash.id != tenant_by_name.id
            ):
                raise RuntimeError(
                    f"Cannot provision {tenant_name!r}: its configured name and API key "
                    "resolve to different existing tenants."
                )

            tenant = tenant_by_hash or tenant_by_name
            if tenant is None:
                tenant = Tenant(
                    name=tenant_name,
                    api_key_hash=api_key_hash,
                    active=True,
                )
                db.add(tenant)
                action = "created"
            else:
                tenant.name = tenant_name
                tenant.api_key_hash = api_key_hash
                tenant.active = True
                action = "updated"

            db.flush()
            provisioned.append(tenant)
            logger.info(
                "bootstrap_tenant_ready",
                tenant_id=str(tenant.id),
                tenant_position=index,
                action=action,
            )

        db.commit()
        for tenant in provisioned:
            db.refresh(tenant)

    logger.info("bootstrap_tenants_provisioned", count=len(provisioned))
    return provisioned


def bootstrap_tenant() -> Tenant:
    """Backward-compatible helper for callers expecting one bootstrap tenant."""

    return bootstrap_tenants()[0]


def initialize_database() -> None:
    wait_for_database()
    run_migrations()
    bootstrap_tenants()


def _configured_tenant_name(*, index: int, total: int) -> str:
    if total == 1:
        return settings.bootstrap_tenant_name
    return f"{settings.bootstrap_tenant_name} {index}"


def main() -> None:
    configure_logging()
    initialize_database()


if __name__ == "__main__":
    main()
