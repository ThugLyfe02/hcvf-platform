from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings


def test_hcvf_api_keys_are_trimmed_deduplicated_and_preferred() -> None:
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        hcvf_api_keys=SecretStr(" first-key , second-key,first-key "),
        bootstrap_api_key=SecretStr("fallback-key"),
    )

    assert settings.configured_api_keys == ("first-key", "second-key")


def test_bootstrap_api_key_remains_a_single_key_fallback() -> None:
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        hcvf_api_keys=None,
        bootstrap_api_key=SecretStr("fallback-key"),
    )

    assert settings.configured_api_keys == ("fallback-key",)


def test_postgres_url_requires_psycopg_three_dialect() -> None:
    with pytest.raises(ValidationError):
        Settings(database_url="postgresql+psycopg2://hcvf:password@localhost:5432/hcvf")


def test_database_bootstrap_provisions_one_tenant_per_configured_key(monkeypatch) -> None:
    from sqlalchemy import delete, select

    from app.core.security import hash_api_key
    from app.db import init_db
    from app.db.session import SessionLocal
    from app.models.tenant import Tenant

    with SessionLocal() as db:
        db.execute(delete(Tenant))
        db.commit()

    configured = Settings(
        environment="test",
        database_url=str(init_db.settings.database_url),
        hcvf_api_keys=SecretStr("first-integration-key,second-integration-key"),
        bootstrap_api_key=None,
        bootstrap_tenant_name="Configured Test Tenant",
    )
    monkeypatch.setattr(init_db, "settings", configured)

    tenants = init_db.bootstrap_tenants()

    assert [tenant.name for tenant in tenants] == [
        "Configured Test Tenant 1",
        "Configured Test Tenant 2",
    ]
    with SessionLocal() as db:
        hashes = set(db.scalars(select(Tenant.api_key_hash)))
    assert hashes == {
        hash_api_key("first-integration-key"),
        hash_api_key("second-integration-key"),
    }
