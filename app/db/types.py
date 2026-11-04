"""Dialect-portable column types.

Production is PostgreSQL. Tests and local development use SQLite, which has no
native UUID or JSONB. Rather than fork the models, each type carries a Postgres
implementation and a portable fallback. The Postgres DDL is unchanged, so
migrations and production behaviour are unaffected.
"""

from __future__ import annotations

import uuid

from sqlalchemy import JSON, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.types import CHAR, TypeDecorator


class GUID(TypeDecorator):
    """UUID primary/foreign keys: native ``uuid`` on Postgres, ``char(36)`` elsewhere."""

    impl = CHAR(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PGUUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


#: JSONB on Postgres, plain JSON (TEXT) on SQLite.
JSONDoc = JSONB().with_variant(JSON(), "sqlite")
