from __future__ import annotations

from alembic.config import Config

from alembic import command
from app.services.bootstrap import provision_configured_tenants


def main() -> None:
    config = Config("alembic.ini")
    command.upgrade(config, "head")
    provision_configured_tenants()


if __name__ == "__main__":
    main()
