"""Backwards-compatible pipeline facade.

The validation logic now lives in :mod:`app.services.hunt_service` and the
agentic engine under :mod:`app.engine`. This class remains because it is a
convenient synchronous entry point for tests and scripts.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.models import Run
from app.services.hunt_service import HuntService


class CampaignPipeline:
    def __init__(self, db: Session, runner: object | None = None) -> None:
        self.db = db
        self.runner = runner
        self.service = HuntService(db)

    def execute(self, run_id: UUID) -> Run:
        return self.service.execute_run(run_id)
