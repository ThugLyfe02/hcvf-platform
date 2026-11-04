from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db.types import GUID


class Base(DeclarativeBase):
    pass


class UUIDPrimaryKeyMixin:
    id: Mapped[UUID] = mapped_column(GUID(), primary_key=True, default=uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


def utcnow() -> datetime:
    return datetime.now(UTC)


def import_models() -> None:
    from app.models.agent import AgentHeartbeat
    from app.models.audit import AuditLog
    from app.models.autonomy import AutonomyDecision, AutonomyPolicy, HuntTarget
    from app.models.campaign import Campaign
    from app.models.evidence import EvidenceBlob, ProbeStat
    from app.models.finding import Finding
    from app.models.governance import FindingSuppression, IdempotencyKey, Webhook
    from app.models.memory import ObjectiveMemory
    from app.models.objective import Objective, ObjectiveEvent, ObjectiveTask
    from app.models.outbox import Outbox
    from app.models.run import Run
    from app.models.tenant import Tenant
    from app.models.triage import Asset, FindingNote

    _ = (
        Tenant,
        Campaign,
        Run,
        Finding,
        AuditLog,
        Outbox,
        EvidenceBlob,
        ProbeStat,
        AutonomyPolicy,
        HuntTarget,
        AutonomyDecision,
        IdempotencyKey,
        FindingSuppression,
        Webhook,
        Objective,
        ObjectiveTask,
        ObjectiveEvent,
        ObjectiveMemory,
        Asset,
        FindingNote,
        AgentHeartbeat,
    )
