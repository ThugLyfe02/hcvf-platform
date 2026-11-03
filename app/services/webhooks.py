from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.engine.policy import EgressPolicy
from app.models import Tenant, Webhook
from app.services.outbox import enqueue

SUPPORTED_EVENTS = ("run.completed", "run.failed", "finding.recurring")


def create_webhook(db: Session, *, tenant: Tenant, url: str, events: list[str]) -> tuple[Webhook, str]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("webhook url must be an absolute http(s) URL")
    unknown = [event for event in events if event not in SUPPORTED_EVENTS]
    if unknown:
        raise ValueError(f"unsupported event(s): {', '.join(unknown)}")

    secret = secrets.token_urlsafe(32)
    record = Webhook(
        tenant_id=tenant.id,
        url=url,
        secret=secret,
        events=sorted(set(events)),
        active=True,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record, secret


def signature(secret: str, body: bytes, timestamp: int) -> str:
    payload = f"{timestamp}.".encode() + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def publish(db: Session, *, tenant_id: UUID, event: str, payload: dict) -> int:
    """Queue one delivery per active subscription matching the event."""

    hooks = list(
        db.scalars(
            select(Webhook).where(
                Webhook.tenant_id == tenant_id,
                Webhook.active.is_(True),
            )
        )
    )
    queued = 0
    for hook in hooks:
        if event not in (hook.events or []):
            continue
        enqueue(
            db,
            topic="webhook.deliver",
            payload={
                "webhook_id": str(hook.id),
                "event": event,
                "body": json.loads(json.dumps(payload, default=str)),
            },
        )
        queued += 1
    return queued


def deliver_payload(payload: dict) -> None:
    """Deliver one queued webhook. Raises on failure so the outbox retries."""

    from app.db.session import SessionLocal

    with SessionLocal() as db:
        hook = db.get(Webhook, UUID(str(payload["webhook_id"])))
        if hook is None or not hook.active:
            return

        event = str(payload.get("event", ""))
        body = json.dumps(payload.get("body", {}), sort_keys=True, separators=(",", ":")).encode("utf-8")
        timestamp = int(time.time())
        headers = {
            "Content-Type": "application/json",
            "X-HCVF-Event": event,
            "X-HCVF-Timestamp": str(timestamp),
            "X-HCVF-Signature": f"sha256={signature(hook.secret, body, timestamp)}",
        }

        # The same SSRF policy that guards probes guards outbound webhooks.
        policy = EgressPolicy(
            allow_private=settings.allow_private_targets or settings.environment.lower() == "development"
        )
        parts = urlsplit(hook.url)
        policy.validate(parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80))

        try:
            response = httpx.post(hook.url, content=body, headers=headers, timeout=settings.webhook_timeout_seconds)
            response.raise_for_status()
        except Exception as exc:
            hook.failures += 1
            hook.last_error = f"{exc.__class__.__name__}: {exc}"[:512]
            db.commit()
            raise
        hook.failures = 0
        hook.last_error = ""
        hook.last_delivery_at = datetime.now(UTC)
        db.commit()
