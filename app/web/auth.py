"""Console session handling: an API key exchanged for a short-lived signed cookie.

The console is a read-mostly operator surface. It does not invent a second
authentication system: an operator pastes an API key, the key is resolved
against the same tenant table the API uses, and the browser receives an
HMAC-signed cookie containing only the tenant id and an expiry. The raw key is
never stored client-side.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_api_key
from app.db.session import bind_tenant, get_db
from app.models import Tenant

COOKIE_NAME = "hcvf_console"
SESSION_SECONDS = 8 * 3600


def _secret() -> bytes:
    configured = getattr(settings, "console_secret", "") or ""
    if configured:
        return configured.encode("utf-8")
    # Development fallback: derive a stable secret from the configured keys so a
    # restart does not invalidate every session. Production must set
    # HCVF_CONSOLE_SECRET.
    material = "hcvf-console::" + "|".join(sorted(settings.api_keys))
    return hashlib.sha256(material.encode("utf-8")).digest()


def issue_token(tenant_id: UUID) -> str:
    payload = {"tid": str(tenant_id), "exp": int(time.time()) + SESSION_SECONDS}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def read_token(token: str) -> UUID | None:
    try:
        body, signature = token.rsplit(".", 1)
    except ValueError:
        return None
    expected = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return UUID(str(payload["tid"]))
    except (ValueError, KeyError, TypeError):
        return None


def resolve_tenant(db: Session, api_key: str) -> Tenant | None:
    if not api_key.strip():
        return None
    tenant = db.scalar(select(Tenant).where(Tenant.api_key_hash == hash_api_key(api_key.strip())))
    if tenant is None or not tenant.is_active:
        return None
    return tenant


def current_tenant(request: Request, db: Session = Depends(get_db)) -> Tenant:
    """Console dependency: redirect to the login page when no session exists."""

    token = request.cookies.get(COOKIE_NAME, "")
    tenant_id = read_token(token) if token else None
    if tenant_id is not None:
        tenant = db.get(Tenant, tenant_id)
        if tenant is not None and tenant.is_active:
            bind_tenant(db, tenant.id)
            request.state.console_tenant = tenant
            return tenant
    target = request.url.path
    raise HTTPException(
        status_code=status.HTTP_303_SEE_OTHER,
        detail="console login required",
        headers={"Location": f"/console/login?next={target}"},
    )
