from __future__ import annotations

import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.db.session import SessionLocal
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AuditMiddleware(BaseHTTPMiddleware):
    """Records mutating requests. Best-effort by design.

    An audit write must never turn a successful mutation into a 500, so failures
    are logged and swallowed. The authoritative audit records for domain events
    are written inside the service transaction; this middleware is the coarse
    "something changed" trail.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if request.method not in _MUTATING_METHODS:
            return response

        tenant_id = getattr(request.state, "tenant_id", None)
        if tenant_id is None:
            return response

        try:
            with SessionLocal() as db:
                AuditService(db).record(
                    tenant_id=tenant_id,
                    action=f"{request.method.lower()} {request.url.path}",
                    details={
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": response.status_code,
                    },
                    user_id=getattr(request.state, "actor", "unknown"),
                    resource_type=self._resource_type(request.url.path),
                    resource_id=self._resource_id(request.url.path),
                    request_id=getattr(request.state, "request_id", None),
                )
                db.commit()
        except Exception:
            logger.warning("audit middleware write failed for %s %s", request.method, request.url.path, exc_info=True)
        return response

    @staticmethod
    def _resource_type(path: str) -> str:
        parts = [part for part in path.split("/") if part]
        if len(parts) >= 3 and parts[0] == "api":
            return parts[2]
        return "request"

    @staticmethod
    def _resource_id(path: str) -> str:
        parts = [part for part in path.split("/") if part]
        if len(parts) >= 4 and parts[0] == "api":
            return parts[3]
        return "collection"
