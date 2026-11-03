from __future__ import annotations

import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.metrics import HTTP_REQUEST_DURATION, HTTP_REQUESTS


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Records HTTP metrics for every response, including middleware rejections.

    This lives outside the rate limiter on purpose: a burst of 429s is exactly
    the traffic you most want to see on a dashboard.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        started = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - started
        route = request.scope.get("route")
        path_label = getattr(route, "path", request.url.path)
        try:
            HTTP_REQUESTS.labels(request.method, path_label, str(response.status_code)).inc()
            HTTP_REQUEST_DURATION.labels(request.method, path_label).observe(duration)
        except Exception:
            pass
        return response
