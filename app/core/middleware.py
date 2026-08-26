from __future__ import annotations

import time
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from redis import Redis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.config import settings
from app.core.metrics import HTTP_REQUEST_DURATION, HTTP_REQUESTS


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - started
        route = request.scope.get("route")
        path_label = getattr(route, "path", request.url.path)
        HTTP_REQUESTS.labels(request.method, path_label, str(response.status_code)).inc()
        HTTP_REQUEST_DURATION.labels(request.method, path_label).observe(duration)
        response.headers["X-Request-ID"] = request_id
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in {"/health", "/metrics"}:
            return await call_next(request)

        identity = request.headers.get(settings.api_key_header) or (request.client.host if request.client else "unknown")
        bucket = int(time.time()) // settings.rate_limit_window_seconds
        key = f"hcvf:rate:{identity}:{bucket}"
        try:
            count = self.redis.incr(key)
            if count == 1:
                self.redis.expire(key, settings.rate_limit_window_seconds + 1)
        except Exception:
            return JSONResponse(status_code=503, content={"detail": "Rate limiter unavailable"})

        if count > settings.rate_limit_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(settings.rate_limit_window_seconds)},
            )
        return await call_next(request)
