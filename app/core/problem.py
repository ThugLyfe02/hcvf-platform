"""RFC 9457 Problem Details for every error the API returns.

Uniform errors make clients simpler and make incidents easier to correlate: each
body carries the trace id, so a support ticket can be tied to a trace.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

PROBLEM_CONTENT_TYPE = "application/problem+json"


def problem(
    *,
    status_code: int,
    title: str,
    detail: str = "",
    instance: str = "",
    trace_id: str | None = None,
    errors: list | None = None,
) -> dict:
    body: dict[str, object] = {
        "type": f"https://hcvf.dev/problems/{status_code}",
        "title": title,
        "status": status_code,
        "detail": detail,
    }
    if instance:
        body["instance"] = instance
    if trace_id:
        body["trace_id"] = trace_id
    if errors:
        body["errors"] = errors
    return body


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        trace_id = getattr(request.state, "trace_id", None)
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
        response = JSONResponse(
            status_code=exc.status_code,
            content=problem(
                status_code=exc.status_code,
                title=detail[:120] or "Request failed",
                detail=detail,
                instance=str(request.url.path),
                trace_id=trace_id,
            ),
            media_type=PROBLEM_CONTENT_TYPE,
        )
        for key, value in (exc.headers or {}).items():
            response.headers[key] = value
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=problem(
                status_code=422,
                title="Request validation failed",
                detail="One or more fields are invalid.",
                instance=str(request.url.path),
                trace_id=getattr(request.state, "trace_id", None),
                errors=[
                    {
                        "location": list(error.get("loc", [])),
                        "message": error.get("msg", ""),
                        "type": error.get("type", ""),
                    }
                    for error in exc.errors()
                ],
            ),
            media_type=PROBLEM_CONTENT_TYPE,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        trace_id = getattr(request.state, "trace_id", None)
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=problem(
                status_code=500,
                title="Internal server error",
                detail="The request failed. Quote the trace id when reporting.",
                instance=str(request.url.path),
                trace_id=trace_id,
            ),
            media_type=PROBLEM_CONTENT_TYPE,
        )
