"""Request body size limit.

Streaming/multipart payloads are not part of the API surface here, so a declared
``Content-Length`` above the ceiling is rejected before the body is read. This is
cheap insurance against memory exhaustion and slow-loris style uploads.
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_LIMIT = 1_048_576


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int = DEFAULT_LIMIT) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        declared = headers.get("content-length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                size = 0
            if size > self.max_bytes:
                body = json.dumps(
                    {
                        "type": "https://hcvf.dev/problems/413",
                        "title": "Payload too large",
                        "status": 413,
                        "detail": f"Request body exceeds {self.max_bytes} bytes.",
                    }
                ).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [
                            (b"content-type", b"application/problem+json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                message: Message = {"type": "http.response.body", "body": body}
                await send(message)
                return

        await self.app(scope, receive, send)
