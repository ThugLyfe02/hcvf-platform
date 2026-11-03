"""W3C trace-context propagation.

Distributed tracing without pulling in an SDK: accept ``traceparent`` from a
caller (or mint one), keep the trace id in a context variable so log records
carry it, echo it back, and expose it to the API layer via ``request.state``.
"""

from __future__ import annotations

import re
import secrets
from contextvars import ContextVar

TRACEPARENT_HEADER = "traceparent"
_TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_ZERO_TRACE = "0" * 32

trace_id_context: ContextVar[str | None] = ContextVar("trace_id", default=None)


def new_trace_id() -> str:
    return secrets.token_hex(16)


def new_span_id() -> str:
    return secrets.token_hex(8)


def parse_traceparent(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    match = _TRACEPARENT_RE.match(value.strip().lower())
    if not match:
        return None
    version, trace_id, span_id, _flags = match.groups()
    if version == "ff" or trace_id == _ZERO_TRACE or set(span_id) == {"0"}:
        return None
    return trace_id, span_id


def format_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    return f"00-{trace_id}-{span_id}-{'01' if sampled else '00'}"


def current_trace_id() -> str | None:
    return trace_id_context.get()


class TraceContextMiddleware:
    """Minimal ASGI middleware: parse/mint trace context, echo it back."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        parsed = parse_traceparent(headers.get(TRACEPARENT_HEADER))
        if parsed is None:
            trace_id = new_trace_id()
        else:
            trace_id, _parent_span = parsed

        token = trace_id_context.set(trace_id)
        scope.setdefault("state", {})["trace_id"] = trace_id
        outgoing = format_traceparent(trace_id, new_span_id())

        async def send_with_context(message):
            if message["type"] == "http.response.start":
                raw = message.setdefault("headers", [])
                raw.append((b"traceparent", outgoing.encode("latin-1")))
            await send(message)

        try:
            await self.app(scope, receive, send_with_context)
        finally:
            trace_id_context.reset(token)
