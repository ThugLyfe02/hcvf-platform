"""Log redaction.

API keys, bearer tokens, cookies and webhook secrets must never reach a log
sink, including in exception tracebacks and structured ``extra`` fields. The
filter is applied at the formatter boundary so no caller can forget it.
"""

from __future__ import annotations

import logging
import re
from typing import Any

SENSITIVE_KEYS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "private_key",
)

REDACTED = "[redacted]"

_PATTERNS = (
    re.compile(r"(?i)(x-api-key\s*[:=]\s*)([^\s,;\"']+)"),
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)([^\s,;\"']+)"),
    re.compile(r"(?i)(set-cookie\s*[:=]\s*)([^\r\n]+)"),
    re.compile(r"(?i)(\"?(?:password|secret|api_key|token)\"?\s*[:=]\s*\"?)([^\s,;\"'}\]]+)"),
)


def is_sensitive(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(marker in lowered for marker in SENSITIVE_KEYS)


def redact_text(text: str) -> str:
    result = text
    for pattern in _PATTERNS:
        result = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}", result)
    return result


def scrub_mapping(mapping: dict) -> dict:
    cleaned = {}
    for key, item in mapping.items():
        if is_sensitive(str(key)):
            cleaned[key] = REDACTED
        elif isinstance(item, dict):
            cleaned[key] = scrub_mapping(item)
        elif isinstance(item, (list, tuple)):
            cleaned[key] = [REDACTED if is_sensitive(str(key)) else entry for entry in item]
        elif isinstance(item, str):
            cleaned[key] = redact_text(item)
        else:
            cleaned[key] = item
    return cleaned


def redact_value(key: str, value: Any) -> Any:
    if not is_sensitive(key):
        return scrub_mapping(value) if isinstance(value, dict) else value
    if isinstance(value, dict):
        return {
            inner: (REDACTED if is_sensitive(inner) else redact_value(inner, item)) for inner, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [REDACTED for _ in value]
    return REDACTED


class RedactionFilter(logging.Filter):
    """Scrub sensitive ``extra`` fields and inline secrets from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_text(record.getMessage())
            record.args = ()
        except Exception:
            return True

        for key in list(record.__dict__):
            if key.startswith("_") or key in {"msg", "args"}:
                continue
            if is_sensitive(key):
                record.__dict__[key] = REDACTED
            else:
                value = record.__dict__[key]
                if isinstance(value, str):
                    record.__dict__[key] = redact_text(value)
                elif isinstance(value, dict):
                    record.__dict__[key] = redact_value(key, value)
        return True
