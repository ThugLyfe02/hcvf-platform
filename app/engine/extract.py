"""Parsing helpers shared by probes. Standard library only, by design."""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_SET_COOKIE_SPLIT = re.compile(r",\s*(?=[^;,\s]+=)")


@dataclass
class Page:
    links: set[str] = field(default_factory=set)
    forms: list[dict[str, object]] = field(default_factory=list)
    title: str = ""


class _Extractor(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.page = Page()
        self._in_title = False
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in {"a", "link", "script", "img", "iframe", "source"}:
            for attribute in ("href", "src"):
                target = values.get(attribute)
                if target and not target.startswith(("javascript:", "mailto:", "tel:", "#")):
                    self.page.links.add(self._absolute(target))
        elif tag == "form":
            self._form = {
                "action": self._absolute(values.get("action", "") or self.base_url),
                "method": (values.get("method") or "GET").upper(),
                "inputs": [],
            }
            self.page.forms.append(self._form)
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            name = values.get("name")
            if name:
                inputs = self._form["inputs"]
                assert isinstance(inputs, list)
                inputs.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.page.title:
            self.page.title = data.strip()[:200]

    def _absolute(self, target: str) -> str:
        return urljoin(self.base_url, target.strip())


def extract_page(html: str, base_url: str) -> Page:
    parser = _Extractor(base_url)
    with contextlib.suppress(ValueError, AssertionError):
        parser.feed(html)
    return parser.page


def split_set_cookie(values: list[str]) -> list[str]:
    """Split a joined Set-Cookie header without breaking Expires dates."""

    cookies: list[str] = []
    for value in values:
        cookies.extend(part for part in _SET_COOKIE_SPLIT.split(value) if part.strip())
    return cookies


def parse_cookie(raw: str) -> dict[str, object]:
    segments = [segment.strip() for segment in raw.split(";")]
    name, _, value = segments[0].partition("=")
    flags = {"secure": False, "httponly": False, "samesite": "", "path": "", "domain": "", "max_age": None}
    for segment in segments[1:]:
        key, _, flag_value = segment.partition("=")
        lowered = key.strip().lower()
        if lowered == "secure":
            flags["secure"] = True
        elif lowered == "httponly":
            flags["httponly"] = True
        elif lowered == "samesite":
            flags["samesite"] = flag_value.strip()
        elif lowered == "path":
            flags["path"] = flag_value.strip()
        elif lowered == "domain":
            flags["domain"] = flag_value.strip()
        elif lowered == "max-age":
            with contextlib.suppress(ValueError):
                flags["max_age"] = int(flag_value.strip())
    return {"name": name.strip(), "value": value.strip(), **flags}


def find_jwts(texts: list[str]) -> list[str]:
    found: list[str] = []
    for text in texts:
        for match in _JWT_RE.findall(text):
            if match not in found:
                found.append(match)
    return found


def decode_jwt(token: str) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    parts = token.split(".")
    if len(parts) < 2:
        return None, None

    def decode(segment: str) -> dict[str, object] | None:
        padding = "=" * (-len(segment) % 4)
        try:
            raw = base64.urlsafe_b64decode(segment + padding)
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else None
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None

    return decode(parts[0]), decode(parts[1])


def parse_allow_header(value: str) -> set[str]:
    return {item.strip().upper() for item in value.split(",") if item.strip()}


def same_origin(first: str, second: str) -> bool:
    a, b = urlsplit(first), urlsplit(second)
    return (a.scheme, a.hostname, a.port or (443 if a.scheme == "https" else 80)) == (
        b.scheme,
        b.hostname,
        b.port or (443 if b.scheme == "https" else 80),
    )
