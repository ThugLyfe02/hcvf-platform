from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any, Protocol


class SafetyClass(IntEnum):
    """Ordered blast-radius classes. Higher values may include all lower ones."""

    read_only = 0
    state_changing = 1
    destructive = 2

    def allowed_by(self, ceiling: SafetyClass) -> bool:
        return int(self) <= int(ceiling)


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


SEVERITY_SCORE = {
    Severity.critical: 9.5,
    Severity.high: 8.0,
    Severity.medium: 5.5,
    Severity.low: 3.0,
    Severity.info: 0.5,
}


@dataclass(frozen=True, slots=True)
class Target:
    """A single origin under test. Always normalized to scheme://host[:port]."""

    scheme: str
    host: str
    port: int
    base_path: str = "/"

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        suffix = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{self.host}{suffix}"

    @property
    def url(self) -> str:
        return f"{self.origin}{self.base_path}"

    @property
    def is_tls(self) -> bool:
        return self.scheme == "https"


@dataclass(frozen=True, slots=True)
class ScopeGrant:
    """An authorization artifact. Deny-by-default; every request needs one."""

    origin: str
    methods: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})
    path_prefix: str = "/"
    max_safety: SafetyClass = SafetyClass.read_only
    expires_at: datetime | None = None
    max_rps: float = 5.0
    approver: str = "unspecified"
    evidence_sha256: str = ""

    def covers(self, url: str, method: str, safety: SafetyClass, *, now: datetime | None = None) -> bool:
        from urllib.parse import urlsplit

        now = now or datetime.now(UTC)
        if self.expires_at is not None and now >= self.expires_at:
            return False
        if method.upper() not in {m.upper() for m in self.methods}:
            return False
        if not safety.allowed_by(self.max_safety):
            return False
        parts = urlsplit(url)
        if f"{parts.scheme}://{parts.netloc}" != self.origin:
            return False
        return (parts.path or "/").startswith(self.path_prefix)


@dataclass(frozen=True, slots=True)
class Cost:
    requests: int = 0
    bytes_in: int = 0
    seconds: float = 0.0

    def __add__(self, other: Cost) -> Cost:
        return Cost(
            self.requests + other.requests,
            self.bytes_in + other.bytes_in,
            self.seconds + other.seconds,
        )

    def scaled(self, factor: float) -> Cost:
        return Cost(
            requests=int(self.requests * factor),
            bytes_in=int(self.bytes_in * factor),
            seconds=self.seconds * factor,
        )


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A discovered addressable surface. ``value`` is a 0..1 heuristic worth."""

    url: str
    method: str = "GET"
    status: int | None = None
    content_type: str = ""
    value: float = 0.0
    source: str = "seed"
    title: str = ""

    @property
    def path(self) -> str:
        from urllib.parse import urlsplit

        return urlsplit(self.url).path or "/"


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def canonical(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": dict(self.headers),
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "body_len": len(self.body),
        }


@dataclass(frozen=True, slots=True)
class TlsInfo:
    version: str = ""
    cipher: str = ""
    verified: bool = False
    error: str = ""
    not_after: str = ""
    subject: str = ""
    issuer: str = ""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    elapsed_ms: float
    url: str
    peer_ip: str = ""
    tls: TlsInfo | None = None
    truncated: bool = False

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def text(self, limit: int = 65536) -> str:
        return self.body[:limit].decode("utf-8", "replace")

    def canonical(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "headers": dict(self.headers),
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "body_len": len(self.body),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "url": self.url,
            "peer_ip": self.peer_ip,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class Observation:
    """One sealed request/response pair plus the reason it was sent."""

    probe_id: str
    request: HttpRequest
    response: HttpResponse
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "note": self.note,
            "request": self.request.canonical(),
            "response": self.response.canonical(),
        }


@dataclass(frozen=True, slots=True)
class FindingDraft:
    """A probe's claim before fingerprinting, scoring and evidence sealing."""

    probe_id: str
    kind: str
    title: str
    detail: str
    severity: Severity
    confidence: float
    cwe: str = ""
    remediation: str = ""
    location: str = ""
    tags: tuple[str, ...] = ()
    #: Class-level probability shift claimed by this probe on a finding.
    likelihood_ratio: float = 8.0

    def with_location(self, location: str) -> FindingDraft:
        return replace(self, location=location or self.location)


@dataclass(slots=True)
class ProbeOutcome:
    observations: list[Observation] = field(default_factory=list)
    findings: list[FindingDraft] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    cost: Cost = Cost()
    skipped: str = ""

    @property
    def yielded(self) -> bool:
        return bool(self.findings)


@dataclass(frozen=True, slots=True)
class Finding:
    """A fingerprinted, scored, evidence-linked finding."""

    id: str
    fingerprint: str
    probe_id: str
    kind: str
    title: str
    detail: str
    severity: Severity
    confidence: float
    cwe: str
    remediation: str
    location: str
    tags: tuple[str, ...]
    evidence: tuple[str, ...] = ()
    first_seen: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "probe_id": self.probe_id,
            "kind": self.kind,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "cwe": self.cwe,
            "remediation": self.remediation,
            "location": self.location,
            "tags": list(self.tags),
            "evidence": list(self.evidence),
            "first_seen": self.first_seen,
        }


class HttpClient(Protocol):
    """The only way a probe may touch the network."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Sequence[tuple[str, str]] | None = None,
        body: bytes = b"",
        safety: SafetyClass = SafetyClass.read_only,
        follow_redirects: bool = False,
    ) -> HttpResponse: ...


@dataclass(slots=True)
class ProbeContext:
    """Everything a probe is allowed to know."""

    client: HttpClient
    target: Target
    grant: ScopeGrant
    rng: Any
    deadline: float
    observed: dict[str, Any] = field(default_factory=dict)
    endpoints: list[Endpoint] = field(default_factory=list)

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.client.request("GET", url, **kwargs)


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
