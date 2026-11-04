from __future__ import annotations

import http.client
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from urllib.parse import urljoin, urlsplit

from app.engine.budget import Budget, KillSwitch
from app.engine.errors import ScopeViolation, TransportError
from app.engine.policy import EgressPolicy
from app.engine.types import HttpRequest, HttpResponse, SafetyClass, ScopeGrant, TlsInfo

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ALLOWED_METHODS = READ_ONLY_METHODS | WRITE_METHODS
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that dials a pre-validated address, not a hostname."""

    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an address while keeping Host/SNI intact."""

    def __init__(self, host: str, port: int, address: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class RateLimiter:
    """Token bucket. Politeness is a control, not a nicety."""

    def __init__(
        self,
        rate_per_second: float,
        *,
        burst: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.rate = float(rate_per_second)
        self.capacity = max(1.0, float(burst if burst is not None else rate_per_second))
        self._tokens = self.capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available. Returns seconds waited."""

        waited = 0.0
        while True:
            now = self._clock()
            self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return waited
            deficit = tokens - self._tokens
            delay = deficit / self.rate
            waited += delay
            self._sleep(delay)


def _format_cert_name(name: Sequence) -> str:
    parts: list[str] = []
    for rdn in name or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _join_headers(items: Sequence[tuple[str, str]]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for key, value in items:
        lowered = key.lower()
        if lowered in merged:
            merged[lowered] = f"{merged[lowered]}, {value}"
        else:
            merged[lowered] = value
    return merged


def _validate_header(name: str, value: str) -> None:
    if not name or any(ch in name for ch in "\r\n:"):
        raise ValueError(f"invalid header name: {name!r}")
    if any(ch in value for ch in "\r\n"):
        raise ValueError(f"invalid header value for {name!r}")


class GuardedHttpClient:
    """The only egress path. Enforces scope, SSRF policy, budget and politeness.

    Design notes that matter:
      * connects to a resolved-and-validated IP, so DNS rebinding cannot move
        the connection after authorization;
      * redirects are never followed implicitly — each hop is re-authorized;
      * every request spends from a shared budget and passes the kill switch.
    """

    def __init__(
        self,
        policy: EgressPolicy,
        grant: ScopeGrant,
        budget: Budget,
        *,
        kill_switch: KillSwitch | None = None,
        timeout: float = 10.0,
        max_bytes: int = 262_144,
        max_redirects: int = 3,
        rate_limiter: RateLimiter | None = None,
        user_agent: str = "HCVF-Validation/1.0 (+authorized-testing)",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self.grant = grant
        self.budget = budget
        self.kill_switch = kill_switch or KillSwitch()
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.rate_limiter = rate_limiter or RateLimiter(grant.max_rps)
        self.user_agent = user_agent
        self._clock = clock
        self.requests_sent = 0
        self.denials: list[str] = []

    # -- authorization ---------------------------------------------------
    def authorize(self, method: str, url: str, safety: SafetyClass) -> tuple[str, str, int, str]:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ScopeViolation(f"method {method} is not permitted by the engine")
        if safety is SafetyClass.read_only and method not in READ_ONLY_METHODS:
            raise ScopeViolation(f"read-only probe attempted {method}")

        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            raise ScopeViolation(f"scheme {parts.scheme!r} is not supported")
        if parts.username or parts.password:
            raise ScopeViolation("credentials in URLs are not permitted")
        if not parts.hostname:
            raise ScopeViolation("URL has no host")
        if len(url) > 8192:
            raise ScopeViolation("URL exceeds 8192 characters")

        if not self.grant.covers(url, method, safety):
            raise ScopeViolation(f"{method} {url} is outside the active scope grant")

        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        addresses = self.policy.validate(host, port)
        return parts.scheme, host, port, addresses[0]

    # -- transport -------------------------------------------------------
    def _send_once(
        self,
        method: str,
        url: str,
        scheme: str,
        host: str,
        port: int,
        address: str,
        headers: Sequence[tuple[str, str]],
        body: bytes,
    ) -> HttpResponse:
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        started = self._clock()
        connection: http.client.HTTPConnection
        tls: TlsInfo | None = None
        if scheme == "https":
            context = ssl.create_default_context()
            try:
                secure = _PinnedHTTPSConnection(host, port, address, self.timeout, context)
                secure.connect()
            except ssl.SSLCertVerificationError as exc:
                # Capture the finding, then reconnect without verification so
                # the probe can still inspect protocol and cipher posture.
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                secure = _PinnedHTTPSConnection(host, port, address, self.timeout, context)
                secure.connect()
                tls = TlsInfo(
                    version=secure.sock.version() or "",
                    cipher=",".join(str(part) for part in (secure.sock.cipher() or ())),
                    verified=False,
                    error=f"{exc.__class__.__name__}: {exc.verify_message or exc}",
                )
            else:
                cert = secure.sock.getpeercert() or {}
                tls = TlsInfo(
                    version=secure.sock.version() or "",
                    cipher=",".join(str(part) for part in (secure.sock.cipher() or ())),
                    verified=True,
                    not_after=str(cert.get("notAfter", "")),
                    subject=_format_cert_name(cert.get("subject", ())),
                    issuer=_format_cert_name(cert.get("issuer", ())),
                )
            connection = secure
        else:
            connection = _PinnedHTTPConnection(host, port, address, self.timeout)
            connection.connect()

        try:
            connection.putrequest(method, path, skip_accept_encoding=True)
            sent: set[str] = {"host"}
            defaults = (
                ("User-Agent", self.user_agent),
                ("Accept", "*/*"),
                ("Connection", "close"),
            )
            for name, value in (*defaults, *headers):
                _validate_header(name, value)
                if name.lower() in sent:
                    continue
                connection.putheader(name, value)
                sent.add(name.lower())
            connection.endheaders(body if body else None)
            raw_response = connection.getresponse()
            raw = raw_response.read(self.max_bytes + 1)
            elapsed_ms = (self._clock() - started) * 1000.0
            truncated = len(raw) > self.max_bytes
            if truncated:
                raw = raw[: self.max_bytes]
            headers_out = {
                "host": host,
                "user-agent": self.user_agent,
                "accept": "*/*",
            }
            headers_out.update(_join_headers(raw_response.getheaders()))
            return HttpResponse(
                status=raw_response.status,
                headers=headers_out,
                body=raw,
                elapsed_ms=elapsed_ms,
                url=url,
                peer_ip=address,
                tls=tls,
                truncated=truncated,
            )
        except TimeoutError as exc:
            raise TransportError(f"timeout after {self.timeout}s: {url}") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(f"{exc.__class__.__name__}: {exc} ({url})") from exc
        finally:
            connection.close()

    # -- public API ------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Sequence[tuple[str, str]] | None = None,
        body: bytes = b"",
        safety: SafetyClass = SafetyClass.read_only,
        follow_redirects: bool = False,
    ) -> HttpResponse:
        current_url = url
        current_method = method.upper()
        current_body = body
        extra = list(headers or ())

        for hop in range(self.max_redirects + 1):
            self.budget.check_deadline()
            self.kill_switch.check()
            scheme, host, port, address = self.authorize(current_method, current_url, safety)

            self.rate_limiter.acquire()
            self.budget.spend(requests=1)
            self.requests_sent += 1
            response = self._send_once(current_method, current_url, scheme, host, port, address, extra, current_body)
            self.budget.spend(bytes_in=len(response.body))

            location = response.header("location")
            if not (follow_redirects and response.status in REDIRECT_STATUSES and location):
                return response

            next_url = urljoin(current_url, location)
            if (response.status == 303 and current_method != "HEAD") or (
                response.status in {301, 302} and current_method == "POST"
            ):
                current_method, current_body = "GET", b""

            if hop == self.max_redirects:
                raise TransportError(f"redirect limit ({self.max_redirects}) exceeded at {next_url}")
            # Authorize the hop before it happens; a redirect is not a grant.
            self.authorize(current_method, next_url, safety)
            current_url = next_url

        raise TransportError("redirect handling failed")

    def head(self, url: str, **kwargs: object) -> HttpResponse:
        return self.request("HEAD", url, **kwargs)  # type: ignore[arg-type]

    def get(self, url: str, **kwargs: object) -> HttpResponse:
        return self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    def as_request(self, method: str, url: str, headers: Sequence[tuple[str, str]], body: bytes) -> HttpRequest:
        return HttpRequest(method=method, url=url, headers=tuple(headers), body=body)
