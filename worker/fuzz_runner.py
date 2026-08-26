from __future__ import annotations

import hashlib
import ipaddress
import socket
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.core.config import Settings, get_settings
from app.models.finding import FindingSeverity

_DEFAULT_PROBE_VALUES = ("baseline", "0", "-1", "unicode-check-✓")


@dataclass(frozen=True, slots=True)
class FuzzFinding:
    title: str
    category: str
    severity: FindingSeverity
    description: str
    evidence: dict[str, Any]
    fingerprint: str


@dataclass(frozen=True, slots=True)
class FuzzResult:
    summary: dict[str, Any]
    findings: list[FuzzFinding]


class FuzzRunner:
    """
    Execute a bounded, non-destructive HTTP validation pass against one authorized target.

    The runner performs GET requests only, never crawls links, never follows redirects, caps
    both cases and response bytes, and blocks non-approved address ranges unless the operator
    explicitly enables public targets.
    """

    def __init__(
        self,
        *,
        target_url: str,
        config: dict[str, Any] | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.target_url = self._validate_target(target_url)
        self.config = config or {}
        self.probe_values = self._probe_values(self.config)

    def execute(self) -> FuzzResult:
        started = time.perf_counter()
        observations: list[dict[str, Any]] = []

        self._assert_target_still_allowed()
        with httpx.Client(
            timeout=httpx.Timeout(self.settings.target_request_timeout_seconds),
            follow_redirects=False,
            headers={
                "User-Agent": "HCVF/1.0 Authorized-Defensive-Validation",
                "X-HCVF-Authorized-Validation": "true",
                "Accept": "*/*",
            },
        ) as client:
            baseline = self._request(client, self.target_url, case_name="baseline")
            if baseline.get("error"):
                raise RuntimeError(
                    "The authorized target was unreachable during the baseline request: "
                    f"{baseline['error']}"
                )
            observations.append(baseline)

            for index, value in enumerate(self.probe_values, start=1):
                self._assert_target_still_allowed()
                probe_url = _with_probe_parameter(self.target_url, value)
                observations.append(
                    self._request(client, probe_url, case_name=f"probe-{index}")
                )

        findings = self._derive_findings(observations)
        status_counts = Counter(
            str(item["status_code"])
            for item in observations
            if item.get("status_code") is not None
        )
        summary = {
            "cases_executed": len(observations),
            "finding_count": len(findings),
            "status_counts": dict(sorted(status_counts.items())),
            "request_errors": sum(1 for item in observations if item.get("error")),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "response_bytes_observed": sum(
                int(item.get("bytes_observed", 0)) for item in observations
            ),
        }
        return FuzzResult(summary=summary, findings=findings)

    def _request(
        self,
        client: httpx.Client,
        url: str,
        *,
        case_name: str,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        digest = hashlib.sha256()
        observed = 0
        truncated = False

        try:
            with client.stream("GET", url) as response:
                for chunk in response.iter_bytes():
                    remaining = self.settings.target_max_response_bytes - observed
                    if remaining <= 0:
                        truncated = True
                        break
                    retained = chunk[:remaining]
                    digest.update(retained)
                    observed += len(retained)
                    if len(retained) < len(chunk):
                        truncated = True
                        break

                return {
                    "case": case_name,
                    "status_code": response.status_code,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                    "bytes_observed": observed,
                    "content_sha256": digest.hexdigest(),
                    "content_type": response.headers.get("content-type", "")[:200],
                    "redirect": 300 <= response.status_code < 400,
                    "truncated": truncated,
                    "error": None,
                }
        except httpx.RequestError as exc:
            return {
                "case": case_name,
                "status_code": None,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "bytes_observed": 0,
                "content_sha256": None,
                "content_type": "",
                "redirect": False,
                "truncated": False,
                "error": f"{exc.__class__.__name__}: {str(exc)[:300]}",
            }

    def _derive_findings(self, observations: list[dict[str, Any]]) -> list[FuzzFinding]:
        findings: list[FuzzFinding] = []
        statuses = {
            int(item["status_code"])
            for item in observations
            if item.get("status_code") is not None
        }
        server_error_cases = [
            item["case"]
            for item in observations
            if isinstance(item.get("status_code"), int) and item["status_code"] >= 500
        ]
        request_error_cases = [item["case"] for item in observations if item.get("error")]
        redirect_cases = [item["case"] for item in observations if item.get("redirect")]
        truncated_cases = [item["case"] for item in observations if item.get("truncated")]

        if server_error_cases:
            findings.append(
                self._finding(
                    title="Server error triggered by bounded benign input variation",
                    category="http_server_error",
                    severity=FindingSeverity.HIGH,
                    description=(
                        "One or more non-destructive GET variations produced an HTTP 5xx "
                        "response. Review application error handling and input validation."
                    ),
                    evidence={
                        "affected_cases": server_error_cases,
                        "status_by_case": _status_by_case(observations),
                    },
                )
            )

        if len(statuses) > 1:
            findings.append(
                self._finding(
                    title="HTTP status behavior changes across benign input variations",
                    category="http_status_variance",
                    severity=FindingSeverity.LOW,
                    description=(
                        "The target returned different status classes for bounded query "
                        "variations. Confirm that the behavior is intentional and documented."
                    ),
                    evidence={"status_by_case": _status_by_case(observations)},
                )
            )

        if request_error_cases:
            findings.append(
                self._finding(
                    title="Intermittent request failures during bounded validation",
                    category="request_reliability",
                    severity=FindingSeverity.MEDIUM,
                    description=(
                        "At least one validation case failed at the transport layer after the "
                        "baseline succeeded. Review service stability and connection handling."
                    ),
                    evidence={"affected_cases": request_error_cases},
                )
            )

        if redirect_cases:
            findings.append(
                self._finding(
                    title="Target returned redirects during validation",
                    category="http_redirect",
                    severity=FindingSeverity.INFO,
                    description=(
                        "HCVF does not follow redirects. Confirm that redirect destinations are "
                        "within the authorized test scope before validating them separately."
                    ),
                    evidence={"affected_cases": redirect_cases},
                )
            )

        if truncated_cases:
            findings.append(
                self._finding(
                    title="Response exceeded the configured evidence byte cap",
                    category="response_size_limit",
                    severity=FindingSeverity.INFO,
                    description=(
                        "HCVF stopped reading one or more responses at the configured byte cap "
                        "to preserve bounded execution."
                    ),
                    evidence={
                        "affected_cases": truncated_cases,
                        "byte_cap": self.settings.target_max_response_bytes,
                    },
                )
            )

        return findings

    def _finding(
        self,
        *,
        title: str,
        category: str,
        severity: FindingSeverity,
        description: str,
        evidence: dict[str, Any],
    ) -> FuzzFinding:
        fingerprint_input = f"{urlsplit(self.target_url).netloc}|{category}|{title}"
        fingerprint = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()
        return FuzzFinding(
            title=title,
            category=category,
            severity=severity,
            description=description,
            evidence=evidence,
            fingerprint=fingerprint,
        )

    def _validate_target(self, target_url: str) -> str:
        parsed = urlsplit(target_url.strip())
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Campaign targets must use http:// or https://.")
        if not parsed.hostname:
            raise ValueError("Campaign target must include a hostname.")
        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in the campaign target URL.")
        self._assert_host_allowed(parsed.hostname, parsed.port or _default_port(parsed.scheme))
        return urlunsplit(parsed)

    def _assert_target_still_allowed(self) -> None:
        parsed = urlsplit(self.target_url)
        assert parsed.hostname is not None
        self._assert_host_allowed(parsed.hostname, parsed.port or _default_port(parsed.scheme))

    def _assert_host_allowed(self, hostname: str, port: int) -> None:
        try:
            address_info = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError(f"Campaign target hostname could not be resolved: {exc}") from exc

        addresses = {
            ipaddress.ip_address(item[4][0].split("%", maxsplit=1)[0]) for item in address_info
        }
        if not addresses:
            raise ValueError("Campaign target hostname did not resolve to an address.")

        allowed_networks = _parse_networks(self.settings.allowed_target_cidrs)
        for address in addresses:
            if address.is_unspecified or address.is_multicast or address.is_link_local:
                raise ValueError(f"Campaign target resolves to a blocked address: {address}")
            if any(address in network for network in allowed_networks):
                continue
            if self.settings.allow_public_targets and address.is_global:
                continue
            raise ValueError(
                "Campaign target resolves outside ALLOWED_TARGET_CIDRS. "
                "Public targets remain disabled unless ALLOW_PUBLIC_TARGETS=true is set "
                "by an authorized operator."
            )

    def _probe_values(self, config: dict[str, Any]) -> tuple[str, ...]:
        configured = config.get("probe_values", _DEFAULT_PROBE_VALUES)
        if not isinstance(configured, (list, tuple)):
            raise ValueError("config.probe_values must be an array of strings.")

        values: list[str] = []
        for value in configured[: self.settings.fuzz_max_cases]:
            if not isinstance(value, str):
                raise ValueError("Every config.probe_values item must be a string.")
            if not 1 <= len(value) <= 64:
                raise ValueError("Probe values must contain between 1 and 64 characters.")
            values.append(value)

        if not values:
            raise ValueError("At least one probe value is required.")
        return tuple(values)


def _parse_networks(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw_network in value.split(","):
        raw_network = raw_network.strip()
        if raw_network:
            networks.append(ipaddress.ip_network(raw_network, strict=False))
    if not networks:
        raise ValueError("ALLOWED_TARGET_CIDRS must contain at least one network.")
    return tuple(networks)


def _with_probe_parameter(url: str, value: str) -> str:
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("hcvf_probe", value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _status_by_case(observations: list[dict[str, Any]]) -> dict[str, int | None]:
    return {item["case"]: item.get("status_code") for item in observations}
