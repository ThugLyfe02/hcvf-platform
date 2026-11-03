from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from app.engine.bayes import VulnClass
from app.engine.probes.base import Probe, ProbeSpec, register
from app.engine.types import Cost, ProbeContext, ProbeOutcome, SafetyClass, Severity

_ENV_LINE = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+")


@register
class ExposedConfigProbe(Probe):
    spec = ProbeSpec(
        id="exposed-config",
        name="Exposed VCS, environment and traversal paths",
        safety=SafetyClass.read_only,
        targets=(VulnClass.traversal, VulnClass.infra),
        cost=Cost(requests=3, seconds=0.6),
        description="Checks for reachable .git metadata, .env files and path-traversal normalisation gaps.",
        cwe="CWE-538",
        remediation="Block dotfiles at the edge, deny path traversal in the server, and keep VCS metadata out of web roots.",
        sensitivity=0.95,
        false_positive_rate=0.01,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        origin = ctx.target.origin
        outcome = ProbeOutcome()

        checks = (
            (
                f"{origin}/.git/config",
                "vcs-metadata",
                "[core]",
                "Exposed Git metadata",
                Severity.high,
                "The Git configuration file is served publicly, which can disclose repository internals and remote URLs.",
            ),
            (
                f"{origin}/.env",
                "env-file",
                None,
                "Exposed environment file",
                Severity.high,
                "An environment file is served publicly, potentially including credentials and signing keys.",
            ),
            (
                f"{origin}/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "path-traversal",
                "root:x:0:0",
                "Path traversal reaches /etc/passwd",
                Severity.critical,
                "Encoded traversal segments resolve outside the web root and return system files.",
            ),
        )

        for url, kind, signature, title, severity, detail in checks:
            response = ctx.client.request("GET", url, safety=self.spec.safety)
            outcome.observations.append(self.observe(ctx, response, note=kind))
            outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(response.body))
            if response.status != 200:
                continue
            body = response.text(65536)
            matched = signature in body if signature else bool(_ENV_LINE.search(body))
            if matched:
                outcome.findings.append(
                    self.finding(
                        kind=kind,
                        title=title,
                        detail=f"{detail} Observed at {url} (HTTP 200).",
                        severity=severity,
                        confidence=0.95,
                        location=url,
                    )
                )
        return outcome


@register
class OpenRedirectProbe(Probe):
    spec = ProbeSpec(
        id="open-redirect",
        name="Open redirect on query parameters",
        safety=SafetyClass.state_changing,
        targets=(VulnClass.redirect,),
        cost=Cost(requests=4, seconds=0.8),
        description="Substitutes an external URL into existing query parameters and inspects Location.",
        cwe="CWE-601",
        remediation="Resolve redirect targets against an allowlist and reject absolute external URLs.",
        default_enabled=False,
        sensitivity=0.85,
        false_positive_rate=0.05,
    )
    PROBE_TARGET = "https://hcvf-probe.invalid/redirected"

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        parts = urlsplit(ctx.target.url)
        params = list(parse_qs(parts.query).keys())
        candidates = params or ["redirect", "next", "url", "return", "continue"]
        outcome = ProbeOutcome()

        for name in candidates[:3]:
            query = dict(parse_qs(parts.query))
            query[name] = [self.PROBE_TARGET]
            url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(query, doseq=True), ""))
            response = ctx.client.request("GET", url, safety=self.spec.safety, follow_redirects=False)
            outcome.observations.append(self.observe(ctx, response, note=f"redirect parameter {name}"))
            outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(response.body))
            location = response.header("location") or ""
            if 300 <= response.status < 400 and location.startswith("https://hcvf-probe.invalid"):
                outcome.findings.append(
                    self.finding(
                        kind="open-redirect",
                        title="Open redirect via query parameter",
                        detail=f"Parameter {name!r} controlled the Location header to an attacker-chosen origin.",
                        severity=Severity.medium,
                        confidence=0.9,
                        location=url,
                    )
                )
                break
        return outcome


@register
class GraphqlIntrospectionProbe(Probe):
    spec = ProbeSpec(
        id="graphql-introspection",
        name="GraphQL introspection exposure",
        safety=SafetyClass.state_changing,
        targets=(VulnClass.graphql,),
        cost=Cost(requests=1, seconds=0.4),
        description="Sends a minimal introspection query to a discovered GraphQL endpoint.",
        cwe="CWE-200",
        remediation="Disable introspection in production or restrict it to authenticated operators.",
        default_enabled=False,
        sensitivity=0.8,
        false_positive_rate=0.02,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        known = [e.url for e in ctx.endpoints if "graphql" in e.url.lower()]
        url = known[0] if known else f"{ctx.target.origin}/graphql"
        body = json.dumps({"query": "{__schema{queryType{name}}}"}).encode("utf-8")
        headers = [("Content-Type", "application/json"), ("Accept", "application/json")]
        response = ctx.client.request("POST", url, headers=headers, body=body, safety=self.spec.safety)
        outcome = ProbeOutcome(
            observations=[self.observe(ctx, response, method="POST", headers=headers, body=body, note="introspection")],
            cost=Cost(requests=1, bytes_in=len(response.body)),
        )
        text = response.text(65536)
        if response.status == 200 and "__schema" in text and "queryType" in text:
            outcome.findings.append(
                self.finding(
                    kind="graphql-introspection-enabled",
                    title="GraphQL introspection is enabled",
                    detail="The endpoint returns a full schema description to unauthenticated callers, exposing the entire API surface.",
                    severity=Severity.medium,
                    confidence=0.9,
                    location=url,
                )
            )
        return outcome
