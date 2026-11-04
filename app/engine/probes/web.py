from __future__ import annotations

import re

from app.engine.bayes import VulnClass
from app.engine.extract import parse_allow_header, parse_cookie, split_set_cookie
from app.engine.probes.base import Probe, ProbeSpec, register
from app.engine.types import Cost, ProbeContext, ProbeOutcome, SafetyClass, Severity

_WEAK_CSP_TOKENS = ("unsafe-inline", "unsafe-eval", "data:", "*")


@register
class SecurityHeadersProbe(Probe):
    spec = ProbeSpec(
        id="security-headers",
        name="Security header posture",
        safety=SafetyClass.read_only,
        targets=(VulnClass.headers,),
        cost=Cost(requests=1, seconds=0.3),
        description="Evaluates CSP, HSTS, framing, sniffing and referrer protections.",
        cwe="CWE-693",
        remediation="Set a strict Content-Security-Policy, HSTS, frame-ancestors, nosniff and a referrer policy.",
        sensitivity=0.92,
        false_positive_rate=0.02,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        url = ctx.target.url
        response = ctx.client.request("GET", url, safety=self.spec.safety)
        outcome = ProbeOutcome(
            observations=[self.observe(ctx, response)], cost=Cost(requests=1, bytes_in=len(response.body))
        )
        headers = response.headers

        csp = headers.get("content-security-policy", "")
        if not csp:
            outcome.findings.append(
                self.finding(
                    kind="missing-content-security-policy",
                    title="No Content-Security-Policy",
                    detail="The response has no Content-Security-Policy header, so the browser applies no restriction on script or frame sources.",
                    severity=Severity.medium,
                    confidence=0.98,
                    location=url,
                )
            )
        else:
            lowered = csp.lower()
            weak = [token for token in _WEAK_CSP_TOKENS if token in lowered]
            missing = [
                directive for directive in ("object-src", "base-uri", "frame-ancestors") if directive not in lowered
            ]
            if "script-src" not in lowered and "default-src" not in lowered:
                weak.append("no-script-directive")
            if weak or missing:
                outcome.findings.append(
                    self.finding(
                        kind="weak-content-security-policy",
                        title="Content-Security-Policy allows unsafe sources",
                        detail=(
                            "CSP is present but permissive. "
                            f"Weak tokens: {', '.join(weak) or 'none'}. "
                            f"Missing directives: {', '.join(missing) or 'none'}."
                        ),
                        severity=Severity.medium if "unsafe-inline" in weak or "unsafe-eval" in weak else Severity.low,
                        confidence=0.9,
                        location=url,
                    )
                )

        if ctx.target.is_tls:
            hsts = headers.get("strict-transport-security", "")
            if not hsts:
                outcome.findings.append(
                    self.finding(
                        kind="missing-hsts",
                        title="No Strict-Transport-Security header",
                        detail="HTTPS responses do not advertise HSTS, leaving users exposed to downgrade on first visit.",
                        severity=Severity.low,
                        confidence=0.97,
                        location=url,
                    )
                )
            else:
                match = re.search(r"max-age\s*=\s*(\d+)", hsts)
                max_age = int(match.group(1)) if match else 0
                if max_age < 15_552_000:
                    outcome.findings.append(
                        self.finding(
                            kind="short-hsts-max-age",
                            title="HSTS max-age is shorter than six months",
                            detail=f"Strict-Transport-Security max-age is {max_age} seconds; 15552000 or more is recommended.",
                            severity=Severity.low,
                            confidence=0.95,
                            location=url,
                        )
                    )

        if not headers.get("x-content-type-options", "").lower().startswith("nosniff"):
            outcome.findings.append(
                self.finding(
                    kind="missing-nosniff",
                    title="Missing X-Content-Type-Options: nosniff",
                    detail="Without nosniff, browsers may MIME-sniff responses and execute content as a different type.",
                    severity=Severity.low,
                    confidence=0.98,
                    location=url,
                )
            )

        if not headers.get("x-frame-options") and "frame-ancestors" not in csp.lower():
            outcome.findings.append(
                self.finding(
                    kind="missing-frame-protection",
                    title="Missing clickjacking protection",
                    detail="Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed by any origin.",
                    severity=Severity.low,
                    confidence=0.96,
                    location=url,
                )
            )

        if "referrer-policy" not in headers:
            outcome.findings.append(
                self.finding(
                    kind="missing-referrer-policy",
                    title="Missing Referrer-Policy",
                    detail="Default referrer behaviour can leak full URLs, including tokens in query strings, to third parties.",
                    severity=Severity.info,
                    confidence=0.9,
                    location=url,
                )
            )

        if "permissions-policy" not in headers and "feature-policy" not in headers:
            outcome.findings.append(
                self.finding(
                    kind="missing-permissions-policy",
                    title="Missing Permissions-Policy",
                    detail="Browser features such as camera, microphone and geolocation are not explicitly restricted.",
                    severity=Severity.info,
                    confidence=0.85,
                    location=url,
                )
            )

        return outcome


@register
class HttpMethodsProbe(Probe):
    spec = ProbeSpec(
        id="http-methods",
        name="HTTP method surface",
        safety=SafetyClass.read_only,
        targets=(VulnClass.methods,),
        cost=Cost(requests=2, seconds=0.4),
        description="Inspects OPTIONS and detects an enabled TRACE method.",
        cwe="CWE-650",
        remediation="Disable TRACE at the edge and restrict the allowed method set per route.",
        sensitivity=0.8,
        false_positive_rate=0.03,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        url = ctx.target.url
        outcome = ProbeOutcome()
        options = ctx.client.request("OPTIONS", url, safety=self.spec.safety)
        outcome.observations.append(self.observe(ctx, options, method="OPTIONS", note="method enumeration"))
        outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(options.body))

        allow = parse_allow_header(options.header("allow") or "")
        if allow:
            sensitive = sorted(allow & {"TRACE", "PUT", "DELETE", "PATCH"})
            if sensitive:
                outcome.findings.append(
                    self.finding(
                        kind="broad-method-allowlist",
                        title="Server advertises write or diagnostic methods",
                        detail=f"OPTIONS reports Allow: {', '.join(sorted(allow))}. Advertised methods: {', '.join(sensitive)}.",
                        severity=Severity.info,
                        confidence=0.8,
                        location=url,
                        tags=("disclosure",),
                    )
                )

        if "TRACE" in allow or not allow:
            trace = ctx.client.request("TRACE", url, safety=self.spec.safety)
            outcome.observations.append(self.observe(ctx, trace, method="TRACE", note="TRACE enablement check"))
            outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(trace.body))
            body = trace.text(4096).upper()
            if trace.status == 200 and ("TRACE" in body or "MESSAGE" in body):
                outcome.findings.append(
                    self.finding(
                        kind="trace-method-enabled",
                        title="HTTP TRACE is enabled",
                        detail="The server echoes the request in a TRACE response, enabling cross-site tracing against legacy clients.",
                        severity=Severity.medium,
                        confidence=0.9,
                        location=url,
                    )
                )
        return outcome


_TRACE_MARKERS = (
    "traceback (most recent call last)",
    "exception in thread",
    "java.lang.",
    "org.springframework",
    "at org.apache",
    "sqlstate[",
    "warning: mysql",
    "unclosed quotation mark",
    "doctrine\\",
    "werkzeug debugger",
    "debugpy",
    "x-powered-by: express",
    "stack trace",
)


@register
class ErrorDisclosureProbe(Probe):
    spec = ProbeSpec(
        id="error-disclosure",
        name="Verbose error and stack disclosure",
        safety=SafetyClass.read_only,
        targets=(VulnClass.error_disclosure,),
        cost=Cost(requests=1, seconds=0.3),
        description="Requests a non-existent path and inspects the error page for stack traces and framework detail.",
        cwe="CWE-209",
        remediation="Return generic error pages and disable debug mode outside development.",
        sensitivity=0.75,
        false_positive_rate=0.04,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        # Deterministic probe path: a random token here would make the finding
        # fingerprint differ between otherwise identical runs, breaking replay.
        from app.engine.types import stable_hash

        token = stable_hash({"probe": self.spec.id, "target": ctx.target.origin})[:12]
        url = f"{ctx.target.origin}/hcvf-probe-{token}"
        response = ctx.client.request("GET", url, safety=self.spec.safety)
        outcome = ProbeOutcome(
            observations=[self.observe(ctx, response, note="non-existent path error page")],
            cost=Cost(requests=1, bytes_in=len(response.body)),
        )
        text = response.text(65536)
        lowered = text.lower()
        hits = [marker for marker in _TRACE_MARKERS if marker in lowered]
        if hits:
            outcome.findings.append(
                self.finding(
                    kind="verbose-error-page",
                    title="Error page leaks internal implementation detail",
                    detail=f"A non-existent path returned HTTP {response.status} with diagnostic markers: {', '.join(hits[:4])}.",
                    severity=Severity.medium,
                    confidence=0.85,
                    location=url,
                )
            )

        banner = response.header("x-powered-by") or response.header("server")
        if banner:
            outcome.findings.append(
                self.finding(
                    kind="technology-disclosure",
                    title="Server banner discloses technology",
                    detail=f"The response advertises: {banner}.",
                    severity=Severity.info,
                    confidence=0.95,
                    location=url,
                    tags=("disclosure",),
                )
            )
        return outcome


@register
class CookieProbe(Probe):
    spec = ProbeSpec(
        id="cookie-flags",
        name="Cookie attribute posture",
        safety=SafetyClass.read_only,
        targets=(VulnClass.cookies,),
        cost=Cost(requests=1, seconds=0.3),
        description="Checks Secure, HttpOnly, SameSite and __Host-/__Secure- prefix correctness.",
        cwe="CWE-614",
        remediation="Mark session cookies Secure, HttpOnly, SameSite=Lax or Strict, and use the __Host- prefix.",
        sensitivity=0.9,
        false_positive_rate=0.05,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        url = ctx.target.url
        response = ctx.client.request("GET", url, safety=self.spec.safety)
        outcome = ProbeOutcome(
            observations=[self.observe(ctx, response)], cost=Cost(requests=1, bytes_in=len(response.body))
        )

        raw_cookies = split_set_cookie([response.header("set-cookie") or ""]) if response.header("set-cookie") else []
        if not raw_cookies:
            outcome.skipped = "no cookies issued on the entry point"
            return outcome

        for raw in raw_cookies:
            cookie = parse_cookie(raw)
            name = str(cookie["name"])
            issues: list[str] = []
            severity = Severity.low
            if ctx.target.is_tls and not cookie["secure"]:
                issues.append("missing Secure")
                severity = Severity.medium
            if not cookie["httponly"]:
                issues.append("missing HttpOnly")
                severity = Severity.medium if severity is Severity.medium else Severity.low
            if not cookie["samesite"]:
                issues.append("missing SameSite")
            if name.startswith("__Host-") and (not cookie["secure"] or cookie["path"] != "/" or cookie["domain"]):
                issues.append("__Host- prefix contract violated")
                severity = Severity.medium
            if name.startswith("__Secure-") and not cookie["secure"]:
                issues.append("__Secure- prefix contract violated")
                severity = Severity.medium

            if issues:
                outcome.findings.append(
                    self.finding(
                        kind=f"cookie-attributes:{name}",
                        title=f"Cookie {name!r} has weak attributes",
                        detail=f"Cookie {name!r} is missing or violates: {', '.join(issues)}.",
                        severity=severity,
                        confidence=0.9,
                        location=url,
                        tags=("cookies",),
                    )
                )
        return outcome


@register
class CorsProbe(Probe):
    spec = ProbeSpec(
        id="cors-policy",
        name="CORS trust policy",
        safety=SafetyClass.read_only,
        targets=(VulnClass.cors,),
        cost=Cost(requests=2, seconds=0.4),
        description="Checks whether an arbitrary origin is reflected with credentials allowed.",
        cwe="CWE-942",
        remediation="Allowlist exact origins; never combine a reflected Origin with Access-Control-Allow-Credentials: true.",
        sensitivity=0.9,
        false_positive_rate=0.03,
    )
    PROBE_ORIGIN = "https://hcvf-probe.invalid"

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        url = ctx.target.url
        outcome = ProbeOutcome()
        headers = [("Origin", self.PROBE_ORIGIN)]
        response = ctx.client.request("GET", url, headers=headers, safety=self.spec.safety)
        outcome.observations.append(self.observe(ctx, response, headers=headers, note="cross-origin probe"))
        outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(response.body))

        acao = response.header("access-control-allow-origin") or ""
        acac = (response.header("access-control-allow-credentials") or "").lower() == "true"
        reflected = acao.strip() == self.PROBE_ORIGIN
        wildcard = acao.strip() == "*"
        null_origin = acao.strip() == "null"

        preflight = ctx.client.request(
            "OPTIONS",
            url,
            headers=[
                ("Origin", self.PROBE_ORIGIN),
                ("Access-Control-Request-Method", "GET"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
            safety=self.spec.safety,
        )
        outcome.observations.append(self.observe(ctx, preflight, method="OPTIONS", note="CORS preflight"))
        outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(preflight.body))

        if reflected and acac:
            outcome.findings.append(
                self.finding(
                    kind="cors-reflected-origin-with-credentials",
                    title="CORS reflects arbitrary origin with credentials",
                    detail=f"Origin {self.PROBE_ORIGIN} was reflected in Access-Control-Allow-Origin while credentials are allowed.",
                    severity=Severity.high,
                    confidence=0.95,
                    location=url,
                )
            )
        elif reflected:
            outcome.findings.append(
                self.finding(
                    kind="cors-reflected-origin",
                    title="CORS reflects arbitrary origin",
                    detail=f"Origin {self.PROBE_ORIGIN} was reflected in Access-Control-Allow-Origin without credentials.",
                    severity=Severity.medium,
                    confidence=0.9,
                    location=url,
                )
            )
        elif null_origin:
            outcome.findings.append(
                self.finding(
                    kind="cors-null-origin",
                    title="CORS allows the null origin",
                    detail="Access-Control-Allow-Origin: null lets sandboxed iframes and local files call the API.",
                    severity=Severity.medium,
                    confidence=0.85,
                    location=url,
                )
            )
        elif wildcard:
            outcome.findings.append(
                self.finding(
                    kind="cors-wildcard",
                    title="CORS allows any origin",
                    detail="Access-Control-Allow-Origin: * exposes the response to every origin. Acceptable for public read-only data, not for authenticated APIs.",
                    severity=Severity.low,
                    confidence=0.8,
                    location=url,
                )
            )
        return outcome


@register
class SecurityTxtProbe(Probe):
    spec = ProbeSpec(
        id="security-txt",
        name="Vulnerability disclosure metadata",
        safety=SafetyClass.read_only,
        targets=(VulnClass.infra,),
        cost=Cost(requests=2, seconds=0.4),
        description="Checks for /.well-known/security.txt and reports robots.txt paths as new surface.",
        cwe="",
        remediation="Publish a security.txt with Contact and Expires fields.",
        default_enabled=True,
        sensitivity=0.5,
        false_positive_rate=0.02,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        outcome = ProbeOutcome()
        security_txt = ctx.client.request(
            "GET", f"{ctx.target.origin}/.well-known/security.txt", safety=self.spec.safety
        )
        outcome.observations.append(self.observe(ctx, security_txt, note="security.txt probe"))
        outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(security_txt.body))
        looks_valid = security_txt.status == 200 and "contact:" in security_txt.text(8192).lower()
        if not looks_valid:
            outcome.findings.append(
                self.finding(
                    kind="missing-security-txt",
                    title="No security.txt disclosure policy",
                    detail=f"/.well-known/security.txt returned HTTP {security_txt.status}, so researchers have no published contact route.",
                    severity=Severity.info,
                    confidence=0.9,
                    location=f"{ctx.target.origin}/.well-known/security.txt",
                )
            )

        robots = ctx.client.request("GET", f"{ctx.target.origin}/robots.txt", safety=self.spec.safety)
        outcome.observations.append(self.observe(ctx, robots, note="robots.txt discovery"))
        outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(robots.body))
        if robots.status == 200:
            interesting: list[str] = []
            for line in robots.text(65536).splitlines():
                lowered = line.lower()
                if lowered.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and any(
                        token in path.lower() for token in ("admin", "internal", "debug", "backup", "config", "api")
                    ):
                        interesting.append(path)
                        outcome.endpoints.append(self.endpoint(f"{ctx.target.origin}{path}", source=robots.url))
            if interesting:
                outcome.findings.append(
                    self.finding(
                        kind="robots-discloses-sensitive-paths",
                        title="robots.txt names sensitive paths",
                        detail=f"robots.txt advertises restricted locations: {', '.join(interesting[:6])}.",
                        severity=Severity.info,
                        confidence=0.85,
                        location=f"{ctx.target.origin}/robots.txt",
                        tags=("disclosure",),
                    )
                )
        return outcome
