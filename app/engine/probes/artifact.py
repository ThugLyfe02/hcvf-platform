"""Artifact and edge-surface probes: what the build published, and how caches trust it.

Modern applications ship more than HTML: bundles that carry credentials by
accident, source maps that expose the original tree, dependency manifests that
name every package, and cache layers that believe whatever header they are given.
These probes look for those artefacts without sending anything state-changing.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from app.engine.bayes import VulnClass
from app.engine.probes.base import Probe, ProbeSpec, register
from app.engine.types import Cost, ProbeContext, ProbeOutcome, SafetyClass, Severity

#: Credential shapes that are worth reporting when found in a public bundle.
#: Each pattern is deliberately narrow to keep the false-positive rate low; a
#: match is reported masked, never verbatim.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    ("stripe-secret-key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "Stripe live secret key"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "Slack token"),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "GitHub token"),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key block"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "signed JWT"),
)

_SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
_SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")

_MANIFESTS: tuple[tuple[str, str], ...] = (
    ("/package.json", "npm"),
    ("/package-lock.json", "npm-lock"),
    ("/yarn.lock", "yarn"),
    ("/composer.json", "composer"),
    ("/composer.lock", "composer-lock"),
    ("/requirements.txt", "pip"),
    ("/Gemfile.lock", "bundler"),
    ("/go.mod", "go"),
    ("/Cargo.lock", "cargo"),
    ("/pom.xml", "maven"),
    ("/build.gradle", "gradle"),
)

#: Headers a cache or reverse proxy may trust too readily.
_TRUST_HEADERS = ("X-Forwarded-Host", "X-Forwarded-Server", "X-Original-URL", "X-Rewrite-URL")
_CACHE_HEADERS = ("x-cache", "cf-cache-status", "x-proxy-cache", "x-varnish", "x-served-by", "age")


def _mask(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return f"{value[:4]}...{value[-2:]} ({len(value)} chars)"


def _absolute(base: str, reference: str) -> str:
    return urljoin(base, reference)


def _same_origin(base: str, candidate: str) -> bool:
    left, right = urlsplit(base), urlsplit(candidate)
    return (left.scheme, left.hostname, left.port) == (right.scheme, right.hostname, right.port)


@register
class SecretsInBundleProbe(Probe):
    spec = ProbeSpec(
        id="secrets-in-bundle",
        name="Credentials in public bundles",
        safety=SafetyClass.read_only,
        targets=(VulnClass.infra,),
        cost=Cost(requests=5, seconds=1.2),
        description="Fetches same-origin scripts and reports credential-shaped strings, masked.",
        cwe="CWE-798",
        remediation="Remove credentials from client bundles, rotate any exposed key, and inject secrets at runtime.",
        sensitivity=0.8,
        false_positive_rate=0.06,
        default_enabled=False,
    )

    MAX_SCRIPTS = 4
    MAX_BYTES = 400_000

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        entry = ctx.target.url
        page = ctx.client.request("GET", entry, safety=self.spec.safety)
        outcome = ProbeOutcome(observations=[self.observe(ctx, page)], cost=Cost(requests=1, bytes_in=len(page.body)))
        html = page.body.decode("utf-8", "replace")
        scripts = []
        for match in _SCRIPT_RE.finditer(html):
            candidate = _absolute(entry, match.group(1))
            if _same_origin(entry, candidate) and candidate not in scripts:
                scripts.append(candidate)
        if not scripts:
            return outcome

        checked = 0
        for script_url in scripts[: self.MAX_SCRIPTS]:
            try:
                response = ctx.client.request("GET", script_url, safety=self.spec.safety)
            except Exception as exc:
                outcome.observations.append(
                    self.observe(
                        ctx,
                        page,
                        url=script_url,
                        note=f"bundle unavailable: {exc.__class__.__name__}",
                    )
                )
                continue
            checked += 1
            outcome.observations.append(self.observe(ctx, response, url=script_url))
            outcome.endpoints.append(self.endpoint(script_url, response=response, source=self.spec.id, value=0.5))
            body = response.body.decode("utf-8", "replace")[: self.MAX_BYTES]
            for kind, pattern, label in _SECRET_PATTERNS:
                match = pattern.search(body)
                if not match:
                    continue
                outcome.findings.append(
                    self.finding(
                        kind=f"secret-in-bundle:{kind}",
                        title=f"{label} exposed in a public bundle",
                        detail=(
                            f"{script_url} contains a string matching {label} ({_mask(match.group(0))}). "
                            "The value is masked in the report; the evidence blob holds the raw response."
                        ),
                        severity=Severity.critical
                        if kind in {"aws-access-key", "stripe-secret-key", "private-key"}
                        else Severity.high,
                        confidence=0.82,
                        location=script_url,
                        tags=("artifacts", "secrets"),
                    )
                )
        if checked == 0:
            outcome.skipped = "no same-origin bundles could be fetched"
        return outcome


@register
class SourceMapProbe(Probe):
    spec = ProbeSpec(
        id="source-map-exposure",
        name="Source map exposure",
        safety=SafetyClass.read_only,
        targets=(VulnClass.infra,),
        cost=Cost(requests=5, seconds=1.0),
        description="Looks for published source maps that disclose original file trees.",
        cwe="CWE-540",
        remediation="Do not publish source maps in production, or restrict them to authenticated operators.",
        sensitivity=0.85,
        false_positive_rate=0.03,
        default_enabled=False,
    )

    MAX_SCRIPTS = 4

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        entry = ctx.target.url
        page = ctx.client.request("GET", entry, safety=self.spec.safety)
        outcome = ProbeOutcome(observations=[self.observe(ctx, page)], cost=Cost(requests=1, bytes_in=len(page.body)))
        html = page.body.decode("utf-8", "replace")
        scripts: list[str] = []
        for match in _SCRIPT_RE.finditer(html):
            candidate = _absolute(entry, match.group(1))
            if _same_origin(entry, candidate) and candidate not in scripts:
                scripts.append(candidate)

        map_candidates: list[tuple[str, str]] = []
        for script_url in scripts[: self.MAX_SCRIPTS]:
            try:
                response = ctx.client.request("GET", script_url, safety=self.spec.safety)
            except Exception:
                continue
            outcome.observations.append(self.observe(ctx, response, url=script_url))
            note = _SOURCE_MAP_RE.search(response.body.decode("utf-8", "replace"))
            candidates = [script_url + ".map"]
            if note:
                candidates.append(_absolute(script_url, note.group(1)))
            for candidate in candidates:
                if _same_origin(entry, candidate) and (candidate, script_url) not in map_candidates:
                    map_candidates.append((candidate, script_url))

        for candidate, script_url in map_candidates[:4]:
            try:
                response = ctx.client.request("GET", candidate, safety=self.spec.safety)
            except Exception:
                continue
            outcome.observations.append(self.observe(ctx, response, url=candidate))
            if response.status != 200:
                continue
            try:
                payload = json.loads(response.body[:2_000_000].decode("utf-8", "replace"))
            except ValueError:
                continue
            if not isinstance(payload, dict) or "mappings" not in payload:
                continue
            sources = [str(item) for item in payload.get("sources", [])][:20]
            outcome.endpoints.append(self.endpoint(candidate, response=response, source=self.spec.id, value=0.7))
            outcome.findings.append(
                self.finding(
                    kind="source-map-published",
                    title="Source map is publicly readable",
                    detail=(
                        f"{candidate} is served with {len(sources)} source reference(s), exposing the "
                        f"original tree behind {script_url}."
                    ),
                    severity=Severity.medium,
                    confidence=0.9,
                    location=candidate,
                    tags=("artifacts", "disclosure"),
                )
            )
        return outcome


@register
class DependencyManifestProbe(Probe):
    spec = ProbeSpec(
        id="dependency-manifest",
        name="Published dependency manifests",
        safety=SafetyClass.read_only,
        targets=(VulnClass.infra,),
        cost=Cost(requests=11, seconds=1.5),
        description="Checks well-known manifest paths for build metadata and dependency inventory.",
        cwe="CWE-200",
        remediation="Serve manifests from the build pipeline, not from the web root.",
        sensitivity=0.75,
        false_positive_rate=0.02,
        default_enabled=False,
    )

    MAX_REQUESTS = 11

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        origin = f"{urlsplit(ctx.target.url).scheme}://{urlsplit(ctx.target.url).netloc}"
        outcome = ProbeOutcome()
        exposed = 0
        requests = 0
        for path, ecosystem in _MANIFESTS[: self.MAX_REQUESTS]:
            url = origin + path
            try:
                response = ctx.client.request("GET", url, safety=self.spec.safety)
            except Exception:
                continue
            requests += 1
            if response.status != 200 or not response.body:
                continue
            text = response.body.decode("utf-8", "replace")
            if len(text) < 12:
                continue
            outcome.observations.append(self.observe(ctx, response, url=url))
            outcome.endpoints.append(self.endpoint(url, response=response, source=self.spec.id, value=0.6))
            exposed += 1
            count = _dependency_count(ecosystem, text)
            outcome.findings.append(
                self.finding(
                    kind=f"dependency-manifest:{ecosystem}",
                    title=f"{ecosystem} manifest is publicly readable",
                    detail=(
                        f"{url} is served directly. Approximate dependency entries: {count}. "
                        "This discloses the supply chain and often exact versions."
                    ),
                    severity=Severity.low,
                    confidence=0.85,
                    location=url,
                    tags=("artifacts", "supply-chain"),
                )
            )
        outcome.cost = Cost(requests=requests)
        if exposed == 0:
            outcome.skipped = "no dependency manifests were served"
        return outcome


def _dependency_count(ecosystem: str, text: str) -> int:
    try:
        if ecosystem == "npm":
            payload = json.loads(text)
            deps = payload.get("dependencies") or {}
            dev = payload.get("devDependencies") or {}
            return len(deps) + len(dev)
        if ecosystem in {"composer"}:
            payload = json.loads(text)
            return len(payload.get("require") or {}) + len(payload.get("require-dev") or {})
    except ValueError:
        pass
    if ecosystem in {"pip", "go", "yarn", "bundler", "cargo"}:
        return sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith(("#", "//")))
    if ecosystem in {"npm-lock", "composer-lock"}:
        return text.count('"version"')
    return 1


@register
class CachePoisoningSurfaceProbe(Probe):
    spec = ProbeSpec(
        id="cache-poisoning-surface",
        name="Cache trust surface",
        safety=SafetyClass.read_only,
        targets=(VulnClass.infra, VulnClass.headers),
        cost=Cost(requests=4, seconds=0.8),
        description="Tests whether forwarding headers are reflected into a cacheable response.",
        cwe="CWE-444",
        remediation="Do not reflect forwarding headers; key caches on the canonical host and strip untrusted headers at the edge.",
        sensitivity=0.7,
        false_positive_rate=0.12,
        default_enabled=False,
    )

    CANARY = "hcvf-canary.invalid"

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        entry = ctx.target.url
        outcome = ProbeOutcome()
        requests = 0
        for header in _TRUST_HEADERS:
            try:
                response = ctx.client.request(
                    "GET",
                    entry,
                    headers=((header, self.CANARY),),
                    safety=self.spec.safety,
                )
            except Exception:
                continue
            requests += 1
            outcome.observations.append(self.observe(ctx, response, url=entry, headers=((header, self.CANARY),)))
            body = response.body.decode("utf-8", "replace").lower()
            reflected = self.CANARY in body or self.CANARY in json.dumps(dict(response.headers)).lower()
            if not reflected:
                continue
            cache_headers = {name: response.header(name) for name in _CACHE_HEADERS if response.header(name)}
            outcome.findings.append(
                self.finding(
                    kind=f"forwarded-header-reflected:{header.lower()}",
                    title=f"{header} is reflected into the response",
                    detail=(
                        f"Supplying {header}: {self.CANARY} changes the response. "
                        f"Cache indicators: {cache_headers or 'none'}. If the response is cacheable, "
                        "an attacker can poison the cached copy for other users."
                    ),
                    severity=Severity.medium if cache_headers else Severity.low,
                    confidence=0.6 if cache_headers else 0.45,
                    location=entry,
                    tags=("cache", "injection"),
                )
            )
            outcome.cost = Cost(requests=requests)
            return outcome
        outcome.cost = Cost(requests=requests)
        return outcome
