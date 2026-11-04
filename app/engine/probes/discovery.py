from __future__ import annotations

from urllib.parse import urlsplit

from app.engine.bayes import VulnClass
from app.engine.errors import BudgetExceeded, HuntHalted
from app.engine.extract import extract_page
from app.engine.graph import endpoint_value
from app.engine.probes.base import Probe, ProbeSpec, register
from app.engine.types import Cost, Endpoint, ProbeContext, ProbeOutcome, SafetyClass, Severity


@register
class CrawlProbe(Probe):
    """Builds the attack-surface graph the planner routes over.

    Bounded on purpose: one page, then at most ``MAX_CHILDREN`` HEAD requests.
    Crawling depth is a cost decision, not a correctness decision.
    """

    MAX_CHILDREN = 4

    spec = ProbeSpec(
        id="surface-crawl",
        name="Bounded surface discovery",
        safety=SafetyClass.read_only,
        targets=(VulnClass.infra,),
        cost=Cost(requests=5, seconds=1.0),
        description="Extracts links and forms from the entry point and probes the most valuable children.",
        cwe="",
        remediation="Reduce unnecessary surface exposure and remove references to unlinked internal endpoints.",
        sensitivity=0.6,
        false_positive_rate=0.02,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        outgoing = ctx.client.request("GET", ctx.target.url, safety=self.spec.safety)
        outcome = ProbeOutcome(
            observations=[self.observe(ctx, outgoing, note="entry point")],
            cost=Cost(requests=1, bytes_in=len(outgoing.body)),
        )

        page = extract_page(outgoing.text(262144), outgoing.url)
        origin = ctx.target.origin
        discovered: list[Endpoint] = []

        for link in sorted(page.links):
            parts = urlsplit(link)
            if f"{parts.scheme}://{parts.netloc}" != origin:
                continue
            if link.rstrip("/") == ctx.target.url.rstrip("/"):
                continue
            discovered.append(
                Endpoint(
                    url=link,
                    source=outgoing.url,
                    value=endpoint_value(link),
                    title=page.title,
                )
            )

        for form in page.forms:
            action = str(form.get("action") or ctx.target.url)
            inputs = form.get("inputs") or []
            method = str(form.get("method") or "GET").upper()
            query = "&".join(f"{name}=" for name in inputs) if inputs else ""
            if query and "?" not in action:
                action = f"{action}?{query}"
            discovered.append(
                Endpoint(
                    url=action,
                    method=method,
                    source=outgoing.url,
                    value=min(1.0, endpoint_value(action) + 0.25),
                    title=f"form ({method})",
                )
            )

        deduped: dict[str, Endpoint] = {}
        for item in discovered:
            deduped.setdefault(item.url, item)

        ranked = sorted(deduped.values(), key=lambda item: item.value, reverse=True)
        for child in ranked[: self.MAX_CHILDREN]:
            try:
                head = ctx.client.request("HEAD", child.url, safety=self.spec.safety)
            except (BudgetExceeded, HuntHalted):
                # Resource and kill-switch signals must never be swallowed by
                # discovery best-effort handling.
                raise
            except Exception:
                continue
            outcome.observations.append(self.observe(ctx, head, method="HEAD", note="child discovery"))
            outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(head.body))
            outcome.endpoints.append(
                Endpoint(
                    url=child.url,
                    method=child.method,
                    status=head.status,
                    content_type=head.header("content-type") or "",
                    value=endpoint_value(child.url, status=head.status),
                    source=child.source,
                    title=child.title,
                )
            )

        outcome.endpoints.append(
            Endpoint(
                url=outgoing.url,
                status=outgoing.status,
                content_type=outgoing.header("content-type") or "",
                value=endpoint_value(outgoing.url, status=outgoing.status),
                source=outgoing.url,
                title=page.title,
            )
        )
        return outcome


@register
class RateLimitProbe(Probe):
    """Coarse throttle check. Deliberately off by default and low-confidence.

    Absence of a 429 on a handful of requests is weak evidence, so this probe
    reports an observation, not an accusation. It exists mainly to demonstrate
    that load-generating checks are gated behind ``state_changing``.
    """

    REQUESTS = 8

    spec = ProbeSpec(
        id="rate-limit",
        name="Entry-point throttling observation",
        safety=SafetyClass.state_changing,
        targets=(VulnClass.rate_limit,),
        cost=Cost(requests=REQUESTS, seconds=2.0),
        description="Sends a small burst and records whether the server throttles it.",
        cwe="CWE-770",
        remediation="Apply per-identity rate limits on authentication and expensive endpoints.",
        default_enabled=False,
        sensitivity=0.4,
        false_positive_rate=0.3,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        outcome = ProbeOutcome()
        throttled = False
        for index in range(self.REQUESTS):
            response = ctx.client.request("GET", ctx.target.url, safety=self.spec.safety)
            outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(response.body))
            if index == 0:
                outcome.observations.append(self.observe(ctx, response, note="burst start"))
            if response.status == 429:
                throttled = True
                outcome.observations.append(self.observe(ctx, response, note="throttled"))
                break

        if not throttled:
            outcome.findings.append(
                self.finding(
                    kind="no-throttle-observed",
                    title="No throttling observed on the entry point",
                    detail=f"{self.REQUESTS} sequential requests returned without a 429. This is weak evidence and requires manual review of authentication endpoints.",
                    severity=Severity.info,
                    confidence=0.5,
                    location=ctx.target.url,
                    tags=("needs-manual-review",),
                )
            )
        return outcome
