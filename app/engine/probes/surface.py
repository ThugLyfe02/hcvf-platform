from __future__ import annotations

import json

from app.engine.bayes import VulnClass
from app.engine.graph import endpoint_value
from app.engine.probes.base import Probe, ProbeSpec, register
from app.engine.types import Cost, Endpoint, ProbeContext, ProbeOutcome, SafetyClass, Severity

SPEC_PATHS = ("/openapi.json", "/swagger.json", "/api/openapi.json", "/.well-known/openapi.json")
MAX_ENDPOINTS = 40


@register
class OpenApiSurfaceProbe(Probe):
    """Ingest a published API specification and turn it into surface.

    A spec is the cheapest high-fidelity route map a target will ever hand you:
    documented paths, methods and parameter names. When one is exposed it also
    tells the swarm where *not* to guess.
    """

    spec = ProbeSpec(
        id="openapi-surface",
        name="OpenAPI specification ingestion",
        safety=SafetyClass.read_only,
        targets=(VulnClass.infra,),
        cost=Cost(requests=3, seconds=0.6),
        description="Fetches a published OpenAPI/Swagger document and adds its paths to the route graph.",
        cwe="CWE-497",
        remediation="Publish API specifications only where intended, and keep internal operations out of them.",
        sensitivity=0.7,
        false_positive_rate=0.02,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        outcome = ProbeOutcome()
        found = False

        for path in SPEC_PATHS:
            if found:
                break
            url = f"{ctx.target.origin}{path}"
            response = ctx.client.request("GET", url, safety=self.spec.safety)
            outcome.observations.append(self.observe(ctx, response, note="spec discovery"))
            outcome.cost = outcome.cost + Cost(requests=1, bytes_in=len(response.body))
            if response.status != 200:
                continue
            content_type = response.header("content-type") or ""
            text = response.text(262_144)
            if "json" not in content_type and not text.lstrip().startswith("{"):
                continue
            try:
                document = json.loads(text)
            except (ValueError, TypeError):
                continue
            if not isinstance(document, dict):
                continue
            if "openapi" not in document and "swagger" not in document:
                continue

            paths = document.get("paths")
            if not isinstance(paths, dict):
                continue
            found = True

            for index, (documented_path, operations) in enumerate(sorted(paths.items())):
                if index >= MAX_ENDPOINTS or not isinstance(operations, dict):
                    break
                for method in operations:
                    if str(method).lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                        continue
                    endpoint_url = f"{ctx.target.origin}{documented_path}"
                    outcome.endpoints.append(
                        Endpoint(
                            url=endpoint_url,
                            method=str(method).upper(),
                            source=url,
                            value=min(1.0, endpoint_value(endpoint_url) + 0.2),
                            title=f"documented {str(method).upper()}",
                        )
                    )
                    break

            version = document.get("openapi") or document.get("swagger")
            outcome.findings.append(
                self.finding(
                    kind="openapi-specification-exposed",
                    title="API specification is publicly retrievable",
                    detail=(
                        f"{url} returns an OpenAPI document (version {version}) describing "
                        f"{len(paths)} paths. This is often intentional, but it gives an attacker the "
                        "full route map and parameter names."
                    ),
                    severity=Severity.low,
                    confidence=0.9,
                    location=url,
                    tags=("disclosure",),
                )
            )
        return outcome
