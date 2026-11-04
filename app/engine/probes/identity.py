from __future__ import annotations

import time

from app.engine.bayes import VulnClass
from app.engine.extract import decode_jwt, find_jwts, split_set_cookie
from app.engine.probes.base import Probe, ProbeSpec, register
from app.engine.types import Cost, ProbeContext, ProbeOutcome, SafetyClass, Severity


@register
class JwtPostureProbe(Probe):
    """Static analysis of any JWT the application hands out.

    Deliberately passive: no token is forged and no signature is attacked. The
    probe reads what the server already sent and flags construction weaknesses
    that are visible without exploitation.
    """

    spec = ProbeSpec(
        id="jwt-posture",
        name="JWT construction posture",
        safety=SafetyClass.read_only,
        targets=(VulnClass.jwt,),
        cost=Cost(requests=1, seconds=0.3),
        description="Decodes issued JWTs and checks alg, exp, kid and key-indirection headers.",
        cwe="CWE-347",
        remediation="Reject alg=none, pin the expected algorithm, set short exp, and never resolve kid/jku from user-controlled input.",
        sensitivity=0.85,
        false_positive_rate=0.03,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        url = ctx.target.url
        response = ctx.client.request("GET", url, safety=self.spec.safety)
        outcome = ProbeOutcome(
            observations=[self.observe(ctx, response)], cost=Cost(requests=1, bytes_in=len(response.body))
        )

        texts: list[str] = [response.text(65536)]
        cookie_header = response.header("set-cookie")
        if cookie_header:
            texts.extend(split_set_cookie([cookie_header]))
        authorization = response.header("authorization")
        if authorization:
            texts.append(authorization)

        tokens = find_jwts(texts)
        if not tokens:
            outcome.skipped = "no JWT observed in cookies, headers or body"
            return outcome

        reported = 0
        for token in tokens[:3]:
            header, payload = decode_jwt(token)
            if header is None:
                continue
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                outcome.findings.append(
                    self.finding(
                        kind="jwt-alg-none",
                        title="JWT accepts alg=none",
                        detail="An issued token declares alg=none, which means the signature is not verified at all.",
                        severity=Severity.critical,
                        confidence=0.97,
                        location=url,
                    )
                )
            kid = header.get("kid")
            if isinstance(kid, str) and ("../" in kid or "..\\" in kid or kid.startswith("/")):
                outcome.findings.append(
                    self.finding(
                        kind="jwt-kid-path-injection",
                        title="JWT kid header looks path-controllable",
                        detail=f"Token header carries kid={kid!r}, which resembles a file path and invites key-confusion attacks.",
                        severity=Severity.high,
                        confidence=0.7,
                        location=url,
                    )
                )
            if any(key in header for key in ("jku", "x5u")):
                outcome.findings.append(
                    self.finding(
                        kind="jwt-remote-key-reference",
                        title="JWT header references a remote key URL",
                        detail="The token header contains jku/x5u, so key retrieval is driven by token data and must be allowlisted server-side.",
                        severity=Severity.medium,
                        confidence=0.6,
                        location=url,
                    )
                )

            if payload is None:
                continue
            exp = payload.get("exp")
            if exp is None:
                outcome.findings.append(
                    self.finding(
                        kind="jwt-missing-exp",
                        title="JWT has no expiry claim",
                        detail="An issued token carries no exp claim, so it remains valid until the signing key rotates.",
                        severity=Severity.medium,
                        confidence=0.85,
                        location=url,
                    )
                )
            else:
                try:
                    if float(exp) < time.time():
                        outcome.findings.append(
                            self.finding(
                                kind="jwt-expired-token-issued",
                                title="Server issued an already-expired JWT",
                                detail=f"The token exp claim is in the past ({int(float(exp))}), which suggests clock or issuance defects.",
                                severity=Severity.low,
                                confidence=0.9,
                                location=url,
                            )
                        )
                except (TypeError, ValueError):
                    pass

            reported += 1
            if reported >= 2:
                break

        if reported == 0:
            outcome.skipped = "tokens present but not decodable as JWT"
        return outcome
