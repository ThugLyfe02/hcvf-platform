from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from app.engine.bayes import VulnClass
from app.engine.probes.base import Probe, ProbeSpec, register
from app.engine.types import Cost, ProbeContext, ProbeOutcome, SafetyClass, Severity

_WEAK_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES_", "NULL", "MD5", "EXPORT", "anon")


@register
class TlsPostureProbe(Probe):
    spec = ProbeSpec(
        id="tls-posture",
        name="TLS configuration and certificate",
        safety=SafetyClass.read_only,
        targets=(VulnClass.tls,),
        cost=Cost(requests=1, seconds=0.4),
        description="Validates the certificate chain, protocol version, cipher and expiry.",
        cwe="CWE-326",
        remediation="Serve TLS 1.2+ only, present a valid certificate from a public CA, and renew 30 days before expiry.",
        sensitivity=0.95,
        false_positive_rate=0.01,
    )

    def run(self, ctx: ProbeContext) -> ProbeOutcome:
        if not ctx.target.is_tls:
            outcome = ProbeOutcome()
            outcome.skipped = "target is not HTTPS"
            return outcome

        url = ctx.target.url
        response = ctx.client.request("GET", url, safety=self.spec.safety)
        outcome = ProbeOutcome(
            observations=[self.observe(ctx, response)], cost=Cost(requests=1, bytes_in=len(response.body))
        )
        tls = response.tls
        if tls is None:
            outcome.skipped = "no TLS metadata captured"
            return outcome

        if not tls.verified:
            outcome.findings.append(
                self.finding(
                    kind="invalid-tls-certificate",
                    title="TLS certificate is not trusted",
                    detail=f"The certificate chain failed validation: {tls.error or 'unknown verification error'}.",
                    severity=Severity.high,
                    confidence=0.98,
                    location=url,
                )
            )

        if tls.version in _WEAK_PROTOCOLS:
            outcome.findings.append(
                self.finding(
                    kind="deprecated-tls-version",
                    title=f"Deprecated TLS version negotiated ({tls.version})",
                    detail=f"The handshake completed with {tls.version}, which is no longer considered secure.",
                    severity=Severity.high,
                    confidence=0.97,
                    location=url,
                )
            )

        cipher = tls.cipher.upper()
        weak = [token for token in _WEAK_CIPHER_TOKENS if token in cipher]
        if weak:
            outcome.findings.append(
                self.finding(
                    kind="weak-tls-cipher",
                    title="Weak TLS cipher negotiated",
                    detail=f"Cipher suite {tls.cipher!r} contains weak primitives ({', '.join(weak)}).",
                    severity=Severity.medium,
                    confidence=0.9,
                    location=url,
                )
            )

        if tls.verified and tls.not_after:
            try:
                expires = parsedate_to_datetime(tls.not_after)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=UTC)
                days = (expires - datetime.now(UTC)).days
                if days < 0:
                    outcome.findings.append(
                        self.finding(
                            kind="expired-tls-certificate",
                            title="TLS certificate has expired",
                            detail=f"The certificate expired {abs(days)} days ago ({tls.not_after}).",
                            severity=Severity.high,
                            confidence=0.99,
                            location=url,
                        )
                    )
                elif days < 30:
                    outcome.findings.append(
                        self.finding(
                            kind="tls-certificate-expiring",
                            title="TLS certificate expires soon",
                            detail=f"The certificate expires in {days} days ({tls.not_after}).",
                            severity=Severity.low,
                            confidence=0.95,
                            location=url,
                        )
                    )
            except (TypeError, ValueError):
                pass

        return outcome
