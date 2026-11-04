"""Bayesian probe selection.

Most scanners decide what to run with a static list. HCVF treats probe selection
as an experimental-design problem: each probe is an *observation* that shifts a
posterior over vulnerability classes, and the planner spends its budget where
the expected reduction in uncertainty is highest.

The model is deliberately small and auditable — one independent Bernoulli per
vulnerability class, with a probe supplying a likelihood ratio. That is enough
to make selection principled and, unlike a black box, it can be explained to an
auditor in one paragraph.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum


class VulnClass(StrEnum):
    headers = "headers"
    tls = "tls"
    cookies = "cookies"
    cors = "cors"
    methods = "methods"
    error_disclosure = "error_disclosure"
    jwt = "jwt"
    redirect = "redirect"
    traversal = "traversal"
    graphql = "graphql"
    rate_limit = "rate_limit"
    xss = "xss"
    sqli = "sqli"
    ssrf = "ssrf"
    infra = "infra"


#: 0..1 business impact weight per class. Used to turn a probability vector into
#: a single comparable risk number.
IMPACT: dict[VulnClass, float] = {
    VulnClass.headers: 1.0,
    VulnClass.tls: 2.0,
    VulnClass.cookies: 1.2,
    VulnClass.cors: 1.8,
    VulnClass.methods: 1.0,
    VulnClass.error_disclosure: 0.8,
    VulnClass.jwt: 2.2,
    VulnClass.redirect: 1.5,
    VulnClass.traversal: 2.0,
    VulnClass.graphql: 1.2,
    VulnClass.rate_limit: 1.0,
    VulnClass.xss: 2.2,
    VulnClass.sqli: 2.5,
    VulnClass.ssrf: 2.5,
    VulnClass.infra: 1.5,
}

#: Weak, defensible web-application priors. A hunt that finds nothing still
#: moves these numbers, which is what makes the second hunt smarter.
DEFAULT_PRIOR: dict[VulnClass, float] = {
    VulnClass.headers: 0.55,
    VulnClass.tls: 0.25,
    VulnClass.cookies: 0.45,
    VulnClass.cors: 0.20,
    VulnClass.methods: 0.30,
    VulnClass.error_disclosure: 0.35,
    VulnClass.jwt: 0.15,
    VulnClass.redirect: 0.25,
    VulnClass.traversal: 0.10,
    VulnClass.graphql: 0.10,
    VulnClass.rate_limit: 0.45,
    VulnClass.xss: 0.20,
    VulnClass.sqli: 0.12,
    VulnClass.ssrf: 0.10,
    VulnClass.infra: 0.15,
}


def clamp(p: float, low: float = 1e-6, high: float = 1 - 1e-6) -> float:
    return max(low, min(high, p))


def entropy(p: float) -> float:
    p = clamp(p)
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def binary_kl(posterior: float, prior: float) -> float:
    """KL(Bernoulli(posterior) || Bernoulli(prior))."""

    posterior, prior = clamp(posterior), clamp(prior)
    return posterior * math.log2(posterior / prior) + (1 - posterior) * math.log2((1 - posterior) / (1 - prior))


@dataclass(frozen=True)
class ProbeModel:
    """What a probe is expected to tell us about which classes."""

    probe_id: str
    targets: tuple[VulnClass, ...]
    sensitivity: float = 0.85
    false_positive_rate: float = 0.05

    def posterior_given(self, prior: float, observed: str) -> float:
        prior = clamp(prior)
        s = clamp(self.sensitivity)
        f = clamp(self.false_positive_rate)
        if observed == "finding":
            return clamp(prior * s / (prior * s + (1 - prior) * f))
        if observed == "clean":
            return clamp(prior * (1 - s) / (prior * (1 - s) + (1 - prior) * (1 - f)))
        return prior

    def eig(self, prior: float) -> float:
        """Expected information gain in bits for one class."""

        prior = clamp(prior)
        s = clamp(self.sensitivity)
        f = clamp(self.false_positive_rate)
        p_finding = prior * s + (1 - prior) * f
        p_clean = 1 - p_finding
        # An inconclusive result is possible and carries no information; model
        # it as a small probability so the planner still values cheap probes.
        p_inconclusive = 0.02
        p_finding *= 1 - p_inconclusive
        p_clean *= 1 - p_inconclusive

        expected = (
            p_finding * entropy(self.posterior_given(prior, "finding"))
            + p_clean * entropy(self.posterior_given(prior, "clean"))
            + p_inconclusive * entropy(prior)
        )
        return max(0.0, entropy(prior) - expected)


@dataclass
class Posterior:
    """Independent per-class beliefs plus the operations a planner needs."""

    beliefs: dict[VulnClass, float] = field(default_factory=lambda: dict(DEFAULT_PRIOR))

    def probability(self, vuln: VulnClass) -> float:
        return self.beliefs.get(vuln, DEFAULT_PRIOR.get(vuln, 0.1))

    def update(self, model: ProbeModel, observed: str) -> Posterior:
        updated = dict(self.beliefs)
        for vuln in model.targets:
            updated[vuln] = model.posterior_given(self.probability(vuln), observed)
        return Posterior(updated)

    def risk_score(self) -> float:
        total = sum(IMPACT.values())
        return sum(self.probability(v) * IMPACT[v] for v in IMPACT) / total

    def expected_information_gain(self, model: ProbeModel) -> float:
        return sum(IMPACT.get(v, 1.0) * model.eig(self.probability(v)) for v in model.targets)

    def top(self, limit: int = 5) -> list[tuple[VulnClass, float]]:
        return sorted(self.beliefs.items(), key=lambda kv: kv[1] * IMPACT.get(kv[0], 1.0), reverse=True)[:limit]

    def to_dict(self) -> dict[str, float]:
        return {k.value: round(v, 6) for k, v in self.beliefs.items()}

    @classmethod
    def from_dict(cls, payload: dict[str, float] | None) -> Posterior:
        beliefs = dict(DEFAULT_PRIOR)
        for key, value in (payload or {}).items():
            try:
                beliefs[VulnClass(key)] = clamp(float(value))
            except (ValueError, TypeError):
                continue
        return cls(beliefs)
