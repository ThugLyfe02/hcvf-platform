"""Acceptance criteria: parse, evaluate, explain.

Criteria are the difference between "the agents ran something" and "the work is
done". They are evaluated against an evidence bundle assembled from task
outcomes, and every failure names the criterion that was not met.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.engine.workforce.coverage import CoverageState
from app.engine.workforce.types import (
    Criterion,
    CriterionKind,
    CriterionResult,
    FindingLite,
    TaskStatus,
)

#: Severities that must be independently reproduced by default.
DEFAULT_VERIFY_SEVERITIES = ("critical", "high")


@dataclass
class EvidenceBundle:
    """Everything the workforce has observed so far for one objective."""

    findings: dict[str, FindingLite] = field(default_factory=dict)
    probes_run: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    risk: float = 0.0
    verified: set[str] = field(default_factory=set)
    refuted: set[str] = field(default_factory=set)
    requests_used: int = 0
    coverage: CoverageState = field(default_factory=CoverageState)

    def add_findings(self, findings: tuple[FindingLite, ...]) -> None:
        for finding in findings:
            self.findings.setdefault(finding.fingerprint, finding)

    def absorb(self, outcome) -> None:
        self.add_findings(outcome.findings)
        self.probes_run.update(outcome.probes_run)
        self.endpoints.update(outcome.endpoints)
        self.coverage.discover(outcome.endpoints)
        if getattr(outcome, "route", ""):
            self.coverage.record(outcome.route, outcome.probes_run)
        self.requests_used += outcome.requests
        self.risk = max(self.risk, outcome.risk)
        if outcome.confirmed is True:
            for finding in outcome.findings:
                self.verified.add(finding.fingerprint)
        elif outcome.confirmed is False:
            for finding in outcome.findings:
                self.refuted.add(finding.fingerprint)

    def kinds(self) -> set[str]:
        return {finding.kind for finding in self.findings.values()}

    def to_dict(self) -> dict[str, object]:
        return {
            "findings": len(self.findings),
            "kinds": sorted(self.kinds()),
            "probes": sorted(self.probes_run),
            "endpoints": len(self.endpoints),
            "risk": round(self.risk, 2),
            "verified": len(self.verified),
            "refuted": len(self.refuted),
            "requests_used": self.requests_used,
            "coverage": self.coverage.to_dict(),
        }


class CriterionError(ValueError):
    pass


def parse_criteria(payload: list[dict] | None, *, template_criteria: tuple[Criterion, ...]) -> tuple[Criterion, ...]:
    """Merge caller-supplied criteria with a template's defaults."""

    if not payload:
        return template_criteria
    criteria: list[Criterion] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise CriterionError(f"criterion #{index} must be an object")
        raw_kind = str(item.get("kind", "")).strip().lower()
        try:
            kind = CriterionKind(raw_kind)
        except ValueError as exc:
            raise CriterionError(f"unknown criterion kind {raw_kind!r}") from exc
        value = item.get("value", 0.0)
        if kind in {CriterionKind.min_probes, CriterionKind.min_endpoints, CriterionKind.min_verified}:
            value = int(value)
            if value < 1:
                raise CriterionError(f"{raw_kind} must be at least 1")
        elif kind is CriterionKind.min_route_coverage:
            value = float(value)
            if not 0.0 <= value <= 1.0:
                raise CriterionError("min_route_coverage must be between 0 and 1")
        elif kind in {CriterionKind.risk_below, CriterionKind.risk_above}:
            value = float(value)
            if not 0.0 <= value <= 100.0:
                raise CriterionError("risk criteria must be between 0 and 100")
        else:
            key = str(item.get("key", "")).strip()
            if not key:
                raise CriterionError(f"{raw_kind} requires a 'key' naming the finding kind")
            value = key
        criteria.append(
            Criterion(
                kind=kind,
                value=value,
                key=str(item.get("key", "")).strip()
                if kind
                not in {
                    CriterionKind.min_probes,
                    CriterionKind.min_endpoints,
                    CriterionKind.min_verified,
                    CriterionKind.risk_below,
                    CriterionKind.risk_above,
                    CriterionKind.min_route_coverage,
                }
                else "",
                label=str(item.get("label", "")).strip(),
                required=bool(item.get("required", True)),
            )
        )
    return tuple(criteria)


def evaluate(criteria: tuple[Criterion, ...], evidence: EvidenceBundle) -> list[CriterionResult]:
    results: list[CriterionResult] = []
    kinds = evidence.kinds()

    for criterion in criteria:
        if criterion.kind is CriterionKind.finding_present:
            key = str(criterion.value)
            satisfied = key in kinds
            results.append(
                CriterionResult(
                    criterion,
                    satisfied,
                    f"{key} observed" if satisfied else f"{key} not observed",
                )
            )
        elif criterion.kind is CriterionKind.finding_absent:
            key = str(criterion.value)
            satisfied = key not in kinds
            results.append(
                CriterionResult(
                    criterion,
                    satisfied,
                    "absent" if satisfied else f"{key} present",
                )
            )
        elif criterion.kind is CriterionKind.min_probes:
            count = len(evidence.probes_run)
            results.append(CriterionResult(criterion, count >= int(criterion.value), f"{count} probes executed"))
        elif criterion.kind is CriterionKind.min_endpoints:
            count = len(evidence.endpoints)
            results.append(CriterionResult(criterion, count >= int(criterion.value), f"{count} endpoints discovered"))
        elif criterion.kind is CriterionKind.risk_below:
            results.append(
                CriterionResult(criterion, evidence.risk < float(criterion.value), f"risk {evidence.risk:.1f}")
            )
        elif criterion.kind is CriterionKind.risk_above:
            results.append(
                CriterionResult(criterion, evidence.risk > float(criterion.value), f"risk {evidence.risk:.1f}")
            )
        elif criterion.kind is CriterionKind.min_route_coverage:
            ratio = evidence.coverage.ratio()
            results.append(
                CriterionResult(
                    criterion,
                    ratio >= float(criterion.value),
                    f"coverage {ratio:.0%} of {len(evidence.coverage.discovered)} discovered route(s)",
                )
            )
        elif criterion.kind is CriterionKind.min_verified:
            count = len(evidence.verified)
            results.append(CriterionResult(criterion, count >= int(criterion.value), f"{count} findings verified"))
        else:  # pragma: no cover - exhaustive by enum
            results.append(CriterionResult(criterion, False, "unknown criterion"))

    return results


def unmet(results: list[CriterionResult]) -> list[str]:
    return [result.criterion.description for result in results if result.criterion.required and not result.satisfied]


def summarise(results: list[CriterionResult]) -> str:
    return "; ".join(f"{'PASS' if r.satisfied else 'FAIL'} {r.criterion.description} ({r.observed})" for r in results)


def needs_verification(
    findings: tuple[FindingLite, ...], *, severities: tuple[str, ...] = ("high", "critical")
) -> tuple[FindingLite, ...]:
    """Findings serious enough that a fresh confirmation run is mandatory."""

    return tuple(finding for finding in findings if finding.severity in severities and finding.confidence >= 0.6)


def evidence_from_tasks(task_rows) -> EvidenceBundle:
    """Rebuild the bundle from persisted task outcomes (service layer)."""

    bundle = EvidenceBundle()
    for row in task_rows:
        if row.get("status") != TaskStatus.done.value:
            continue
        for item in row.get("findings", []):
            finding = FindingLite(
                fingerprint=str(item.get("fingerprint", "")),
                kind=str(item.get("kind", "")),
                severity=str(item.get("severity", "info")),
                confidence=float(item.get("confidence", 0.0)),
                probe_id=str(item.get("probe_id", "")),
                route=str(item.get("route", "")),
            )
            if finding.fingerprint and finding.kind:
                bundle.findings.setdefault(finding.fingerprint, finding)
        bundle.probes_run.update(str(probe) for probe in row.get("probes_run", []))
        bundle.endpoints.update(str(url) for url in row.get("endpoints", []))
        bundle.requests_used += int(row.get("requests", 0) or 0)
        bundle.risk = max(bundle.risk, float(row.get("risk", 0.0) or 0.0))
        if row.get("confirmed") is True:
            for item in row.get("findings", []):
                bundle.verified.add(str(item.get("fingerprint", "")))
        if row.get("confirmed") is False:
            for item in row.get("findings", []):
                bundle.refuted.add(str(item.get("fingerprint", "")))
    return bundle
