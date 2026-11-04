"""Hunt execution.

The executor is intentionally boring: it walks the plan, enforces the budget,
seals evidence, and never decides anything. Decisions live in the planner; this
module exists to make those decisions observable and reproducible.
"""

from __future__ import annotations

import random
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.engine.bandit import ProbeBandit
from app.engine.bayes import Posterior
from app.engine.budget import Budget, KillSwitch
from app.engine.errors import BudgetExceeded, EngineError, HuntHalted
from app.engine.evidence import (
    EvidenceBundle,
    EvidenceStore,
    InMemoryEvidenceStore,
    seal_bundle,
    verification_key_from_env,
)
from app.engine.evolution import Genome
from app.engine.http import GuardedHttpClient, RateLimiter
from app.engine.planner import HuntPlan, HuntPlanner
from app.engine.policy import EgressPolicy
from app.engine.probes import registry
from app.engine.types import (
    Cost,
    Endpoint,
    Finding,
    Observation,
    ProbeContext,
    ScopeGrant,
    Severity,
    Target,
    stable_hash,
)

#: Probes whose whole purpose is to expand the surface map. Planning re-runs
#: once the last of them has executed, so specialists deliberate on real routes.
DISCOVERY_PROBES = frozenset({"surface-crawl", "openapi-surface"})


@dataclass
class ProbeRun:
    probe_id: str
    status: str
    findings: int = 0
    cost: Cost = field(default_factory=Cost)
    skipped: str = ""
    error: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "probe_id": self.probe_id,
            "status": self.status,
            "findings": self.findings,
            "requests": self.cost.requests,
            "bytes_in": self.cost.bytes_in,
            "seconds": round(self.cost.seconds, 3),
            "skipped": self.skipped,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class HuntResult:
    target: Target
    plan: HuntPlan
    findings: list[Finding]
    observations: list[Observation]
    endpoints: list[Endpoint]
    posterior_after: Posterior
    bandit_after: ProbeBandit
    budget: dict[str, object]
    evidence_root: str
    manifest: dict[str, object]
    probe_runs: list[ProbeRun]
    started_at: str
    finished_at: str
    halted: str = ""
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.info
        return max((finding.severity for finding in self.findings), key=lambda severity: severity.rank)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target.origin,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "halted": self.halted,
            "evidence_root": self.evidence_root,
            "budget": self.budget,
            "highest_severity": self.highest_severity.value,
            "summary": {
                "probes": len(self.probe_runs),
                "findings": len(self.findings),
                "endpoints": len(self.endpoints),
                "requests": sum(run.cost.requests for run in self.probe_runs),
            },
            "plan": self.plan.to_dict(),
            "probe_runs": [run.to_dict() for run in self.probe_runs],
            "findings": [finding.to_json() for finding in self.findings],
            "posterior_after": self.posterior_after.to_dict(),
            "bandit_after": self.bandit_after.to_dict(),
            "metadata": self.metadata,
        }


_SEVERITY_REWARD = {
    Severity.critical: 1.0,
    Severity.high: 0.9,
    Severity.medium: 0.7,
    Severity.low: 0.4,
    Severity.info: 0.2,
}


class HuntExecutor:
    def __init__(
        self,
        *,
        policy: EgressPolicy | None = None,
        store: EvidenceStore | None = None,
        signer_key: bytes | None = None,
        planner: HuntPlanner | None = None,
    ) -> None:
        self.policy = policy or EgressPolicy()
        self.store = store or InMemoryEvidenceStore()
        self.signer_key = signer_key or verification_key_from_env()
        self.planner = planner or HuntPlanner()

    def run(
        self,
        target: Target,
        grant: ScopeGrant,
        *,
        seed: int = 0,
        budget_requests: int | None = None,
        aggression: float = 0.4,
        posterior: Posterior | None = None,
        bandit: ProbeBandit | None = None,
        genome: Genome | None = None,
        endpoints: Iterable[Endpoint] = (),
        kill_switch: KillSwitch | None = None,
        requested_probes: list[str] | None = None,
        max_routes: int = 6,
    ) -> HuntResult:
        started_at = datetime.now(UTC).isoformat()
        kill_switch = kill_switch or KillSwitch()
        rng = random.Random(seed)

        initial_endpoints = list(endpoints)
        plan = self.planner.plan(
            target,
            grant,
            endpoints=initial_endpoints,
            posterior=posterior,
            bandit=bandit,
            genome=genome,
            budget_requests=budget_requests,
            aggression=aggression,
            seed=seed,
            max_routes=max_routes,
        )

        probes = requested_probes if requested_probes is not None else list(plan.probes)
        known = registry()
        probes = [probe_id for probe_id in probes if probe_id in known]
        # An explicit probe list means "run exactly this" (tests, replay, CLI).
        # Otherwise planning is two-phase: discover, then deliberate again with
        # the real surface map so specialists can be convened on what exists.
        two_phase = requested_probes is None
        replanned = False
        index = 0

        max_requests = max(1, int(budget_requests or plan.budget_requests))
        budget = Budget(
            max_requests=max_requests,
            max_bytes=32_000_000,
            max_seconds=max(5.0, min(900.0, max_requests * 1.5)),
        )
        client = GuardedHttpClient(
            self.policy,
            grant,
            budget,
            kill_switch=kill_switch,
            rate_limiter=RateLimiter(grant.max_rps),
        )
        context = ProbeContext(
            client=client,
            target=target,
            grant=grant,
            rng=rng,
            deadline=budget.max_seconds,
            endpoints=list(initial_endpoints),
        )

        bundle = EvidenceBundle(store=self.store)
        observations: list[Observation] = []
        evidence_by_probe: dict[str, list[str]] = {}
        findings: list[Finding] = []
        probe_runs: list[ProbeRun] = []
        endpoints_by_url: dict[str, Endpoint] = {endpoint.url: endpoint for endpoint in initial_endpoints}
        posterior_state = posterior or Posterior()
        bandit_state = bandit or ProbeBandit()
        halted_reason = ""

        while index < len(probes):
            probe_id = probes[index]
            index += 1
            if kill_switch.halted:
                halted_reason = kill_switch.reason
                break
            probe = known[probe_id]()
            started = time.perf_counter()
            run = ProbeRun(probe_id=probe_id, status="ok")
            try:
                outcome = probe.run(context)
                run.cost = outcome.cost
                run.skipped = outcome.skipped
                if outcome.skipped and not outcome.findings:
                    run.status = "skipped"
            except BudgetExceeded as exc:
                run.status = "budget"
                run.error = str(exc)
                probe_runs.append(run)
                halted_reason = f"budget: {exc}"
                break
            except HuntHalted as exc:
                run.status = "halted"
                run.error = str(exc)
                probe_runs.append(run)
                halted_reason = str(exc)
                break
            except (EngineError, OSError, ValueError) as exc:
                run.status = "error"
                run.error = f"{exc.__class__.__name__}: {exc}"
                probe_runs.append(run)
                bandit_state.update(probe_id, 0.0)
                continue
            finally:
                run.duration_ms = (time.perf_counter() - started) * 1000.0

            for observation in outcome.observations:
                observations.append(observation)
                payload = _observation_payload(observation)
                digest = bundle.add(
                    payload,
                    kind="observation",
                    label=f"{probe_id}:{observation.response.status}:{observation.request.method}",
                    media_type="application/json",
                )
                evidence_by_probe.setdefault(probe_id, []).append(digest)
                body = observation.response.body
                content_type = observation.response.header("content-type") or ""
                if (
                    body
                    and len(body) <= 65_536
                    and any(token in content_type for token in ("text", "json", "xml", "html"))
                ):
                    body_digest = bundle.add(
                        body,
                        kind="response-body",
                        label=f"{probe_id}:{observation.response.status}",
                        media_type=content_type.split(";")[0] or "application/octet-stream",
                    )
                    evidence_by_probe.setdefault(probe_id, []).append(body_digest)

            for endpoint in outcome.endpoints:
                if endpoint.url not in endpoints_by_url:
                    endpoints_by_url[endpoint.url] = endpoint
                    # Discovery feeds the second planning phase: the swarm can
                    # only convene specialists for a surface it can see.
                    context.endpoints.append(endpoint)

            for draft in outcome.findings:
                severity = draft.severity
                finding = _materialize(draft, severity, evidence_by_probe.get(probe_id, [])[:5])
                findings.append(finding)
                run.findings += 1

            observed = "finding" if outcome.findings else "clean"
            posterior_state = posterior_state.update(known[probe_id].spec.model(), observed)
            best = max((_SEVERITY_REWARD[f.severity] for f in outcome.findings), default=0.0)
            bandit_state.update(probe_id, best * max((f.confidence for f in outcome.findings), default=1.0))
            probe_runs.append(run)

            remaining_discovery = [candidate for candidate in probes[index:] if candidate in DISCOVERY_PROBES]
            if (
                two_phase
                and not replanned
                and probe_id in DISCOVERY_PROBES
                and not remaining_discovery
                and len(context.endpoints) > len(initial_endpoints)
            ):
                # The surface is now measured. Deliberate again, with the routes
                # that actually exist, and let the swarm convene specialists.
                replanned = True
                replan = self.planner.plan(
                    target,
                    grant,
                    endpoints=context.endpoints,
                    posterior=posterior_state,
                    bandit=bandit_state,
                    genome=genome,
                    budget_requests=budget_requests,
                    aggression=aggression,
                    seed=seed,
                    max_routes=max_routes,
                )
                executed = {probe_run.probe_id for probe_run in probe_runs}
                probes = [candidate for candidate in replan.probes if candidate not in executed]
                index = 0
                plan = replan

        metadata = {
            "engine": "hcvf",
            "plan_seed": seed,
            "grant_origin": grant.origin,
            "grant_approver": grant.approver,
            "grant_evidence": grant.evidence_sha256,
            "safety_ceiling": grant.max_safety.name,
            "planning_phases": 2 if replanned else 1,
            "requests_sent": client.requests_sent,
            "halted": halted_reason,
        }
        manifest = (
            seal_bundle(bundle, key=self.signer_key, metadata=metadata)
            if bundle.entries
            else {
                "format": "hcvf-evidence/v1",
                "root": "",
                "leaf_count": 0,
                "entries": [],
                "metadata": metadata,
            }
        )

        return HuntResult(
            target=target,
            plan=plan,
            findings=findings,
            observations=observations,
            endpoints=list(endpoints_by_url.values()),
            posterior_after=posterior_state,
            bandit_after=bandit_state,
            budget=budget.snapshot(),
            evidence_root=str(manifest.get("root", "")),
            manifest=manifest,
            probe_runs=probe_runs,
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            halted=halted_reason,
            metadata=metadata,
        )


def _materialize(draft, severity: Severity, evidence: list[str]) -> Finding:
    fingerprint = stable_hash(
        {
            "probe": draft.probe_id,
            "kind": draft.kind,
            "location": draft.location,
            "title": draft.title,
        }
    )[:32]
    return Finding(
        id=fingerprint[:16],
        fingerprint=fingerprint,
        probe_id=draft.probe_id,
        kind=draft.kind,
        title=draft.title,
        detail=draft.detail,
        severity=severity,
        confidence=round(max(0.0, min(1.0, draft.confidence)), 3),
        cwe=draft.cwe,
        remediation=draft.remediation,
        location=draft.location,
        tags=draft.tags,
        evidence=tuple(evidence),
        first_seen=datetime.now(UTC).isoformat(),
    )


def _observation_payload(observation: Observation) -> bytes:
    return _json_bytes(observation.to_json())


def _json_bytes(payload: object) -> bytes:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
