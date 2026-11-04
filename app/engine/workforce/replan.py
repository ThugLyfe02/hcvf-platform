"""Adaptive planning: choose the next task by expected information gain.

A doctrine plans once. An adaptive objective re-plans after every result: the
posterior over vulnerability classes moves, the surface graph records what has
been covered, and the next assignment is the one with the best value per request
rather than the next item in a fixed list.

The planner is deterministic: ties break on (route, probe), so the same seed and
the same observations produce the same plan. That matters for replay and for
tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.engine.bayes import Posterior, ProbeModel
from app.engine.probes import registry
from app.engine.types import SafetyClass
from app.engine.workforce.coverage import classify_route, normalize_route
from app.engine.workforce.surface import SurfaceGraph
from app.engine.workforce.types import TaskKind, TaskSpec

#: Yields are damped so a single lucky finding does not dominate selection.
MAX_MEMORY_BOOST = 0.6


@dataclass
class Belief:
    """Posterior over vulnerability classes for one objective."""

    posterior: Posterior = field(default_factory=Posterior)
    probes_run: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)
    observations: int = 0

    @classmethod
    def start(cls) -> Belief:
        return cls()

    def observe(self, probe_id: str, findings: tuple[str, ...]) -> None:
        model = _model(probe_id)
        self.probes_run.add(probe_id)
        if model is None:
            return
        observed = "finding" if findings else "clean"
        self.posterior = self.posterior.update(model, observed)
        self.probes_run |= {probe_id}
        self.findings |= {finding for finding in findings if finding}
        self.observations += 1

    def information_gain(self, probe_id: str) -> float:
        model = _model(probe_id)
        if model is None:
            return 0.0
        return self.posterior.expected_information_gain(model)

    def top(self, limit: int = 3) -> list[tuple[str, float]]:
        return [(vuln.value, round(probability, 4)) for vuln, probability in self.posterior.top(limit)]

    def to_dict(self) -> dict[str, object]:
        return {
            "posterior": self.posterior.to_dict(),
            "top": self.top(5),
            "probes_run": sorted(self.probes_run),
            "findings": sorted(self.findings),
            "observations": self.observations,
        }


_MODELS: dict[str, ProbeModel] = {}


def _model(probe_id: str) -> ProbeModel | None:
    cached = _MODELS.get(probe_id)
    if cached is not None:
        return cached
    probe = registry().get(probe_id)
    if probe is None:
        return None
    model = probe.spec.model()
    _MODELS[probe_id] = model
    return model


def belief_from_outcomes(outcomes) -> Belief:
    """Reconstruct the belief from persisted task outcomes."""

    belief = Belief.start()
    for outcome in outcomes:
        probes = tuple(getattr(outcome, "probes_run", ()) or ())
        if not probes:
            continue
        kinds = tuple(finding.kind for finding in getattr(outcome, "findings", ()) or ())
        for probe_id in probes:
            belief.observe(probe_id, kinds if probe_id in {finding.probe_id for finding in outcome.findings} else ())
    return belief


@dataclass(frozen=True, slots=True)
class Candidate:
    route: str
    probe_id: str
    score: float
    information_gain: float
    value: float
    memory_boost: float

    def to_dict(self) -> dict[str, object]:
        return {
            "route": self.route,
            "probe": self.probe_id,
            "score": round(self.score, 4),
            "information_gain": round(self.information_gain, 4),
            "value": round(self.value, 4),
            "memory_boost": round(self.memory_boost, 4),
        }


def score_candidates(
    graph: SurfaceGraph,
    belief: Belief,
    *,
    allowed_probes: tuple[str, ...],
    known: set[tuple[str, str]] | None = None,
    memory: dict[tuple[str, str], float] | None = None,
    limit: int = 24,
) -> list[Candidate]:
    """Rank unexplored (route, probe) pairs by expected value of the request."""

    allowed = set(allowed_probes)
    known = known or set()
    memory = memory or {}
    candidates: list[Candidate] = []
    for node, probe_id in graph.frontier(tuple(allowed), limit=limit):
        if (node.route, probe_id) in known:
            continue
        model = _model(probe_id)
        if model is None:
            continue
        gain = belief.information_gain(probe_id)
        boost = min(MAX_MEMORY_BOOST, max(0.0, memory.get((probe_id, node.role), 0.0)))
        saturation = node.saturation()
        score = (0.35 + gain) * node.value * (1.0 + boost) * (1.0 - 0.5 * saturation)
        candidates.append(
            Candidate(
                route=node.route,
                probe_id=probe_id,
                score=round(score, 6),
                information_gain=round(gain, 6),
                value=node.value,
                memory_boost=boost,
            )
        )
    candidates.sort(key=lambda item: (-item.score, item.route, item.probe_id))
    return candidates


def plan_adaptive(
    *,
    graph: SurfaceGraph,
    belief: Belief,
    allowed_probes: tuple[str, ...],
    known: set[tuple[str, str]] | None = None,
    memory: dict[tuple[str, str], float] | None = None,
    per_task_budget: int,
    max_tasks: int,
    start_seq: int,
    safety: SafetyClass,
    recon_key: str = "",
) -> tuple[TaskSpec, ...]:
    """Greedy EIG plan: each pick updates the belief, so the next pick adapts."""

    known = set(known or set())
    memory = memory or {}
    allowed = tuple(probe_id for probe_id in allowed_probes if _permitted(probe_id, safety))
    tasks: list[TaskSpec] = []
    cursor = start_seq
    working = Belief(posterior=belief.posterior, probes_run=set(belief.probes_run), findings=set(belief.findings))
    working.observations = belief.observations

    for _ in range(max(0, max_tasks)):
        candidates = score_candidates(graph, working, allowed_probes=allowed, known=known, memory=memory, limit=32)
        if not candidates:
            break
        best = candidates[0]
        probe = registry().get(best.probe_id)
        if probe is None:
            known.add((best.route, best.probe_id))
            continue
        known.add((best.route, best.probe_id))
        cursor += 1
        tasks.append(
            TaskSpec(
                key=f"t{cursor:02d}-eig-{best.probe_id}-{cursor}",
                seq=cursor,
                kind=TaskKind.probe,
                title=f"{probe.spec.name} at {best.route} (EIG {best.information_gain:.2f})",
                worker=_worker_for(best.probe_id),
                probe_id=best.probe_id,
                route=best.route,
                depends_on=(recon_key,) if recon_key else (),
                budget_requests=per_task_budget,
                max_attempts=1,
                safety=probe.spec.safety,
                payload={
                    "adaptive": True,
                    "expected_information_gain": round(best.information_gain, 4),
                    "score": round(best.score, 4),
                    "role": classify_route(best.route),
                },
            )
        )
        # The plan assumes a clean result for the next pick: if the probe finds
        # something, the posterior moves again and the next expansion re-ranks.
        working.observe(best.probe_id, ())
    return tuple(tasks)


def _permitted(probe_id: str, safety: SafetyClass) -> bool:
    probe = registry().get(probe_id)
    return probe is not None and probe.spec.safety <= safety


def _worker_for(probe_id: str) -> str:
    from app.engine.workforce.decompose import WORKER_BY_PROBE

    return WORKER_BY_PROBE.get(probe_id, "config-worker")


def belief_to_surface_observation(outcome) -> tuple[str, tuple[str, ...], tuple[str, ...], float]:
    return (
        normalize_route(getattr(outcome, "route", "") or ""),
        tuple(getattr(outcome, "probes_run", ()) or ()),
        tuple(finding.kind for finding in getattr(outcome, "findings", ()) or ()),
        float(getattr(outcome, "risk", 0.0) or 0.0),
    )
