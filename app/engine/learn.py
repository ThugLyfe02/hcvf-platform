"""Self-evolution: the part that makes hunt N+1 better than hunt N.

Two loops, both persisted:

* **Belief update** — every probe result moves the posterior over vulnerability
  classes and the Beta bandit over probe efficacy. This happens per hunt.
* **Strategy evolution** — every few hunts a genetic search over probe sets,
  budgets and route biases is scored against realised yields, and the best
  genome replaces the current one.

Nothing here needs a model provider, which is deliberate: the system must get
better on a plane, in an air-gapped network, and on a customer's laptop.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.engine.bandit import ProbeBandit
from app.engine.bayes import Posterior
from app.engine.evolution import Generation, Genome, evolve, seed_population
from app.engine.executor import HuntResult
from app.engine.probes import registry

MEMORY_SCHEMA = 1


@dataclass
class HuntRecord:
    target: str
    at: str
    findings: int
    requests: int
    probes: list[str]
    evidence_root: str
    seed: int
    halted: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "at": self.at,
            "findings": self.findings,
            "requests": self.requests,
            "probes": self.probes,
            "evidence_root": self.evidence_root,
            "seed": self.seed,
            "halted": self.halted,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> HuntRecord:
        return cls(
            target=str(payload.get("target", "")),
            at=str(payload.get("at", "")),
            findings=int(payload.get("findings", 0) or 0),
            requests=int(payload.get("requests", 0) or 0),
            probes=[str(p) for p in payload.get("probes", []) or []],
            evidence_root=str(payload.get("evidence_root", "")),
            seed=int(payload.get("seed", 0) or 0),
            halted=str(payload.get("halted", "")),
        )


@dataclass
class HuntMemory:
    """Durable state that makes the platform improve across runs and targets."""

    hunts: int = 0
    posterior: dict[str, float] = field(default_factory=dict)
    bandit: dict[str, dict[str, float]] = field(default_factory=dict)
    genome: dict[str, object] = field(default_factory=dict)
    records: list[HuntRecord] = field(default_factory=list)
    schema: int = MEMORY_SCHEMA

    # -- persistence -----------------------------------------------------
    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "hunts": self.hunts,
            "posterior": self.posterior,
            "bandit": self.bandit,
            "genome": self.genome,
            "records": [record.to_dict() for record in self.records],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object] | None) -> HuntMemory:
        payload = payload or {}
        return cls(
            hunts=int(payload.get("hunts", 0) or 0),
            posterior=dict(payload.get("posterior", {}) or {}),
            bandit={
                str(k): {str(kk): float(vv) for kk, vv in (v or {}).items()}
                for k, v in (payload.get("bandit", {}) or {}).items()
            },
            genome=dict(payload.get("genome", {}) or {}),
            records=[HuntRecord.from_dict(r) for r in payload.get("records", []) or []],
        )

    def save(self, path: Path | str) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: Path | str) -> HuntMemory:
        source = Path(path)
        if not source.exists():
            return cls()
        try:
            return cls.from_dict(json.loads(source.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, TypeError, ValueError):
            return cls()

    # -- derived views ---------------------------------------------------
    def posterior_state(self) -> Posterior:
        return Posterior.from_dict(self.posterior)

    def bandit_state(self) -> ProbeBandit:
        return ProbeBandit.from_dict(self.bandit)

    def current_genome(self, known_probes: list[str]) -> Genome:
        if self.genome:
            return Genome.from_dict(self.genome, known_probes)
        from app.engine.evolution import Genome as G

        return G(probes=tuple(sorted(known_probes)))


@dataclass
class LearningReport:
    hunts: int
    evolved: bool
    genome_before: dict[str, object]
    genome_after: dict[str, object]
    best_fitness: float
    generations: int
    notes: list[str]
    posterior: dict[str, float]

    def to_dict(self) -> dict[str, object]:
        return {
            "hunts": self.hunts,
            "evolved": self.evolved,
            "genome_before": self.genome_before,
            "genome_after": self.genome_after,
            "best_fitness": round(self.best_fitness, 4),
            "generations": self.generations,
            "notes": self.notes,
            "posterior": self.posterior,
        }


def _fitness_factory(bandit: ProbeBandit, known: list[str]):
    """Fitness = expected yield x surface coverage x efficiency.

    An earlier version scored mean reward only, and the GA promptly collapsed to
    whichever single probe had the best record — a hunt that finds one thing and
    never looks anywhere else. Coverage is therefore a first-class term, and
    undersized genomes are penalised rather than trusted.
    """

    all_classes: set[str] = set()
    for probe_id in known:
        cls = registry().get(probe_id)
        if cls is not None:
            all_classes.update(target.value for target in cls.spec.targets)
    total_classes = max(1, len(all_classes))
    trials_total = sum(arm.trials for arm in bandit.arms.values()) or 1.0

    def fitness(genome: Genome) -> float:
        probes = [pid for pid in genome.probes if pid in known]
        if not probes:
            return 0.0
        means = [bandit.arm(pid).mean for pid in probes]
        expected_yield = sum(means) / len(means)

        covered: set[str] = set()
        demand = 0
        for pid in probes:
            cls = registry().get(pid)
            if cls is None:
                continue
            covered.update(target.value for target in cls.spec.targets)
            demand += cls.spec.cost.requests
        coverage = len(covered) / total_classes

        efficiency = 1.0 / (1.0 + demand / 40.0)
        exploration = 0.08 * max(0.0, 1.0 - trials_total / 60.0)
        size_penalty = 1.0 if len(probes) >= 4 else 0.55

        score = 0.52 * expected_yield + 0.30 * coverage + 0.18 * efficiency + exploration
        return score * size_penalty

    return fitness


def learn(
    result: HuntResult,
    memory: HuntMemory,
    *,
    known_probes: list[str] | None = None,
    evolution_interval: int = 2,
    population_size: int = 14,
    generations: int = 6,
) -> tuple[HuntMemory, LearningReport]:
    """Fold one hunt's outcome into durable memory, evolving when due."""

    known = known_probes or list(registry().keys())
    memory.hunts += 1
    memory.posterior = result.posterior_after.to_dict()
    memory.bandit = result.bandit_after.to_dict()

    requests = sum(run.cost.requests for run in result.probe_runs)
    memory.records.append(
        HuntRecord(
            target=result.target.origin,
            at=result.finished_at,
            findings=len(result.findings),
            requests=requests,
            probes=[run.probe_id for run in result.probe_runs],
            evidence_root=result.evidence_root,
            seed=result.plan.seed,
            halted=result.halted,
        )
    )
    memory.records = memory.records[-200:]

    before = dict(memory.genome) or Genome(probes=tuple(sorted(known))).to_dict()
    notes: list[str] = []
    evolved = False
    best_fitness = 0.0
    generation_count = 0

    if memory.hunts % max(1, evolution_interval) == 0 and memory.records:
        rng = random.Random(memory.hunts * 7919 + 17)
        bandit = memory.bandit_state()
        population = seed_population(population_size, known, rng)
        # Anchor the search with the full default catalog and the incumbent, so
        # a mutation can never win purely by forgetting half the doctrine.
        population.append(Genome(probes=tuple(sorted(known))).normalized(known))
        population.append(memory.current_genome(known))
        history: list[Generation] = evolve(
            population,
            _fitness_factory(bandit, known),
            generations=generations,
            known_probes=known,
            rng=rng,
        )
        generation_count = len(history)
        best = history[-1].best
        best_fitness = history[-1].best_fitness
        current = memory.current_genome(known)
        current_fitness = _fitness_factory(bandit, known)(current)
        if best_fitness > current_fitness:
            memory.genome = best.to_dict()
            evolved = True
            notes.append(
                f"adopted genome with {len(best.probes)} probes (fitness {best_fitness:.3f} vs {current_fitness:.3f})"
            )
        else:
            memory.genome = current.to_dict()
            notes.append(f"kept current genome (fitness {current_fitness:.3f} >= {best_fitness:.3f})")
    else:
        memory.genome = before

    report = LearningReport(
        hunts=memory.hunts,
        evolved=evolved,
        genome_before=before,
        genome_after=dict(memory.genome),
        best_fitness=best_fitness,
        generations=generation_count,
        notes=notes,
        posterior=memory.posterior,
    )
    return memory, report


def probe_leaderboard(memory: HuntMemory, limit: int = 8) -> list[dict[str, object]]:
    bandit = memory.bandit_state()
    rows = []
    for probe_id, mean, trials in bandit.rank()[:limit]:
        rows.append({"probe_id": probe_id, "mean_reward": round(mean, 4), "trials": round(trials, 2)})
    return rows


def summarize_memory(memory: HuntMemory) -> dict[str, object]:
    total_findings = sum(record.findings for record in memory.records)
    return {
        "hunts": memory.hunts,
        "total_findings": total_findings,
        "avg_findings_per_hunt": round(total_findings / memory.hunts, 3) if memory.hunts else 0.0,
        "learned_probes": len(memory.bandit),
        "genome": memory.genome,
        "leaderboard": probe_leaderboard(memory),
        "last_hunt_at": memory.records[-1].at if memory.records else "",
        "now": datetime.now(UTC).isoformat(),
    }
