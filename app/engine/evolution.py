"""Genetic search over hunt strategies.

Each hunt produces a *genome*: which probes to favour, how hard to push, where
to bias the route search. Fitness comes from realised yield (confirmed findings
per unit cost) plus information gain. Selection, crossover and mutation are
seeded and therefore reproducible — a hunt can be replayed from its genome and
seed and produce an identical plan.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, replace

ROUTE_BIASES = ("value", "depth", "breadth")


@dataclass(frozen=True, slots=True)
class Genome:
    probes: tuple[str, ...]
    budget_requests: int = 200
    rps: float = 4.0
    route_bias: str = "value"
    aggression: float = 0.4

    def normalized(self, known_probes: list[str]) -> Genome:
        probes = tuple(sorted({p for p in self.probes if p in known_probes})) or tuple(sorted(known_probes[:3]))
        return replace(
            self,
            probes=probes,
            budget_requests=max(20, min(2000, int(self.budget_requests))),
            rps=max(0.5, min(20.0, float(self.rps))),
            route_bias=self.route_bias if self.route_bias in ROUTE_BIASES else "value",
            aggression=max(0.0, min(1.0, float(self.aggression))),
        )

    def mutate(self, rng: random.Random, known_probes: list[str]) -> Genome:
        probes = list(self.probes)
        action = rng.random()
        if action < 0.34 and known_probes:
            candidate = rng.choice(known_probes)
            if candidate not in probes:
                probes.append(candidate)
        elif action < 0.67 and len(probes) > 1:
            probes.remove(rng.choice(probes))
        elif probes:
            probes[rng.randrange(len(probes))] = rng.choice(known_probes)
        return replace(
            self,
            probes=tuple(sorted(set(probes))),
            budget_requests=int(self.budget_requests * rng.uniform(0.75, 1.35)),
            rps=self.rps * rng.uniform(0.8, 1.25),
            route_bias=rng.choice(ROUTE_BIASES) if rng.random() < 0.15 else self.route_bias,
            aggression=min(1.0, max(0.0, self.aggression + rng.uniform(-0.15, 0.15))),
        ).normalized(known_probes)

    def crossover(self, other: Genome, rng: random.Random, known_probes: list[str]) -> Genome:
        pool = tuple(sorted(set(self.probes) | set(other.probes)))
        size = max(1, min(len(pool), rng.randint(1, len(pool))))
        probes = tuple(sorted(rng.sample(pool, size)))
        return Genome(
            probes=probes,
            budget_requests=int((self.budget_requests + other.budget_requests) / 2),
            rps=(self.rps + other.rps) / 2,
            route_bias=rng.choice((self.route_bias, other.route_bias)),
            aggression=(self.aggression + other.aggression) / 2,
        ).normalized(known_probes)

    def to_dict(self) -> dict[str, object]:
        return {
            "probes": list(self.probes),
            "budget_requests": self.budget_requests,
            "rps": round(self.rps, 3),
            "route_bias": self.route_bias,
            "aggression": round(self.aggression, 3),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object] | None, known_probes: list[str]) -> Genome:
        payload = payload or {}
        probes = payload.get("probes") or []
        return cls(
            probes=tuple(str(p) for p in probes if isinstance(p, str)),  # type: ignore[union-attr]
            budget_requests=int(payload.get("budget_requests", 200) or 200),  # type: ignore[arg-type]
            rps=float(payload.get("rps", 4.0) or 4.0),  # type: ignore[arg-type]
            route_bias=str(payload.get("route_bias", "value")),
            aggression=float(payload.get("aggression", 0.4) or 0.4),  # type: ignore[arg-type]
        ).normalized(known_probes)


@dataclass(frozen=True, slots=True)
class Generation:
    index: int
    best: Genome
    best_fitness: float
    mean_fitness: float
    population: tuple[Genome, ...]


def default_fitness(
    genome: Genome, *, findings: float = 0.0, confirmed: float = 0.0, info_gain: float = 0.0, cost: float = 1.0
) -> float:
    """Fitness = evidence-weighted yield per unit cost, plus exploration bonus."""

    evidence = findings + 2.0 * confirmed
    efficiency = evidence / max(1.0, cost)
    diversity = 0.05 * len(genome.probes) / max(1, len(genome.probes) + 1)
    return efficiency + 0.15 * info_gain + diversity


def evolve(
    population: list[Genome],
    fitness,
    *,
    generations: int = 8,
    known_probes: list[str],
    rng: random.Random,
    elitism: int = 2,
    tournament: int = 3,
    mutation_rate: float = 0.3,
) -> list[Generation]:
    """Run a generational GA. ``fitness`` maps Genome -> float."""

    if not population:
        raise ValueError("population must not be empty")
    scored = sorted(((fitness(g), g) for g in population), key=lambda item: item[0], reverse=True)
    history: list[Generation] = []
    current = [g for _, g in scored]

    for index in range(generations):
        scores = sorted(((fitness(g), g) for g in current), key=lambda item: item[0], reverse=True)
        best_score, best_genome = scores[0]
        mean = sum(score for score, _ in scores) / len(scores)
        history.append(
            Generation(
                index=index,
                best=best_genome,
                best_fitness=best_score,
                mean_fitness=mean,
                population=tuple(current),
            )
        )

        next_generation: list[Genome] = [genome for _, genome in scores[:elitism]]
        while len(next_generation) < len(current):

            def pick(scores=scores) -> Genome:
                contenders = rng.sample(scores, min(tournament, len(scores)))
                return max(contenders, key=lambda item: item[0])[1]

            parent_a, parent_b = pick(), pick()
            child = parent_a.crossover(parent_b, rng, known_probes)
            if rng.random() < mutation_rate:
                child = child.mutate(rng, known_probes)
            next_generation.append(child.normalized(known_probes))
        current = next_generation

    return history


def seed_population(size: int, known_probes: list[str], rng: random.Random) -> list[Genome]:
    population: list[Genome] = []
    for _ in range(size):
        count = rng.randint(2, max(2, min(len(known_probes), 8)))
        population.append(
            Genome(
                probes=tuple(sorted(rng.sample(known_probes, count))),
                budget_requests=rng.choice((80, 150, 250, 400)),
                rps=rng.choice((1.0, 2.0, 4.0, 8.0)),
                route_bias=rng.choice(ROUTE_BIASES),
                aggression=rng.uniform(0.0, 0.8),
            ).normalized(known_probes)
        )
    return population
