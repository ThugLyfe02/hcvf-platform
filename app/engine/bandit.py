"""Thompson sampling over probe efficacy.

A hunt is a sequence of expensive experiments with uncertain payoff. Beta
posteriors over "did this probe produce a confirmed finding" give the planner a
principled explore/exploit rule: early hunts explore broadly, later hunts exploit
whatever has historically paid off *for this target*, while never fully
abandoning a probe (the posterior keeps mass on both outcomes).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class BetaArm:
    alpha: float = 1.0
    beta: float = 1.0

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def trials(self) -> float:
        return self.alpha + self.beta - 2.0

    def sample(self, rng: random.Random) -> float:
        return rng.betavariate(max(self.alpha, 1e-6), max(self.beta, 1e-6))

    def update(self, reward: float, *, decay: float = 0.0) -> None:
        reward = max(0.0, min(1.0, reward))
        self.alpha += reward
        self.beta += 1.0 - reward
        if decay > 0:
            self.alpha = 1.0 + (self.alpha - 1.0) * (1.0 - decay)
            self.beta = 1.0 + (self.beta - 1.0) * (1.0 - decay)


@dataclass
class ProbeBandit:
    arms: dict[str, BetaArm] = field(default_factory=dict)
    decay: float = 0.01

    def arm(self, probe_id: str) -> BetaArm:
        if probe_id not in self.arms:
            self.arms[probe_id] = BetaArm()
        return self.arms[probe_id]

    def sample_scores(self, probe_ids: list[str], rng: random.Random) -> dict[str, float]:
        return {pid: self.arm(pid).sample(rng) for pid in probe_ids}

    def choose(self, probe_ids: list[str], count: int, rng: random.Random) -> list[str]:
        scored = self.sample_scores(probe_ids, rng)
        return sorted(probe_ids, key=lambda pid: scored[pid], reverse=True)[:count]

    def update(self, probe_id: str, reward: float) -> None:
        self.arm(probe_id).update(reward, decay=self.decay)

    def rank(self) -> list[tuple[str, float, float]]:
        return sorted(
            ((pid, arm.mean, arm.trials) for pid, arm in self.arms.items()),
            key=lambda item: item[1],
            reverse=True,
        )

    def to_dict(self) -> dict[str, dict[str, float]]:
        return {pid: {"alpha": arm.alpha, "beta": arm.beta} for pid, arm in self.arms.items()}

    @classmethod
    def from_dict(cls, payload: dict[str, dict[str, float]] | None, *, decay: float = 0.01) -> ProbeBandit:
        bandit = cls(decay=decay)
        for pid, arm in (payload or {}).items():
            bandit.arms[pid] = BetaArm(alpha=float(arm.get("alpha", 1.0)), beta=float(arm.get("beta", 1.0)))
        return bandit
