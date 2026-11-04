"""Tests for cross-hunt learning and strategy evolution."""

from __future__ import annotations

import unittest
from pathlib import Path

from app.engine.evidence import InMemoryEvidenceStore
from app.engine.executor import HuntExecutor
from app.engine.learn import HuntMemory, learn, probe_leaderboard, summarize_memory
from app.engine.policy import EgressPolicy
from app.engine.probes import registry
from app.engine.target import build_grant, parse_target
from tests.fixtures.vulnerable_app import running_fixture


def _run(base_url: str, memory: HuntMemory, seed: int = 3):
    target = parse_target(base_url + "/")
    grant = build_grant(target, max_rps=200)
    executor = HuntExecutor(
        policy=EgressPolicy(allow_private=True),
        store=InMemoryEvidenceStore(),
        signer_key=b"k",
    )
    result = executor.run(
        target,
        grant,
        seed=seed,
        budget_requests=150,
        posterior=memory.posterior_state() if memory.posterior else None,
        bandit=memory.bandit_state() if memory.bandit else None,
        genome=memory.current_genome(list(registry().keys())) if memory.genome else None,
    )
    return learn(result, memory)


class TestLearning(unittest.TestCase):
    def test_memory_accumulates_and_evolves(self) -> None:
        memory = HuntMemory()
        with running_fixture() as base:
            # Run two hunts so the evolution interval triggers.
            memory, first = _run(base, memory, seed=1)
            self.assertEqual(memory.hunts, 1)
            self.assertEqual(first.generations, 0)
            memory, second = _run(base, memory, seed=2)
        self.assertEqual(memory.hunts, 2)
        self.assertGreater(second.generations, 0)
        self.assertTrue(memory.genome)
        self.assertTrue(memory.bandit)
        self.assertGreaterEqual(len(memory.records), 2)

    def test_memory_persists_and_reloads(self) -> None:
        memory = HuntMemory()
        with running_fixture() as base:
            memory, _ = _run(base, memory, seed=1)
        path = Path("build") / "test-memory.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            memory.save(path)
            self.assertTrue(path.exists())
            reloaded = HuntMemory.load(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(reloaded.hunts, memory.hunts)
        self.assertEqual(reloaded.posterior, memory.posterior)
        self.assertEqual(reloaded.genome, memory.genome)

    def test_leaderboard_and_summary(self) -> None:
        memory = HuntMemory()
        with running_fixture() as base:
            memory, _ = _run(base, memory, seed=1)
        rows = probe_leaderboard(memory, limit=3)
        self.assertTrue(rows)
        for row in rows:
            self.assertGreaterEqual(row["mean_reward"], 0.0)
            self.assertLessEqual(row["mean_reward"], 1.0)
        summary = summarize_memory(memory)
        self.assertEqual(summary["hunts"], 1)
        self.assertGreaterEqual(summary["total_findings"], 1)

    def test_learning_is_deterministic_for_same_state(self) -> None:
        with running_fixture() as base:
            memory_a = HuntMemory()
            memory_a, _ = _run(base, memory_a, seed=4)
            memory_b = HuntMemory()
            memory_b, _ = _run(base, memory_b, seed=4)
        self.assertEqual(memory_a.genome, memory_b.genome)
        self.assertEqual(memory_a.posterior, memory_b.posterior)

    def test_missing_memory_file_loads_empty(self) -> None:
        memory = HuntMemory.load(Path("does-not-exist-memory.json"))
        self.assertEqual(memory.hunts, 0)


if __name__ == "__main__":
    unittest.main()
