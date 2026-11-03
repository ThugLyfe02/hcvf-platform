# The agentic layer

This document explains how HCVF decides *what to test*, why the design is
structured as a deliberation rather than a checklist, and exactly where the
mathematics is.

Everything described here is deterministic given `(target, grant, genome,
priors, seed)`. There is no model provider in the decision path. That is a
deliberate constraint: the platform must be able to justify a probe selection to
an auditor, on a plane, without a GPU.

---

## 1. Why deliberate at all?

A fixed probe order has three failure modes:

1. **Waste** — on a hardened target, expensive probes that always come back
   clean consume the budget before the cheap, high-yield ones run.
2. **Blind spots** — the order is written once, by one person, for one mental
   model of "a web app".
3. **No explanation** — when the tool misses something, there is nothing to
   inspect, because nothing decided anything.

The agentic layer replaces a static order with four mechanisms: doctrinal
proposals, cross-critique, principled arbitration, and learning across hunts.

---

## 2. Agents as doctrines

Each agent encodes a narrow theory of where risk lives. Narrow is the point —
broad agents converge on the same generic ranking and the consensus becomes
decorative.

| Agent | Focus classes | Doctrine |
|---|---|---|
| `recon` | infra | Nothing downstream is trustworthy until the surface is mapped |
| `config` | headers, tls, cookies, methods | Misconfiguration is cheap to find and cheap to fix |
| `trust-boundary` | cors, jwt, redirect | Cross-origin and token trust dominate real-world impact |
| `input` | traversal, xss, sqli, ssrf, graphql | Parameters are where attacker-controlled data enters |
| `reliability` | error disclosure, rate limit | Verbose failure and absent throttling are high-signal |
| `risk-officer` | headers, tls, error disclosure | Veto holder: penalises noisy and expensive probes, blocks unsafe ones |

An agent produces `Proposal(probe_id, route, rationale, priority, safety, cost,
expected_gain)`. `route` comes from the attack-surface graph, so the same probe
can be aimed at the most valuable discovered endpoint rather than the root URL.

---

## 3. Cross-critique

> **Updated in 0.5.0.** Critical judgement now happens inside a multi-round
> deliberation with challenges, rebuttals and adjudicated rulings; agents can
> also convene specialists when discovery reveals a surface. The scoring below
> is still the per-agent vote, but it is one voice in a conversation rather than
> the whole mechanism. See [`DELIBERATION.md`](DELIBERATION.md).


Every agent scores **every other agent's** proposal and must state a reason:

```
score = 0.10
      + 0.30 · relevance(agent.focus ∩ probe.targets)
      + 0.25 · route_quality(proposal.route)
      + 0.20 · bandit.mean(probe)
      + 0.15 · efficiency(1 / (1 + cost/4))
```

`RiskOfficer` then subtracts penalties for high false-positive rates (>0.2) and
for probes costing more than a quarter of the budget.

**Self-scoring is excluded.** An agent grading its own proposal is the fastest
way to make consensus meaningless; exclusion is one line in `planner.plan` and a
load-bearing design decision.

Consensus is the weight-averaged mean of non-blocking critiques (`risk-officer`
carries 1.5× weight, `reliability` 0.8×). Any blocker zeroes the proposal.

---

## 4. Arbitration: constraints are filters, not weights

```
hard filters                                  (never negotiable)
  ├─ probe exists and is registered
  ├─ safety_class ≤ grant.safety_ceiling
  ├─ route is covered by the grant
  └─ not a duplicate probe

score = 0.45 · consensus
      + 0.35 · normalised expected information gain
      + 0.20 · Thompson sample for this probe on this host

selection = greedy knapsack under 85% of the request budget,
            discovery first, then descending score
```

The 85% ceiling leaves headroom for redirects and retries. A safety violation is
never traded against a good score — that is why it is a filter. If safety were a
weight, a sufficiently attractive probe could outvote it.

Every rejection is recorded with a reason (`blocked`, `duplicate`, `over budget`,
`route outside scope`), and the whole trace is stored on the run and exposed by
`GET /api/v1/campaigns/{id}/runs/{rid}/plan`.

---

## 5. Expected information gain

Selection treats each probe as an experiment. For a vulnerability class `c` with
prior `p`, a probe has sensitivity `s = P(finding | c)` and false-positive rate
`f = P(finding | ¬c)`. A positive result updates

```
p' = p·s / (p·s + (1-p)·f)
```

and the expected information gain is the reduction in binary entropy:

```
EIG(p) = H(p) − [ P(find)·H(p|find) + P(clean)·H(p|clean) + P(inc)·H(p) ]
```

summed over the classes the probe targets, weighted by business impact
(`bayes.IMPACT`). The planner normalises EIG across proposals to [0,1] before
scoring so it is comparable with consensus and the bandit sample.

This is why the second hunt on the same host differs from the first: the
posterior and the bandit both moved.

---

## 6. Learning loops

### 6.1 Belief update (per hunt)

After each probe, the posterior is updated once (`finding` or `clean`), and the
Beta bandit arm receives a reward derived from the finding's severity and
confidence. Both are persisted (`probe_stats` in the platform, `memory.json` in
the CLI) keyed by `(probe_id, target_host)` so learning is per-target and never
leaks across tenants.

### 6.2 Strategy evolution (every N hunts)

A genome is `(probe set, budget_requests, rps, route_bias, aggression)`. A
generational GA runs tournament selection, uniform crossover and mutation, with
elitism. Fitness is:

```
size_penalty = 1.0 if |probes| ≥ 4 else 0.55

fitness = size_penalty · (
    0.52 · mean bandit reward over the genome's probes
  + 0.30 · fraction of vulnerability classes covered
  + 0.18 · efficiency (fewer requests is better)
  + exploration bonus while trials are few
)
```

An earlier version scored mean reward only. It immediately collapsed to the
single best-performing probe — a hunt that finds one thing and never looks
anywhere else. The coverage term and the size penalty exist because of that
observed failure; the code comment records it so nobody removes them.

Adoption is conservative: the new genome replaces the incumbent only if its
fitness is strictly higher. On a target where every probe fires, the full
catalog wins and the genome stays full — the correct answer, not a bug.

---

## 7. Reproducibility

* `seed` drives one `random.Random` used for bandit sampling and arbitration;
  it is stored on the run (`plan_seed`).
* Probes are executed in plan order; discovery always precedes consumers.
* Probe inputs that must vary are derived from `stable_hash(target, probe_id)`,
  never from `uuid4()` — an earlier version used a UUID for the error-disclosure
  path, which made finding fingerprints differ between identical runs.
* Link extraction is sorted, so set iteration order (hash randomisation) cannot
  change discovery.

**What is *not* reproducible:** network timing, response bodies that change
between requests, and any target-side rate limiting. The *decision* is
reproducible; the target is not. That distinction is why the seed is recorded
next to the evidence root.

---

## 8. What is deliberately absent

- **No LLM in the decision path.** Deterministic, inspectable heuristics beat an
  unexplainable model for an audit-facing product. A model may later propose a
  *spec diff* for a human to approve (triage narrative, remediation PR), never
  an autonomous probe selection.
- **No self-modification of safety policy.** The GA cannot evolve its way past
  the safety ceiling; that constraint lives outside the genome.
- **No unbounded autonomy.** Every hunt is bounded by a grant, a budget and a
  kill switch. "Autonomous" here means *self-directed within a declared scope*,
  which is the only kind of autonomy that is insurable.
