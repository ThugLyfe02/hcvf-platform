# Deliberation

How the swarm argues, what it is allowed to change, and how it stops.

The engine no longer asks each agent for one opinion and averages them. Agents
propose **options** (a probe against a specific route), then talk in rounds:
support, oppose, challenge, reply, ruling, withdraw, consensus. The transcript is
stored on the run and readable as Markdown.

---

## 1. What an option is

An option is a concrete instantiation, not a probe in the abstract:

```
security-headers@https://app/api/v1/users?page=1
jwt-posture@https://app/login
exposed-config@https://app/admin
```

This matters because "which probe" is the easy question and "against what" is the
one that decides whether the hunt finds anything. Two agents may propose the same
probe against different routes; the conversation picks between them.

Route choice is doctrinal, not uniform: JWT checks prefer token-issuing paths,
method checks prefer administrative surfaces, header checks prefer pages that
actually render. Ties are broken deterministically per probe so the swarm spreads
across the top routes instead of converging on the homepage.

---

## 2. The protocol

```
Round 1  propose
         ├── every agent submits options from its doctrine
         ├── recon convenes specialists it can justify (auth / graphql / admin)
         └── spawned specialists propose their own options

Round 2+ vote
         ├── every agent scores every option it does not sponsor
         ├── sponsors get a capped advocacy voice (never a self-score)
         ├── devil's advocate challenges the current leader
         ├── sponsor replies with a falsifiable claim
         ├── risk officer rules on the objection (upheld / dismissed)
         └── moderator checks convergence; withdraws options below 0.22 support

Consensus
         └── the budgeted probe set is identical two rounds running,
             and the leader clears the support floor
```

**Why the plan, not the leader.** A single "winner" is a poor convergence target:
several options often score within noise of each other, and demanding a 12% margin
means the room argues forever. What actually matters is that the *allocation* —
which probes, at which routes, within budget — has stopped changing. Two identical
consecutive allocations is a stronger and more honest signal of agreement.

**Bounded and honest.** At most five rounds. If the room does not settle, the
moderator records a forced decision and the dissent, and the hunt proceeds. The
transcript says `no consensus (forced decision, dissent recorded)` rather than
pretending otherwise.

---

## 3. Objections are adjudicated, not counted

| Code | Raised when | Sponsor can resolve it by | Risk officer upholds when |
|---|---|---|---|
| `over_budget` | option cost > ¼ of the budget | accepting withdrawal | always |
| `high_false_positive` | modelled FP rate ≥ 0.20 | showing findings are capped at `info` with manual review | FP rate still ≥ 0.50 |
| `low_information` | expected gain < 0.02 bits | citing recalculated EIG ≥ 0.02 | EIG still below 0.02 |
| `low_route_value` | route quality < 0.15 | showing it is the top route in the graph | not the top route |
| `inefficient_tradeoff` | a cheaper option buys ≥ 80% of the gain | showing the classes are disjoint | classes overlap |
| `unverified_route` | the route has not been observed yet | pointing at scored provenance from discovery | no provenance |

An upheld objection applies a real penalty to the option's support — it is not a
talking point. If that demotes the option out of the budgeted set, it is gone.

---

## 4. The swarm grows to fit the target

Planning runs **twice** on a normal hunt:

1. **Before discovery** — the agents convene on what is known (usually just the
   entry point).
2. **After discovery** — the crawl's route map is injected and the agents
   deliberate again. This is when specialists are convened, because now there is
   something to convene them for.

From a real hunt against the fixture:

```
- **recon** convenes - Convening auth-specialist: an authentication surface is reachable
- **recon** convenes - Convening admin-specialist: an administrative surface is reachable
```

Seven agents became nine. The spawn is a logged utterance with its trigger, so the
transcript explains why a specialist appeared rather than just showing up.

**Safety invariant:** a spawned specialist may introduce work outside the genome
(that is the point of discovery), but it can never exceed the grant's safety
ceiling. The conversation may discover new work; it can never discover new
authority.

---

## 5. Convergence, in a real run

```
- **Agents:** `recon`, `config`, `trust-boundary`, `input`, `reliability`,
  `risk-officer`, `devils-advocate`, `auth-specialist`, `admin-specialist`
- **Utterances:** 194
- **Decision seed:** `21`
...
- **moderator** closes **exposed-config@http://127.0.0.1:8099/admin** (`0.61`) —
  Consensus on a plan of 9 probes after 3 rounds (identical allocation two rounds
  running; leader exposed-config@http://127.0.0.1:8099/admin at 0.61).
```

Three rounds, nine agents, a plan that includes probes aimed at `/login`,
`/admin` and the parameterized API rather than everything at the root.

---

## 6. Reading the transcript

**CLI** — every hunt writes `transcript.md` next to the reports:

```bash
python -m app.engine.cli hunt --target http://127.0.0.1:8099/ \
  --authorized --allow-private --out out --seed 21
cat out/transcript.md
```

**API** — the same document, with a machine-readable envelope:

```bash
curl "http://localhost:8000/api/v1/campaigns/<id>/runs/<run>/transcript" \
  -H 'X-API-Key: dev-hcvf-key' | jq '{rounds, converged, agents}'

# readable, without the per-agent vote lines
curl ".../transcript?include_votes=false"
```

**JSON** — the full message list is inside `run.plan.deliberation.messages`,
returned by `GET .../plan`, and rendered in the HTML report under *Deliberation*.

**Determinism** — the conversation has no randomness. Same target, grant, genome,
priors and seed reproduce the same transcript byte for byte, which is what makes
"why did it probe that?" answerable after the fact.

---

## 7. What this is not

- **Not an LLM debate.** Every utterance is grounded in a number (posterior,
  bandit mean, route score, cost, FP rate) and produced by a rule that can be
  inspected. There is no generative model in the loop, so the transcript is a
  reproducible artifact rather than a plausible narrative.
- **Not unbounded.** Five rounds, a fixed budget, a hard safety ceiling, and no
  ability to spawn an agent that can propose outside its declared doctrine.
- **Not theatre.** When nothing is objectionable — a cheap, well-aimed,
  high-gain option — the devil's advocate stays quiet and the transcript records
  only support and dissent that actually exists. Silence is a finding too.
