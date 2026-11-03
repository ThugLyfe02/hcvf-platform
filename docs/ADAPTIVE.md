# Adaptive planning: choose the next request, not the next item

A doctrine plans once and executes a list. An adaptive objective re-plans after
every result. That difference is the whole point: on a real surface, the most
valuable next request depends on what the last one revealed.

```
recon ──► probe ──► re-plan ──► probe ──► re-plan ──► ... ──► audit ──► report
             │           ▲
             └── finding ┘   posterior moves, surface graph updates,
                             next pick = best value per request
```

## 1. What the planner sees

Three inputs, all built from the objective's own history:

| Input | Source | Meaning |
|---|---|---|
| Surface graph | recon endpoints, task routes, observed findings | which routes exist, what role they play, what has been probed |
| Belief state | task outcomes | posterior over 15 vulnerability classes |
| Memory | `objective_memory` | what has yielded on this host before |

Nothing is read from a global cache or another tenant. Two objectives on the
same host cannot contaminate each other's reasoning; only `objective_memory`
is deliberately cross-objective, and it is scoped by tenant and host.

## 2. The surface graph

`app/engine/workforce/surface.py` builds a node for every discovered route and
every implied ancestor (`/admin/users` implies `/admin`, which is often the
more interesting route). Nodes carry:

- `role`: entry / auth / admin / api / data / other (from the path);
- `value`: role-weighted worth, from the same heuristic the hunt engine uses;
- `probes`: which probes already ran there;
- `finding_kinds` and `risk`: what was actually observed;
- `saturation`: coverage of the role's expected probe set.

Selection uses value, saturation and observed risk together. A high-value route
that has been probed four times is less interesting than a high-value route that
has been probed once.

## 3. The belief state

Each probe has a `ProbeModel` (sensitivity, false-positive rate, target classes).
Observing a result updates the posterior:

- finding -> `P(class) = prior*s / (prior*s + (1-prior)*f)`
- clean -> `P(class) = prior*(1-s) / (prior*(1-s) + (1-prior)*(1-f))`

`expected_information_gain` is the entropy reduction weighted by impact. The
planner scores each candidate as:

```
score = (0.35 + EIG) * route_value * (1 + memory_boost) * (1 - 0.5 * saturation)
```

The `0.35` floor keeps cheap, low-information probes competitive so the planner
does not starve on one class. `memory_boost` is capped at `0.6`: memory biases,
it does not dictate.

## 4. Determinism and replay

Ties break on `(route, probe)`; the planner takes no randomness, uses no clock.
The same observations produce the same plan, which is why the demo output and
the tests can assert exact task keys and EIG ordering.

## 5. Memory that learns

After a terminal objective, `memory_service.record_objective` folds each task's
outcome into a recipe row per `(tenant, host, template, probe, route role)`:

```
weighted = findings + 1.5*verified - 1.2*refuted
score    = clamp(weighted / attempts / 2, 0, 0.6)
```

A probe that finds something on `/auth` routes is tried earlier next time on
that host. A probe whose claims are routinely refuted is discounted. Memory is
readable at `GET /api/v1/memory`.

## 6. Artifacts

Every terminal objective writes signed `report.sarif` and `report.md` next to
its evidence. Both are also served by the API with `X-HCVF-Signature` and
`X-HCVF-SHA256` headers, so a reviewer can verify the bytes they downloaded
against the evidence key.

`GET /objectives/{id}/diff` compares finding kinds against the previous
completed objective on the same target: `new`, `fixed`, `recurring`.

## 7. Limits, stated honestly

- The planner optimizes for information gain, not for attacker paths; it is a
  validation prioritizer, not an exploitation engine.
- Memory is per host and template. It is a prior, and a stale prior can be
  wrong; the planner still visits high-value unsaturated routes first.
- The adaptive cap (10 tasks, plus the remaining budget) prevents an adaptive
  objective from becoming an unbounded crawler.
- Determinism is per seed and per observation history; concurrent objectives
  do not share belief.

## 8. Tests

`tests/unit/test_workforce_adaptive.py` (13) covers graph construction,
saturation, frontier exclusion, belief updates, memorycapping, determinism,
safety filtering and EIG ordering. `tests/unit/test_objectives_api.py` proves
the full loop end to end: adaptive tasks appear in the plan, artifacts are
signed, diff produces new/fixed/recurring sets, and memory is written.
