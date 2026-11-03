# Objectives: delegating work that actually finishes

An **objective** is a work order: a target, a doctrine template, a budget, a
deadline and — critically — **acceptance criteria**. The workforce decomposes it
into a DAG of surgical tasks, executes them one at a time, verifies every serious
claim with an independent re-run, and only then writes `completed`.

A hunt says "go look". An objective says "come back when this is true".

---

## 1. The contract

```http
POST /api/v1/objectives
{
  "title": "external posture for app.customer.com",
  "target_url": "https://app.customer.com/",
  "template": "posture",
  "budget_requests": 200,
  "per_task_budget": 25,
  "deadline_minutes": 240,
  "criteria": [
    {"kind": "min_probes", "value": 4},
    {"kind": "min_endpoints", "value": 2},
    {"kind": "finding_absent", "key": "missing-hsts"}
  ]
}
```

The response is a queued objective with a plan. From there:

| Call | Effect |
|---|---|
| `GET /objectives` | list, filter by status |
| `GET /objectives/{id}` | objective, criteria, plan |
| `GET /objectives/{id}/tasks` | every task, its worker, route and state |
| `GET /objectives/{id}/events` | append-only narrative |
| `POST /objectives/{id}/step` | execute exactly **one** ready task |
| `POST /objectives/{id}/run` | drive forward until terminal or capped |
| `GET /objectives/{id}/report` | criteria results, evidence, findings, verdict |
| `POST /objectives/{id}/cancel` | stop and skip outstanding work |

`POST /step` exists because "surgical" should be demonstrable: an operator can
watch a single task, in isolation, and then reproduce it.

---

## 2. What the criteria mean

| Kind | Satisfied when |
|---|---|
| `finding_present` | evidence contains that finding kind |
| `finding_absent` | it does not |
| `min_probes` | at least N probes ran |
| `min_endpoints` | at least N endpoints were discovered |
| `risk_below` / `risk_above` | the composite risk score is on that side |
| `min_verified` | at least N findings were independently reproduced |

Templates ship defaults that only assert the work happened (`min_probes`,
`min_endpoints`). Outcome criteria are yours to add — and if they are not met,
the objective **blocks with the unmet criterion named**, rather than quietly
"completing".

---

## 3. The workers

| Worker | Discipline | Refusal condition |
|---|---|---|
| `recon-worker` | bounded surface discovery | fails if discovery yields no endpoints |
| `config-worker` | headers, TLS, cookies, methods, errors | — |
| `auth-worker` | cookies, CORS, JWT, throttling | — |
| `exposure-worker` | VCS/env exposure, OpenAPI, security.txt | — |
| `surface-worker` | redirects, GraphQL | — |
| `verifier-worker` | independent reproduction | returns `confirmed=False` when it cannot reproduce |
| `report-worker` | assembles the deliverable | never invents conclusions |

Each worker gets one task, one route and one probe. It cannot widen its own
scope, and it cannot mark its own output accepted — that is the supervisor's job
and, for serious findings, the verifier's.

---

## 4. How completion is decided

```
recon ──► probe ──► probe ──► … ──► report
             │
             └─(high/critical finding)─► verify ──► done
```

1. All tasks reach a terminal state.
2. Every required criterion evaluates true against the persisted evidence.
3. Any `verify` task that could not reproduce its claim has recorded
   `confirmed=False` (the claim is refuted, not silently kept).
4. No task is blocked.

If 1–4 hold, the supervisor writes `completed` and the report. Otherwise the
objective is `blocked` with the exact unmet criteria, or `running` if work
remains. A blocked task is retried up to `max_attempts` before it counts.

Verification tasks are injected automatically for findings with severity `high`
or `critical` and confidence ≥ 0.60. They re-run **the same probe against the
same route** with a fresh request; matching fingerprint means confirmed.

---

## 5. Budgets, deadlines, idempotency

- The objective has a total request budget; each task gets a slice. A task that
  would exceed the remainder blocks instead of overrunning.
- `deadline_at` is checked before every step; expiry blocks with a recorded
  reason.
- Tasks are leased (`300s`) before execution, so two workers cannot run the same
  task.
- `run_step` is safe to call repeatedly: it always picks the next ready task and
  rehydrates evidence from persisted outcomes, so progress survives process
  restarts.

---

## 6. Autonomy, now objective-first

`AutonomyPolicy.mode` selects the behaviour:

| mode | controller does |
|---|---|
| `hunt` | schedules campaigns (previous behaviour) |
| `objective` | delegates an objective and lets the workforce finish it |

In objective mode the controller additionally enforces:

- `max_objectives_per_day` — separate from the run cap;
- `objective_budget_requests` — the delegated budget;
- `objective_template` — or `custom`, in which case the template is chosen by
  **gap analysis**: the doctrine whose probes have the fewest recorded trials on
  that host;
- `escalation_cooldown_minutes` — after a blocked objective, the same template is
  not re-delegated to that target until the cooldown passes;
- one active objective per target, so work is not fragmented.

When an objective finishes, `record_objective_outcome` folds the result into the
target's scheduling state: success resets the failure streak, a block increments
it and writes an `escalate` decision with the cooldown.

---

## 7. Why this is different from "run a scan"

- **A scan ends when the tool stops.** An objective ends when the acceptance
  criteria are satisfied or provably unmet.
- **A scan reports what it saw.** The workforce reports what it proved: serious
  findings have an independent reproduction, and refuted claims are labelled.
- **A scan cannot be audited task by task.** Every task has a worker, a route, a
  budget, attempts and an outcome; every state change is an event.
- **A scan cannot be resumed.** Objectives are durable; work continues after a
  restart at the next ready task.

## 8. Notifications

A terminal objective emits `objective.completed` or `objective.failed` to every
subscribed webhook, signed with the same HMAC scheme as run events and carrying
the objective key, verdict, finding count, verified count, requests used and any
unmet criteria. A delivery failure is retried by the outbox and never changes a
verdict.

## 9. Deliberate limits

- No dynamic worker code execution. Workers are code, not prompts.
- No objective can exceed the tenant's authorized targets or the grant's safety
  ceiling; a template with a forbidden probe is rejected at plan time.
- Verification is *reproduction*, not exploitation: it confirms the observation,
  it does not weaponise it.
