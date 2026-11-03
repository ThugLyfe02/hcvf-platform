# Autonomy

The engine decides *how* to hunt. This layer decides *when* and *where* without a
human in the loop — inside a standing authorization the operator approved.

Autonomy is not "remove the guardrails". It is a different grant: broader in
time, narrower in scope. Everything below is enforced in code and covered by
`tests/unit/test_autonomy.py`.

---

## 1. Standing authorization

`PUT /api/v1/autonomy` installs one policy per tenant:

```json
{
  "enabled": true,
  "target_allowlist": ["https://app.customer.com"],
  "safety_ceiling": "read_only",
  "budget_requests_per_run": 120,
  "max_runs_per_day": 8,
  "min_interval_minutes": 60,
  "quiet_hours_start": 22,
  "quiet_hours_end": 6,
  "timezone": "America/New_York",
  "max_consecutive_failures": 3,
  "min_utility": 0.08,
  "approved_by": "ciso@customer.com",
  "approval_statement": "Continuous validation of the external estate is authorized under ENG-2026-014."
}
```

Non-negotiable properties:

| Property | Enforcement |
|---|---|
| Targets ⊆ tenant's granted targets | `_authorized_allowlist` raises on anything else; autonomy can never widen scope |
| No `destructive` ceiling | rejected at the API, before anything is stored |
| Approval is recorded | enabling without a statement is a 400; the statement, approver, timestamp and SHA-256 are persisted and appear in the status endpoint |
| Global off switch | `AUTONOMY_ENABLED=false` (the default) makes every tick a no-op regardless of policy |
| Kill switch | `POST /kill` disables the policy and cancels in-flight autonomy runs |

Turning autonomy on is therefore two independent acts: the deployment enables the
controller, and a tenant installs an approved policy.

---

## 1a. Two modes (0.7.0)

The controller now has a `mode`:

- **`hunt`** — schedules a campaign directly (the original behaviour).
- **`objective`** — delegates a work objective to the workforce, which
  decomposes it, verifies serious findings and only finishes when acceptance
  criteria pass. See [`OBJECTIVES.md`](OBJECTIVES.md).

Objective mode adds ten rules:

| Rule | Effect |
|---|---|
| `max_objectives_per_day` | daily delegation cap |
| `objective_budget_requests` | budget per delegated objective |
| `objective_template` | fixed doctrine, or `custom`/auto for gap analysis |
| `template_auto` | always choose by gap analysis + rotation |
| `escalation_cooldown_minutes` | how long a blocked template rests |
| `narrow_on_retry` | retry only the criteria that failed |
| `max_active_objectives` | fleet cap across the tenant |
| `daily_objective_requests` | total request budget delegated per day |
| `template_history` | last templates per target, for rotation |
| per-target interval | no target is delegated twice in a row |

Selection is deliberately conservative: a target with an active objective is
skipped, a full fleet blocks delegation entirely, and a target whose
`next_eligible_at` has not arrived is skipped rather than re-delegated.

After a block the controller records the failed criteria in the escalation
decision. Once the cooldown passes, `narrow_on_retry` delegates a **narrow
retry** whose criteria are exactly the ones that failed ? the parts that
passed are not re-run. Every decision stores the alternatives it considered,
so the choice is auditable rather than implied.

## 2. What it actually schedules

`hunt_targets` is the asset inventory. Each target carries `last_run_at`,
`next_eligible_at`, `consecutive_failures`, `runs_total`, `findings_total`.

Every tick picks the eligible target with the highest utility:

```
staleness  = min(1, hours_since_last_run / (4 × min_interval_hours))
risk       = min(1, findings_total / 10)          # historically productive targets matter
novelty    = 1 / (1 + 0.5 × runs_total)           # new targets get a look
penalty    = min(0.9, 0.3 × consecutive_failures)

utility = 0.45·staleness + 0.30·risk + 0.25·novelty − penalty
```

Eligibility is a hard filter, checked before utility:

- policy enabled and global switch on;
- not inside quiet hours (tenant-local, wraps midnight);
- daily run cap not reached (counted from `campaigns.origin = 'autonomy'` since local midnight);
- `next_eligible_at` in the past (per-target interval);
- no `queued`/`running` campaign against the same origin;
- failures below `max_consecutive_failures`.

Any refusal with an operational cause (cap, backoff, threshold, launch failure)
is written to `autonomy_decisions` with a reason — but repeated identical reasons
are deduplicated to one per hour so the table does not fill with noise. Quiet
hours are routine and are not recorded.

---

## 3. It gets better every run

Two mechanisms feed forward into autonomy:

1. **Probe selection.** Before each launch the controller derives a genome from
   `probe_stats` for that host — probes ranked by Beta posterior mean, always
   including discovery, capped at nine. The genome is stored on the campaign and
   handed to the engine, so an autonomous hunt starts from what worked last time
   on that target.
2. **Scheduling.** A target that keeps yielding findings accrues `risk`; one that
   keeps failing accrues `consecutive_failures`, which lowers utility and
   eventually disables it:

```
backoff_minutes = min(1440, base_interval × 2^failures)
```

At `max_consecutive_failures` the target is disabled with a recorded
`action="disable"` decision. A human re-enables it by updating the policy.

---

## 4. Findings aggregate across runs

Autonomy repeats, so repeating must not multiply findings. Each finding has a
stable `fingerprint`; a re-observation increments `occurrences`, updates
`last_seen_at` and `last_run_id`, and does **not** insert a new row.

If the finding had been marked `fixed` or `verified`, a recurrence reopens it as
`open` — regression detection for free. Per-run reporting still works: the run
findings endpoint returns issues whose `run_id` **or** `last_run_id` matches, and
the run itself is resolved first, so campaign and tenant scope are still enforced.

---

## 5. Operating it

```bash
# install / update the standing authorization
curl -X PUT http://localhost:8000/api/v1/autonomy \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-hcvf-key' \
  -d '{"enabled":true,"target_allowlist":["https://app.example.test"],
       "max_runs_per_day":6,"min_interval_minutes":120,
       "approved_by":"you","approval_statement":"Authorized under ENG-014"}'

# what will it do next, and why?
curl http://localhost:8000/api/v1/autonomy -H 'X-API-Key: dev-hcvf-key' | jq
#   → daily_runs_used, in_quiet_hours, targets[] sorted by utility, recent_decisions[]

# run one cycle now (manual go-ahead / testing)
curl -X POST http://localhost:8000/api/v1/autonomy/tick -H 'X-API-Key: dev-hcvf-key'

# stop everything it has in flight
curl -X POST http://localhost:8000/api/v1/autonomy/kill -H 'X-API-Key: dev-hcvf-key'
```

The controller runs inside the scheduler process (`worker/autonomy.py`,
`maybe_tick`), throttled to `AUTONOMY_INTERVAL_SECONDS`; it can also run
standalone as `python -m worker.autonomy`.

---

## 6. Trust boundary, stated plainly

Autonomy may: create campaigns and runs against allowlisted targets, choose
probe sets from learned priors, schedule itself within the caps.

Autonomy may not: add a target, exceed the safety ceiling, run during quiet
hours, exceed the daily cap, act after the policy is paused or killed, or
execute a `destructive` probe ever.

Everything it decides is queryable after the fact, and every hunt it launches
produces the same signed evidence as a manual one. The approval statement and
its hash make "who authorized continuous testing, and when" answerable without
asking anyone to remember.
