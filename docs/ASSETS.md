# Asset inventory

Findings describe issues. Assets describe the surface the issues live on, and
they answer the continuous-validation questions that coverage cannot: what is
new since last week, what has gone stale, and which routes we have only looked at
once.

## How it is built

Every completed objective feeds the inventory from its task outcomes:

- the route each task ran against;
- every endpoint a probe discovered;
- the finding count observed on that route.

A route is counted once per objective (`objective_count`), so the number is a
truthful measure of how often the platform looked. The entry route itself is not
an asset; assets are the surface *around* the entry point.

## Lifecycle

| Field | Meaning |
|---|---|
| `first_seen_at` | first objective that observed the route |
| `last_seen_at` | most recent observation |
| `status` | `active`, or `stale` after 30 days without observation |
| `role` | entry / auth / admin / api / data / other (path heuristics) |
| `objective_count` | how many objectives have observed it |
| `finding_count` | cumulative findings observed on the route |

`mark_stale` flips routes whose last observation is older than the window; it is
callable from the scheduler and idempotent.

## Change feed

`GET /api/v1/assets/changes?days=7&stale_days=30` returns:

- `new`: assets first observed inside the window,
- `stale`: active assets not observed for `stale_days`,
- `vanished`: reserved for surfaces observed before and absent since (see limits).

The console assets page renders the same data with role and status filters.

## Limits, stated honestly

- The inventory records what objectives observed, not a crawl of the whole
  internet; a route never scheduled is never an asset.
- `vanished` requires a complete surface comparison between two objectives. The
  field exists so clients can rely on the shape, but it returns empty until
  objectives record a full surface snapshot rather than per-task observations.
- Staleness is a function of scheduling frequency; a low objective cadence will
  mark healthy routes stale. Tune `stale_days` to the cadence, not the other way
  around.
