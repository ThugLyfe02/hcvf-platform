# Workers: nine specialists, one job each

A worker is a narrow component with a stated discipline, an explicit refusal
condition, and no authority to accept its own output. The workforce is a
hierarchy of trust:

```
supervisor (owns state, verdict, escalation)
  ├── recon-worker        discovers the surface
  ├── config-worker       headers, TLS, cookies, methods, error pages
  ├── auth-worker         JWT, CORS, session cookies, throttling
  ├── exposure-worker     VCS/env exposure, OpenAPI, security.txt
  ├── surface-worker      redirects, GraphQL
  ├── verifier-worker     independent reproduction of serious claims
  ├── auditor-worker      re-verifies every evidence manifest
  ├── diagnose-worker     explains a failure before it becomes final
  └── report-worker       assembles the deliverable
```

## Capability, not theatre

| Worker | Does | Refuses / fails when |
|---|---|---|
| `recon-worker` | bounded crawl, endpoint extraction | discovery yields no endpoints |
| `config-worker` | one configuration probe on one route | probe budget exhausted |
| `auth-worker` | one identity probe on one route | probe budget exhausted |
| `exposure-worker` | one exposure probe on one route | route no longer resolves |
| `surface-worker` | one request-shape probe | redirect chain exceeds policy |
| `verifier-worker` | re-runs the exact probe against the exact route | cannot reproduce the finding (records `confirmed=False`) |
| `auditor-worker` | re-verifies Merkle roots, HMAC signatures and blobs for **every** prior task | a manifest is missing, a leaf changed, a signature is wrong, a blob is absent |
| `diagnose-worker` | one HEAD, classified into transport / auth wall / 404 / throttle / 5xx | never fails the objective; it explains it |
| `report-worker` | assembles the report from task evidence | never invents conclusions |

## What "more capable" means concretely

- **`auditor-worker` is a gate, not a summary.** A completed report is only
  written if every captured manifest still verifies. Tampering with one leaf
  blocks the objective with the offending task named.
- **`diagnose-worker` changes the failure story.** A failed task is not blocked
  immediately: the workforce first asks *why* with one cheap HEAD, then records
  the classification in the blocked verdict ("authentication wall", "origin is
  failing", "route no longer resolves").
- **`verifier-worker` can refute.** A high/critical claim is reproduced by a
  fresh request; a failed reproduction is recorded, and `min_verified` cannot
  be satisfied by unverified evidence.
- **Coverage planning is a supervisor capability.** After recon, the plan grows
  with route-specific tasks (see [OBJECTIVES.md](OBJECTIVES.md)); workers do
  not get to choose their own scope.

## Why workers cannot accept their own output

Every one of these disciplines produces claims that are easy to overstate: a
header check that "passes" because the request was redirected, a CORS finding
that was a one-off cache artefact, a manifest that was written but never
signed. Separating judgment from production is what makes `completed` mean
something.

## Adding a worker

1. Pick a `TaskKind` (or add one) and the execution primitive it needs.
2. Implement `judge()` — the refusal condition matters more than the happy path.
3. Register it and add it to the worker catalog test.
4. Add one test that proves it refuses.
