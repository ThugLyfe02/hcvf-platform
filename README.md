# HCVF — Hybrid Concolic Validation Fabric

**An authorized, evidence-grade, agentic validation platform.** Campaigns do not run a fixed checklist: specialist agents propose probes, critique each other's proposals, and a deterministic arbiter spends a bounded budget under a hard safety ceiling. Every outbound request is scope-checked, budgeted, and sealed into a signed Merkle evidence tree.

> **Authorized use only.** Run HCVF only against systems you own or are explicitly authorized to test. The engine refuses to start a hunt without an explicit `--authorized` attestation, and every request is checked against a signed scope grant. This is not a tool for unauthorized scanning.

---

## Autonomy in one paragraph

A tenant installs an approved policy (`PUT /api/v1/autonomy`) naming the targets, safety ceiling, per-run budget, daily cap, minimum interval and quiet hours. From then on the controller decides: it scores every target by staleness, accumulated risk and novelty, subtracts a failure penalty, and launches the best one — but only while the global switch is on, the policy is enabled, the cap is not reached, the target is eligible, nothing is already in flight and it is not quiet hours. It derives the probe set from `probe_stats` for that host, so autonomy inherits the bandit's learning. `GET /api/v1/autonomy` answers "what will it do next, and why"; `POST /kill` stops it and cancels anything in flight. Full detail: [`docs/AUTONOMY.md`](docs/AUTONOMY.md).

## Why this exists

Scanners produce *alerts*. HCVF produces *proof*:

| Problem with normal scanners | HCVF's answer |
|---|---|
| Findings cannot be reproduced later | Every observation is content-addressed; the run has a signed Merkle root and a replayable decision seed |
| Scope is a config file someone edited | Scope is a grant (origin + methods + path + safety class + expiry) checked at plan *and* at execution |
| "Trust me, we only tested what we were allowed to" | Every request is traceable to a grant; egress to private ranges and cloud metadata is blocked at the socket layer |
| One fixed probe list for every target | A bandit learns which probes pay off per host; a genetic search evolves the probe set across hunts |
| You cannot explain why it tested X and not Y | Every proposal, critique, score and rejection is stored and returned by `GET .../plan` |

---

## What it does today

- **Agentic hunt engine** (`app/engine`) — a swarm of seven specialist agents that deliberates in rounds (propose → support/oppose → challenge → reply → ruling → consensus), convenes specialists when discovery exposes a new surface, and stores the full transcript.
- **13 probes** across configuration, transport, identity, input handling and discovery — each with an explicit blast-radius class (`read_only` / `state_changing` / `destructive`).
- **Two learning loops** — Thompson sampling over probe efficacy per host, and a genetic search over hunt genomes (probe set, budget, rate, route bias).
- **Route-of-approach graph** — discovered endpoints are scored and searched so probes aim at the highest-value surface rather than the homepage.
- **SSRF-resistant egress** — DNS resolved once, connected to the validated IP, redirects re-authorized per hop, metadata/link-local/private ranges blocked, datastore ports refused.
- **Signed evidence** — RFC 6962-style Merkle tree with inclusion proofs, HMAC-signed manifests, offline `verify` command.
- **Reports** — SARIF 2.1.0 (GitHub code scanning / DefectDojo), self-contained HTML, Markdown for PR comments.
- **Autonomy** — a standing, bounded authorization lets a controller hunt without being triggered: it picks the next target by staleness/risk/novelty, derives each launch's probe set from what it has learned about that host, backs off failures and stops at a daily cap. Every launch and refusal is recorded with a reason.
- **Issue-level findings** — repeated observations increment `occurrences` instead of duplicating rows, and a finding that reappears after being marked fixed reopens as a regression.
- **Control plane** — FastAPI + PostgreSQL, tenant-scoped API keys (database-authenticated), roles, transactional outbox, run leases and a reaper, finding fingerprints and triage lifecycle.
- **Operational governance** — capability scopes, key rotation, idempotency keys, daily quotas, finding suppressions with expiry, a tamper-evident audit chain, signed webhooks and cron scheduling.
- **Delegated objectives** — a work order with acceptance criteria, decomposed into a task DAG, executed by specialist workers one surgical step at a time, with independent reproduction of serious findings before the objective can complete.
- **Continuity** — per-run risk score and trend, baseline diff against the previous run (new / fixed / recurring), evidence verification endpoint, and a CLI `diff`.
- **Transport hardening** — GCRA rate limiting, request-size limits, log redaction, W3C trace-context propagation, RFC 9457 problem details, liveness/readiness split, and PostgreSQL RLS with an explicit enable path.
- **Observability** — Prometheus metrics for HTTP, hunts, probes and findings; structured JSON logs with run/campaign/tenant context.

### Capability status (honest)

| Area | Status |
|---|---|
| HTTP probes (headers, TLS, cookies, CORS, methods, errors, JWT posture, exposed config, security.txt, crawl) | **GA** |
| Open redirect, GraphQL introspection, rate-limit observation | **Beta** — off by default, `state_changing` |
| Evidence Merkle + signed manifests | **GA** |
| Bandit learning | **GA** |
| Genetic strategy evolution | **Beta** — conservative: only adopts a genome that strictly improves fitness |
| Multi-round deliberation with adjudicated objections and visible transcript | **GA** |
| Objective delegation, task DAG, independent verification, completion verdict | **GA** |
| Scopes, rotation, idempotency, quotas, suppressions, audit chain | **GA** |
| Webhooks (HMAC, retried), cron scheduling, risk trend, baseline diff | **GA** |
| PostgreSQL RLS | **Beta** — policies + `scripts/enable_rls.py`; off until an operator enables it |
| Trace context | **Beta** — W3C propagation and log correlation; no collector bundled |
| Dynamic specialist spawning after discovery | **GA** |
| Autonomous scheduling (standing authorization, caps, quiet hours, backoff, kill switch) | **GA** |
| Finding recurrence + regression reopening | **GA** |
| Fuzzing (coverage-guided, native/Python/Java) | **Planned** |
| Concolic execution (angr) | **Planned** — the name is aspirational until this ships, and the README says so |
| Web console, SSO, SCIM | **Planned** |

---

## Quickstart

### Full stack

```bash
cp .env.example .env
docker compose up --build
curl -s http://localhost:8000/health | jq
```

### Engine only (no database, no broker)

The engine is deliberately standard-library-only, so a hunt runs anywhere Python runs:

```bash
python -m app.engine.cli probes

# Start a deliberately vulnerable local fixture (never expose this)
python -m tests.fixtures.vulnerable_app --port 8099

# Hunt it, with persistence across runs
python -m app.engine.cli hunt \
  --target http://127.0.0.1:8099/ \
  --authorized --allow-private \
  --out out --memory out/memory.json --seed 11
```

You get findings, a decision trace, SARIF/HTML/Markdown reports and an evidence tree:

```
  findings      19
  evidence root 39b8b6b7...36f2d
  seed          11 (replayable)
  hunts=2 evolved=True generations=6
```

Verify the evidence offline — no HCVF code path required beyond the verifier:

```bash
python -m app.engine.cli verify \
  --manifest out/evidence-manifest.json --evidence out/evidence
# signature OK / merkle root OK / blobs OK
```

### API

```bash
# 1. create a campaign (scope-checked against the tenant's authorized targets)
curl -X POST http://localhost:8000/api/v1/campaigns \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-hcvf-key' \
  -d '{"name":"weekly-external","target_url":"http://127.0.0.1:8001/",
       "authorization_attested":true,"safety_ceiling":"read_only","budget_requests":200}'

# 2. execute (writes a run + outbox intent; the relay publishes it)
curl -X POST http://localhost:8000/api/v1/campaigns/<id>/execute -H 'X-API-Key: dev-hcvf-key'

# 3. inspect what the agents decided and why
curl http://localhost:8000/api/v1/campaigns/<id>/runs/<run>/plan -H 'X-API-Key: dev-hcvf-key'

# 4. findings, triage, SARIF
curl 'http://localhost:8000/api/v1/findings?severity=high' -H 'X-API-Key: dev-hcvf-key'
curl -X PATCH http://localhost:8000/api/v1/findings/<id> \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-hcvf-key' \
  -d '{"status":"confirmed","note":"reproduced manually"}'
curl http://localhost:8000/api/v1/campaigns/<id>/runs/<run>/report.sarif -H 'X-API-Key: dev-hcvf-key'
```

---

## How a hunt is decided

```
Grant + target + priors + seed
        │
        ├─ ReconAgent ────────┐
        ├─ ConfigAgent ───────┤  propose probes with a stated rationale
        ├─ TrustBoundaryAgent ┤
        ├─ InputAgent ────────┤
        └─ ReliabilityAgent ──┘
                    │
       every agent critiques every *other* agent's proposals
       (self-scoring is excluded — see docs/AGENTIC.md)
                    │
        RiskOfficer adds false-positive and cost penalties
                    │
        Arbiter: hard constraints → score → budgeted knapsack
        score = 0.45·consensus + 0.35·normalised info gain + 0.20·bandit sample
                    │
        HuntPlan (probes, routes, seed, full decision trace)
                    │
        Executor: budget + kill switch + evidence sealing
```

Information gain is computed against a Bayesian posterior over 15 vulnerability classes (`app/engine/bayes.py`), so selection is an experimental-design problem rather than a fixed order. The swarm runs the conversation in [`docs/DELIBERATION.md`](docs/DELIBERATION.md); the scoring mathematics are in [`docs/AGENTIC.md`](docs/AGENTIC.md). Every hunt writes `transcript.md` and serves it at `GET .../runs/{id}/transcript`.

---

## Safety model

Three independent layers, all deny-by-default:

1. **Scope grant** — origin, method set, path prefix, expiry, safety ceiling. Checked when the campaign is created *and* again in the worker immediately before egress.
2. **Egress policy** — hostname deny-list, resolved-address classification (loopback, RFC1918, link-local, CGNAT, ULA, metadata endpoints), datastore port block, per-hop redirect re-authorization, connection pinned to the validated IP (defeats DNS rebinding).
3. **Resource guard** — request/byte/time budget, token-bucket rate limit, bandit and GA can never exceed the grant's safety ceiling, kill switch honoured between requests.

## Evidence model

Each observation is stored content-addressed and hashed into a Merkle tree with RFC 6962 domain separation, so any single finding can be proven against the run root without disclosing the rest. The manifest is HMAC-signed; `verify` recomputes the root, checks the signature and re-hashes every blob.

## Repository layout

```
app/
  engine/            dependency-free agentic core
    agents.py        six specialist doctrines + critique protocol
    planner.py       propose → critique → arbitrate, reproducible by seed
    arbiter.py       hard constraints + budgeted knapsack
    bayes.py         posterior over vulnerability classes, expected information gain
    bandit.py        Thompson sampling over probe efficacy
    evolution.py     genetic search over hunt genomes
    graph.py         attack-surface graph + route ranking
    http.py          guarded HTTP client (IP pinning, budgets, redirects)
    policy.py        SSRF/egress policy
    evidence.py      Merkle tree, inclusion proofs, signed manifests
    report.py        SARIF / HTML / Markdown
    probes/          13 probes with safety classes
    deliberation.py  multi-round protocol, convergence, spawn, withdrawal
    transcript.py    Markdown minutes of the conversation
    cli.py           `python -m app.engine.cli`
  services/autonomy_service.py   standing authorization + scheduling decisions
  api/v1/autonomy.py             policy, status, decisions, pause/resume/kill, tick
  api/v1/            campaigns, runs, findings, tenants, health, metrics
  services/          campaign/hunt/run/tenant/outbox/reaper/report services
  core/              config, security, rate limiting, audit, observability
  models/            SQLAlchemy models (PostgreSQL, SQLite-portable types)
worker/              Celery task, scheduler loop (outbox relay + reaper)
alembic/             6 migrations, single head
scripts/             preflight, diagnostics, bootstrap, smoke, alembic graph check
tests/unit/          66 tests, no external services required
docs/                architecture, agentic design, objectives, workers, ADRs
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest tests/unit -q          # no database required
ruff check . && ruff format --check .
python scripts/check_alembic_graph.py
alembic upgrade head                    # against PostgreSQL
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).

## Governance endpoints

| Endpoint | Purpose |
|---|---|
| `GET/PUT /api/v1/autonomy`, `POST /pause|/resume|/kill|/tick` | standing authorization |
| `GET /api/v1/profiles` | campaign doctrine presets |
| `GET/POST/DELETE /api/v1/webhooks` | signed outbound events |
| `GET/POST/DELETE /api/v1/suppressions` | accepted false positives |
| `GET /api/v1/audit/verify` | recompute the per-tenant audit chain |
| `POST /api/v1/objectives` | delegate work with acceptance criteria |
| `POST /api/v1/objectives/{id}/step` / `/run` | advance one task / drive to completion |
| `GET /api/v1/objectives/{id}/report` | criteria results, evidence, verdict |
| `GET /api/v1/workers`, `/objective-templates` | the workforce catalog |
| `GET /api/v1/objectives/{id}/coverage` | measured route coverage and the remaining gap |
| `POST /api/v1/tenants/{id}/rotate-key` | rotate a tenant key |
| `GET .../runs/{id}/diff` | baseline comparison |
| `GET .../runs/{id}/evidence/verify` | recompute Merkle root, signature and blobs |
| `GET .../campaigns/{id}/risk-trend` | risk per run |
| `GET /healthz`, `GET /readyz` | liveness and readiness |

Full enforcement points and proofs: [`docs/HARDENING.md`](docs/HARDENING.md).

## Operational endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | liveness + engine version |
| `GET /health` | PostgreSQL + Redis behind circuit breakers |
| `GET /metrics` | Prometheus exposition |

## Known limitations

- **No concolic execution or coverage-guided fuzzing yet.** The engine does deterministic web probes; the harder capabilities are design-stage.
- Postgres RLS is not enabled; isolation is enforced in the query layer plus denormalized `tenant_id` columns.
- Strategy evolution only adopts strict improvements, so on a fully-vulnerable target it will keep the full catalog rather than prune — by design, but it means the "evolution" is conservative.
- Single-region, single-tenant-per-database deployment; no sharding.
- No UI. Everything is API and CLI.

## License

MIT — see [LICENSE](LICENSE).
