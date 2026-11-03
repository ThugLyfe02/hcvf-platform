# Changelog

All notable changes are recorded here. The project follows semantic versioning.

## [0.10.0] - 2026-11-03

### Added

- **Operator console** (`app/web`): server-rendered pages at `/console` with an
  API-key-to-signed-cookie session, dashboard, objectives with live SSE events,
  findings, runs, autonomy, memory, workforce, audit and runtime pages.
  Thirteen Jinja2 templates, one CSS file, one dependency-free JS file.
- **SSE streams**: `/console/objectives/{id}/events.sse` and
  `/api/v1/objectives/{id}/events/stream` replay durable objective events and
  close on a terminal objective.
- **Signed admin exports**: findings, audit and objectives CSV, and a single
  evidence bundle zip per objective, all with `X-HCVF-Signature` and
  `X-HCVF-SHA256`; members get 403 and bundles are capped at 64 MiB.
- **Four artefact probes** (18 total): `secrets-in-bundle` (masked credential
  shapes), `source-map-exposure`, `dependency-manifest` and
  `cache-poisoning-surface` (forwarding-header reflection with cache indicators).
- `HCVF_CONSOLE_SECRET` setting for console session signing.

### Changed

- The exposure doctrine now includes the artefact probes; the posture doctrine
  includes cache trust. All four are read-only and excluded from default hunts
  to keep classic run profiles stable.
- The fixture application now serves a bundle with a planted credential, a
  source map, a manifest and a reflecting cache route.

### Fixed

- Console login parses its urlencoded body directly instead of requiring
  `python-multipart` as a deployment dependency.

## [0.9.0] - 2026-11-03

### Added

- **Adaptive planning** (`app/engine/workforce/replan.py`): after every result
  the supervisor rebuilds the belief and adds the next request with the best
  expected information gain, capped at ten adaptive tasks and by remaining budget.
  New `adaptive` template.
- **Surface graph** (`app/engine/workforce/surface.py`): nodes per discovered
  route plus implied ancestors, role, value, saturation, findings and risk;
  frontier of unprobed (route, probe) pairs.
- **Cross-objective memory** (`objective_memory`, migration 0011,
  `app/services/memory_service.py`): per-host recipes with attempts, findings,
  verified and refuted counts; capped boost in planning; `GET /api/v1/memory`.
- **Signed artifacts** (`app/services/objective_artifacts.py`): every terminal
  objective writes signed SARIF + Markdown, served with `X-HCVF-Signature` and
  `X-HCVF-SHA256`.
- **Objective diff**: `GET /objectives/{id}/diff` returns new, fixed and
  recurring finding kinds against the previous completed objective.
- **Objective metrics**: objectives by template/status, tasks by worker/status,
  coverage ratio, planned information gain, refuted verifications, memory updates.

### Changed

- A done probe or verifier task now triggers a fresh adaptive selection, so the
  plan is a sequence of decisions rather than a fixed list.
- The `adaptive` template is accepted by the objectives API and by autonomy.

### Fixed

- The surface graph only connected routes whose exact parent was discovered;
  implied ancestors are now part of the graph.

## [0.8.0] - 2026-11-03

### Added

- Coverage planning from the route graph: role classification, role-appropriate
  probe assignment, breadth-first budget spend, measured coverage and the
  `min_route_coverage` acceptance criterion.
- Dynamic plan expansion after recon (`plan.expanded`): the plan grows with the
  routes that were actually discovered, deduplicated and budget-bounded.
- `auditor-worker`: re-verifies every manifest (format, HMAC signature, Merkle
  root, blob presence) before the report; one tampered leaf blocks the objective.
- `diagnose-worker`: one HEAD classifies a hard failure before it becomes final.
- Narrow retry: a blocked objective escalates into a retry for exactly the
  criteria that failed, after the cooldown.
- Fleet and budget governance: `max_active_objectives`,
  `daily_objective_requests`, `template_auto`, `template_history`.
- `GET /api/v1/objectives/{id}/coverage`: measured coverage and remaining gap.

### Changed

- Every plan ends with an audit task before the report; a report cannot be
  written over unverified evidence.
- A failed task is diagnosed before the objective blocks; the blocked verdict
  carries the explanation.
- TickReport reports `delegate-narrow`, and decisions record the alternatives
  considered.

### Fixed

- Coverage expansion treated its own base plan as already expanded, so
  discovered routes never produced tasks.
- Escalation decisions stored a full URL while retry lookup compared origins,
  so narrow retry could never fire.
- Persisted outcomes dropped their route, making measured coverage zero after a
  reload.

## [0.7.0] — 2026-11-03

### Added

- **Objective-driven workforce**: a delegated work order with acceptance
  criteria (`objectives`), decomposed into a task DAG (`objective_tasks`) and an
  append-only narrative (`objective_events`). Work completes only when the
  criteria pass.
- **Seven specialist workers** (`recon`, `config`, `auth`, `exposure`, `surface`,
  `verifier`, `report`), each with a narrow discipline and its own refusal
  conditions. Workers cannot mark their own output accepted.
- **Independent verification**: findings with severity `high`/`critical` and
  confidence ≥ 0.60 spawn a `verify` task that re-runs the same probe against the
  same route. A failed reproduction is recorded as `confirmed=False`, not hidden.
- **Surgical execution**: one probe, one route, one budget per task; tasks are
  leased, retried within `max_attempts`, and re-aimed at discovered routes after
  recon.
- **Durable progress**: evidence is rehydrated from persisted outcomes, so an
  objective resumes at the next ready task after a restart.
- **Objectives API**: create/list/get, tasks, events, `step`, `run`, `cancel`,
  `report`, plus `GET /api/v1/workers` and `/objective-templates`.
- **Objective worker loop** (`worker/objectives.py`) wired into the scheduler.
- **Objective webhooks**: terminal objectives emit `objective.completed` or
  `objective.failed` with the verdict, evidence counts and unmet criteria,
  signed with the same HMAC scheme as run events.

### Changed

- **Autonomy rules**: `AutonomyPolicy` gains `mode` (`hunt` | `objective`),
  `objective_template`, `max_objectives_per_day`, `objective_budget_requests`
  and `escalation_cooldown_minutes`. In objective mode the controller delegates
  work instead of scheduling campaigns; `custom` template selection uses gap
  analysis over per-host probe coverage, and a blocked objective puts the
  template on cooldown rather than retrying immediately.
- Objective outcomes feed back into target scheduling (success resets the failure
  streak, a block escalates with the configured cooldown).

### Fixed

- Supervisor readiness mutated task state on every query, so tasks marked ready
  in one round became invisible to later rounds.
- Persisted task outcomes were not rehydrated, so acceptance criteria evaluated
  against empty evidence after the first step.
- Objective keys could collide when two objectives were delegated in the same
  second for the same tenant.
- Objective outcomes looked up hunt targets by full URL while targets are stored
  as origins; the escalation cooldown never fired.
- The revision id `0002_add_cancelled_campaign_status` (34 chars) exceeded
  Alembic's `version_num` column (VARCHAR(32)), so a real PostgreSQL upgrade
  failed with StringDataRightTruncation; ids are now capped and checked.
- Two DELETE routes declared 204 with a response model, which FastAPI rejects
  at import time on the pinned version; they now return an explicit body.

## [0.6.0] — 2026-11-03

Twenty hardening and governance capabilities, plus two supporting features. See
[`docs/HARDENING.md`](docs/HARDENING.md) for enforcement points and proofs.

### Added

- **Row-level security**: policy DDL generator, per-transaction tenant binding,
  and `scripts/enable_rls.py` with a dry-run mode.
- **API-key scopes** enforced on every router, with deny-by-default grants for
  new tenants.
- **Key rotation** that invalidates the previous key atomically.
- **Idempotency keys** on campaign creation and execution, claimed before the
  handler runs, with replay and conflict detection.
- **Daily quotas** on runs and budgeted requests, applied to manual and autonomous
  execution alike.
- **Finding suppressions** with optional expiry; suppressed issues are not stored
  and do not inflate risk.
- **Tamper-evident audit chain** with a monotonic per-tenant sequence and a
  verification endpoint.
- **Signed webhooks** (HMAC-SHA256 over timestamp + body) delivered through the
  outbox with retries, guarded by the same SSRF policy as probes.
- **Cron scheduling**: five-field parser, next-occurrence computation, and a
  scheduler path that claims due campaigns and advances their slot.
- **Baseline diff** per run (new / fixed / recurring) against the previous
  completed run of the same campaign.
- **Risk score** per run (log-scaled, severity weighted) and a risk-trend endpoint.
- **Evidence verification endpoint** that recomputes the Merkle root, checks the
  signature and re-hashes every blob.
- **OpenAPI ingestion probe** that turns a published spec into routes and reports
  the disclosure.
- **Discovery-ordered replanning**: phase two waits for every surface-acquisition
  probe, so specialists deliberate on measured routes.
- **GCRA rate limiting** replacing the fixed window.
- **Log redaction** filter for inline secrets and sensitive structured fields.
- **Request body size limit** returning a problem-details 413.
- **W3C trace context** propagation and echo, with the trace id in every log line.
- **RFC 9457 problem details** for HTTP errors, validation failures and unhandled
  exceptions, including the trace id.
- **Liveness (`/healthz`) and readiness (`/readyz`)** split.
- **Campaign profiles** (`GET /api/v1/profiles`) and a **CLI diff** command.

### Fixed

- Audit chaining previously depended on timestamp order; equal timestamps could
  make a valid chain fail (or a tampered one pass), which `audit_logs.seq` fixes.
- Quotas counted campaign creation rather than runs, consuming allowance before
  anything executed.
- Adding a probe to a genome did not guarantee it was proposed; OpenAPI ingestion
  is now part of the recon doctrine.
- Scope enforcement was declared but not wired; every router now depends on it.

## [0.5.0] — 2026-11-03

### Added

- **Multi-round deliberation** (`app/engine/deliberation.py`): typed utterances
  (`propose`, `support`, `oppose`, `challenge`, `reply`, `ruling`, `withdraw`,
  `spawn`, `moderate`, `consensus`) with a bounded round count and a convergence
  rule based on a stable budgeted allocation, not a single leader.
- **Adjudicated objections**: a devil's advocate raises `over_budget`,
  `high_false_positive`, `low_information`, `low_route_value`,
  `inefficient_tradeoff` or `unverified_route`; the sponsor replies with a
  falsifiable claim; the risk officer rules and applies a real penalty.
- **Dynamic specialist spawning**: recon convenes auth, GraphQL and admin
  specialists when discovery exposes those surfaces, logged with its trigger.
- **Two-phase planning**: the executor discovers first, then deliberates again
  with the real route map, so specialists are convened on evidence rather than
  guesses. Explicit probe lists remain single-phase and unchanged.
- **Doctrine-aware route selection**: probes are aimed by class affinity and
  rendering status, with deterministic rotation across equally good routes
  instead of every probe piling onto the homepage.
- **Transcript**: stored in `run.plan.deliberation`, written as `transcript.md`,
  served by `GET .../runs/{id}/transcript` and rendered in the HTML report.
- 11 deliberation tests: conversation shape, convergence, spawning, safety
  containment, reproducibility, option accounting.

### Changed

- `HuntPlan` carries `transcript`, `rounds`, `converged`, `consensus_round` and
  the final agent roster; `explain()` reports the deliberation outcome.
- Arbiter input is now one synthesised critique per deliberated option, so budget
  allocation and the conversation cannot disagree about the ranking.

## [0.4.0] — 2026-11-03

### Added

- **Autonomous hunt controller** (`app/services/autonomy_service.py`,
  `worker/autonomy.py`): a standing, human-approved authorization per tenant.
  It selects targets by a staleness/risk/novelty utility, enforces a daily run
  cap, per-target interval, quiet hours, a safety ceiling that can never be
  `destructive`, and a failure backoff that disables a target after repeated
  failures.
- **Target inventory** (`hunt_targets`): last run, next eligibility, failure
  streak, cumulative findings — the state autonomy schedules against.
- **Explainable scheduling** (`autonomy_decisions`): every launch, cap refusal,
  backoff and disable is recorded with a utility score and a reason; repeated
  identical refusals are deduplicated to one per hour.
- **Learned probe sets per launch**: the controller derives a genome from
  `probe_stats` for the target host and stores it on the campaign, closing the
  loop between the bandit and autonomous execution.
- **Autonomy API**: `GET/PUT /api/v1/autonomy`, `POST /pause|/resume|/kill|/tick`,
  `GET /decisions`. Status returns daily usage, quiet-hours state and targets
  ranked by the utility the controller will actually use.
- **Finding recurrence**: `occurrences`, `last_seen_at`, `last_run_id`; repeated
  observations aggregate instead of duplicating, and a recurrence of a `fixed`
  or `verified` finding reopens it as a regression.
- **Scheduler integration**: the scheduler loop now relays the outbox, reaps
  stale runs, dispatches due campaigns and ticks the autonomy controller.
- Risk accounting counts only *new* issues: a target that re-observes 19 known
  findings does not look 38 findings riskier to the scheduler.
- 18 autonomy tests (authorization, scope containment, caps, quiet hours,
  backoff, kill switch, genome derivation, recurrence) bringing the service-free
  suite to 84.

### Changed

- `RunService` resolves the run before listing findings, then matches on
  `run_id` OR `last_run_id`, so aggregated issues still appear in run reports
  without weakening tenant scoping.
- Datetimes read from SQLite are normalized to UTC-aware before comparison;
  this was found by the autonomy tests and applies to every scheduling path.

## [0.3.0] — 2026-11-03

### Added

- **Agentic hunt engine** (`app/engine`): six specialist agents, cross-critique,
  weighted consensus and a budgeted knapsack arbiter with a complete, stored
  decision trace.
- **Bayesian probe selection**: posterior over 15 vulnerability classes and
  expected-information-gain scoring.
- **Thompson sampling** over probe efficacy, persisted per `(probe, host)` in
  `probe_stats`.
- **Genetic strategy evolution** over hunt genomes, with a coverage term and a
  size penalty to prevent collapse onto a single probe.
- **Attack-surface graph** with value scoring and best-first route search.
- **SSRF-resistant egress**: hostname deny-list, address classification, IP
  pinning, per-hop redirect authorization, datastore port block.
- **13 probes** with explicit `read_only` / `state_changing` blast-radius classes.
- **Signed evidence**: Merkle tree with inclusion proofs, HMAC-signed manifests,
  offline `verify` command.
- **Reports**: SARIF 2.1.0, self-contained HTML, Markdown.
- **CLI**: `python -m app.engine.cli hunt|probes|memory|verify`.
- **Platform**: transactional outbox, run leases and reaper, cancellation
  signals, tenant roles, finding fingerprints and triage lifecycle, global
  findings API, SARIF endpoint, plan endpoint.
- **CI**: lint, migration-graph check, import smoke, service-free unit suite,
  PostgreSQL integration suite.
- 66 service-free tests plus integration tests.

### Fixed

- Alembic chain had a dangling `down_revision` and two heads; a fresh
  `alembic upgrade head` could not run.
- `worker/scheduler.py` imported a non-existent `configure_logging`, crash-looping
  the scheduler container.
- API keys minted by `POST /tenants` could never authenticate (env allowlist gate).
- Any tenant could list and rewrite every other tenant (`GET /tenants`,
  `PATCH /tenants/{id}`); scope changes now require an admin role.
- HTTP request metrics were recorded only by dead code; the middleware now lives
  and is ordered outside the rate limiter so 429s are counted.
- Rate limiting raised `HTTPException` from middleware (500 instead of 429) and
  failed closed on Redis errors.
- `FuzzRunner` followed redirects without re-authorization and re-resolved DNS;
  all egress now goes through `GuardedHttpClient`.
- A broker outage left runs permanently `queued`; replaced with an outbox.
- A killed worker left runs permanently `running` with no recovery path; added
  leases and a reaper.
- Double-execute raced; `create_run` now locks the campaign row.
- Audit middleware could turn a successful mutation into a 500.
- Finding `evidence` was untyped JSON; it is now content-addressed digest lists
  plus an `evidence_refs` object.

### Changed

- Database types are dialect-portable (`GUID`, `JSONDoc`); production stays
  native UUID/JSONB.
- Celery results are disabled (`task_ignore_result`); the run row is the source
  of truth.
- Compose publishes Postgres/Redis on loopback only, adds an evidence volume,
  and the image runs as a non-root user.
- README rewritten around what the platform actually does, with an honest
  capability table.

## [0.2.0] — 2026-08-26

- Initial operational baseline: FastAPI control plane, tenant API keys, Celery
  execution, PostgreSQL persistence, health checks, metrics, audit trail,
  campaign/run/finding endpoints and the verification script ladder.
