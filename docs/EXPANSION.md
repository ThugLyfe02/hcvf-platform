# HCVF — From Control Plane to Category Leader

> Companion to [`AUDIT.md`](./AUDIT.md). This is the build plan: what to add, in what order, and how to know it worked. Every recommendation is written to be implementable against *this* codebase, not an imaginary one.

---

## 0. The thesis: what you are actually positioned to win

The security-validation market is crowded at the bottom (`nuclei`, ZAP, Nikto — free, noisy, no accountability) and expensive at the top (PtaaS: Cobalt, XBOW, Synack — humans, weeks, six figures). The unoccupied middle is **authorization-grade, evidence-grade continuous validation**:

> Every finding is *reproducible*, *attributable to a signed scope*, and *provable to an auditor* — and the platform can prove it did not exceed its authority.

That is a fundamentally different product from "a scanner with a queue". Three claims define it, and all three are defensible because they are painful to retrofit:

1. **Proof-carrying findings.** A finding is not a string. It is a sealed artifact (request bytes, response bytes, tool image digest, RNG seed, timestamp, target IP) that any third party can replay and confirm. Scanners cannot do this because they discard evidence as they go.
2. **Provable authorization.** Every outbound byte is traceable to a signed, time-boxed, dual-approved scope grant. When the auditor asks "prove you only touched what you were allowed to touch," you produce a hash-chained log and a scope artifact — not a checkbox.
3. **Measurement, not alerts.** The product reports *trend*: risk posture over time, coverage of the attack surface, regression detection between deploys. Alerts are the commodity; trend is the moat.

Your current architecture already has the skeleton for #2 (attestation, allowlist, audit) and #1 (run→finding→JSONB evidence). Neither is real yet, but the shape is right. That is why the plan below is an *amplification* of what you built rather than a rewrite.

**Positioning sentence to grow into:** *"The reproducible validation layer for teams who must prove their security testing was authorized, scoped, and effective."*

---

## 1. North-star architecture

```
                    ┌──────────────────────────────────────────────┐
  humans ──OIDC──▶  │  Web console (campaign builder, triage,       │
  CI ───scoped key─▶│  evidence viewer, dashboards, reports)        │
  API ──SDK────────▶│                                              │
                    └───────────────┬──────────────────────────────┘
                                    │ REST + SSE/WS
                    ┌───────────────▼──────────────────────────────┐
                    │  API (FastAPI, async)                        │
                    │  authn: OIDC + scoped keys   authz: RBAC+ABAC │
                    │  idempotency · pagination · rate limits       │
                    │  OpenAPI 3.1 · webhooks (HMAC, retried)       │
                    └───┬───────────────┬──────────────┬───────────┘
                        │               │              │
              ┌─────────▼──────┐  ┌─────▼──────┐  ┌────▼─────────────┐
              │ PostgreSQL     │  │ Outbox +   │  │ Object store     │
              │ + RLS          │  │ Redis      │  │ (S3/MinIO)       │
              │ control plane  │  │ queues     │  │ evidence blobs   │
              └────────────────┘  └─────┬──────┘  └──────────────────┘
                                        │
                    ┌───────────────────▼────────────────────────────┐
                    │  Planner  →  Policy engine  →  Probe scheduler │
                    │  (spec → jobs)  (budgets,    (per-tenant fair   │
                    │                  allowlists,  queues, quotas)   │
                    │                  kill switch)                   │
                    └───────────────────┬────────────────────────────┘
                                        │
        ┌───────────────┬───────────────▼───────────────┬────────────────┐
        │ HTTP probes   │ Fuzz workers (AFL++/libFuzzer │ Concolic worker │
        │ OAST listener │ /atheris/Jazzer adapters)      │ (angr, Manticore)│
        └───────┬───────┴───────────────┬───────────────┴────────┬───────┘
                │                       │                        │
        ┌───────▼───────────────────────▼────────────────────────▼───────┐
        │  EGRESS PROXY (the only route out)                             │
        │  IP pinning · DNS pinning · metadata-block · per-tenant egress │
        │  allowlist · full request/response capture for evidence        │
        └───────────────────────────────┬────────────────────────────────┘
                                        ▼
                                  authorized targets
```

Two structural rules that make the rest possible:

- **The API never touches a target.** All egress leaves through the proxy, from worker pods with no other network path.
- **Evidence is captured at the proxy, not the tool.** The tool can be swapped, upgraded, or buggy; the captured bytes are the ground truth.

---

## 2. Domain expansion — fourteen fronts

Each entry: *today* → *target* → *concrete build*.

### 2.1 Correctness & reliability

**Today:** see AUDIT §3. **Target:** a state machine you can reason about under failure.

Build:
- Explicit campaign/run state machines as code (`transitions: dict[Status, set[Status]]`), with every write going through `transition()`. Invalid transitions raise, don't silently corrupt.
- Transactional outbox (`outbox(id, topic, payload, available_at, attempts, published_at)`) + relay worker; dequeue is exactly-once via `FOR UPDATE SKIP LOCKED`.
- Lease + heartbeat + reaper (§AUDIT 3.8) with `lease_expires_at`.
- Idempotency-Key middleware: `idempotency(key, tenant_id, request_hash, response_code, response_body, expires_at)`; replay returns the original response.
- Per-run budget guard in the worker: `requests_sent`, `bytes_out`, `wall_clock` — checked between probes; exceeding it fails the run, does not continue.
- Chaos tests in CI: kill the worker mid-run, drop Redis, stall Postgres (`pg_sleep` in a trigger), and assert the invariants (no stuck `running`, no duplicate runs, no lost audit).

**Exit criteria:** 1,000-run soak with random worker kills → zero orphaned rows, zero duplicate executions, 100% of runs terminal within 2× their budget.

### 2.2 Identity & authorization

**Today:** env API keys, one role, false tenancy. **Target:** enterprise-grade, provable.

Build:
- **Human auth:** OIDC (Keycloak/Auth0/Entra), PKCE sessions, MFA enforced by policy, SCIM for lifecycle.
- **Machine auth:** API keys as `hcvf_<env>_<keyid>_<secret>`; store `keyid` plaintext + Argon2id(secret); scopes (`campaigns:read`, `campaigns:execute`, `findings:triage`, `tenants:admin`), `expires_at`, `last_used_at`, rotation with overlap.
- **RBAC + ABAC:** roles (owner, security-engineer, analyst, auditor, read-only) × resources scoped by `organization_id` → `engagement_id` → `asset_id`. The authorization decision is a single pure function, property-tested with `hypothesis` ("no principal can act outside its org").
- **Postgres RLS as the second line:** every tenant table gets `USING (organization_id = current_setting('app.org_id')::uuid)`; the session sets it per request via `SET LOCAL`. Then even a missed `WHERE` cannot leak.
- **Dual control for scope changes:** a `scope_grants` table; creating a grant requires a second approver; grants carry `expires_at` and an immutable `evidence_uri` (signed RoE PDF). Tenant self-service edits become *requests*, not writes.

**Exit criteria:** an external pentest of your own API finds no cross-tenant read/write; the authorization predicate has ≥95% mutation coverage.

### 2.3 Scope, authorization & legal guardrails (your actual moat)

**Today:** a boolean and a JSONB array. **Target:** the strongest authorization story in the market.

Build:
- `engagements` (customer, start, end, jurisdiction, contact, emergency stop) → `assets` (url/cidr/repo/container, owner, environment) → `scope_grants` (asset, allowed methods, rate cap, window, approver, signature).
- **Signed Rules of Engagement:** generated PDF + detached signature (Ed25519), hash stored on the grant, hash linked into every run. Re-verify the signature at execute time; refuse if the engagement window has closed.
- **Kill switch:** `POST /engagements/{id}/halt` flips a Redis flag read by every worker between probes; in-flight probes abort; the halt is audited and broadcast to the UI. Test it in CI.
- **Jurisdiction/geo-fence:** if `jurisdiction` forbids a technique class, the planner refuses to compile it — policy at plan time, not runtime.
- **No-destructive-payload policy class:** every probe declares `safety: read_only | state_changing | destructive`. Destructive is opt-in per engagement *and* per technique, off by default, and requires a second approver.
- **Egress allowlist by IP + name,** with metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`) hard-blocked at the proxy, not in application code.

**Exit criteria:** an auditor can reconstruct, for any packet, the grant that permitted it, in under 60 seconds, from the UI.

### 2.4 The validation engine (the thing the name promises)

**Today:** one GET. **Target:** a composable probe framework with real depth.

```
Probe
  id, version, safety_class, requires(methods, auth, oast)
  plan(target, spec) -> list[ProbeJob]
  execute(job, ctx) -> list[Observation]     # ctx = http client, budget, oast client
  interpret(observations) -> list[FindingDraft]  # deterministic; no LLM
```

Ship in this order (each is a week of work, each is independently valuable):

**Wave 1 — correctness of the web surface (weeks 3–5).** ~20 probes, all read-only:
| Probe | Detects | Safety |
|---|---|---|
| security-headers | missing CSP/HSTS/XFO/permissions-policy, weak values | read_only |
| tls-config | protocol/cipher policy, cert chain, expiry, hostname mismatch, CT | read_only |
| cookie-flags | Secure/HttpOnly/SameSite/prefix (`__Host-`) | read_only |
| cors-policy | `*` with credentials, reflected origin, null origin | read_only |
| http-methods | advertised vs. actual allowed methods, TRACE, OPTIONS disclosure | read_only |
| cache-poisoning | unkeyed headers reflected into cacheable responses | state_changing |
| host-header | host injection into absolute URLs / password-reset links | state_changing |
| path-normalization | `..%2f`, `%2e%2e/`, double-encoding, unicode dot | read_only |
| error-disclosure | stack traces, debug pages, framework versions | read_only |
| open-redirect | `Location` derived from user input | state_changing |
| graphql-introspection | introspection enabled, depth/alias limits, batching | read_only |
| openapi-conformance | documented vs actual (schemathesis-style property fuzz) | state_changing |
| jwt-posture | `alg:none`, `kid` injection, weak HMAC secret, `exp` missing | state_changing |
| session-lifecycle | fixation, logout invalidation, cookie rotation | state_changing |
| rate-limit-presence | auth endpoints without throttling | state_changing |
| ssrf-oracle | OAST callback on URL-accepting parameters | state_changing |
| xss-reflection | reflected payload surviving encoding, in HTML/attr/JS context | state_changing |
| sqli-oracle | error/boolean/time differential (bounded, no data exfiltration) | state_changing |
| cache-deception | cache key normalization gaps | state_changing |
| subdomain-takeover | dangling CNAME → claimable service fingerprint | read_only |

**Wave 2 — supply chain & config (weeks 5–7).** SBOM ingestion (CycloneDX), dependency CVE matching with KEV/EPSS, secret scanning (gitleaks rules), IaC scan (Trivy/Checkov), container image scan, cloud posture checks (read-only API calls with a customer-provided role).

**Wave 3 — real fuzzing (weeks 7–12).** Adapters that speak a common result protocol:
- HTTP: schema-aware mutation engine with coverage feedback from response *shape* (status class, error signature, latency band, body length bucket) — a poor man's AFL for web, and it works surprisingly well.
- Native: `libFuzzer`/AFL++ harness runner with corpus management, `-max_total_time` and memory caps, crash dedupe by stack hash.
- Python: `atheris` in a sandboxed subprocess; Java: Jazzer.
- Every crash becomes a `Finding` with the crashing input stored as an evidence blob.

**Wave 4 — concolic (weeks 12–20).** This is where the name gets earned:
- `angr`-based symbolic execution of a *provided* binary + harness, with a path-exploration budget and a target-address predicate (find input reaching `crash` or satisfying a branch).
- `crosshair`/`hypothesis` for Python functions under test (property-based + symbolic).
- Outputs: concrete input bytes + path trace + constraint summary, all sealed as evidence.
- Ship it as `POST /api/v1/analyses` with `kind: symbolic` — a separate product surface from campaigns. This is legitimately hard and genuinely differentiating; do not rush it, and never claim it before it exists.

**Exit criteria:** run against OWASP Juice Shop, DVWA, WebGoat, and a deliberately-vulnerable k8s demo; measure precision/recall against the published ground truth; precision ≥80% before you let a customer see it.

### 2.5 Evidence, findings & reporting

**Today:** a row + a JSONB dict. **Target:** proof-carrying findings.

Build:
- `evidence_blobs(sha256, s3_key, bytes, content_type, created_at)`; findings reference blobs by hash. Object lock / WORM for retention. Signed URLs for retrieval.
- `finding_fingerprint` — stable hash over (probe_id, asset, normalized location, CWE) so re-runs update one finding instead of creating twenty.
- Lifecycle: `open → triaged → confirmed | false_positive | risk_accepted → fixed → verified`. Every transition audited with actor and rationale. `risk_accepted` carries an expiry and an owner.
- Enrichment: CWE, CVSS 4.0 vector, EPSS, KEV flag, CISA remediation due date.
- **Verification runs:** a "fix verification" job that replays the exact evidence request and asserts the signature no longer matches. This is the feature that turns a scanner into a QA gate.
- Reports: SARIF (for GitHub Code Scanning), CycloneDX VEX, JSON, and a branded PDF per engagement generated from a template (WeasyPrint or headless Chromium), each page footer carrying the evidence hash.
- **Trending:** risk score per asset over time, coverage % of documented endpoints probed, regression count between deploys.

**Exit criteria:** any finding can be re-executed from its stored evidence and produce a byte-identical signature; a CISO can read the PDF and understand exposure without a call.

### 2.6 Data platform

Postgres is right for the control plane. Do not stretch it:
- Control plane: Postgres 16 + RLS, PITR, read replica for reporting.
- Events: append-only `run_events` (partitioned monthly) or ClickHouse once volume justifies it; feeds the timeline UI and analytics.
- Artifacts: S3-compatible with lifecycle rules (hot 90d → cold 1y → delete per contract).
- Search: start with Postgres `tsvector` + pg_trgm on findings; OpenSearch only when someone asks for it.
- Retention: per-tenant policy object, enforced by a nightly job, with legal-hold override. This is a sales blocker at every enterprise deal — build it early.

### 2.7 Scale & performance

- Move the API to async SQLAlchemy (`asyncpg`) **only when** connection-pool saturation is measured; until then, tune `pool_size`, add `statement_timeout=15s`, and add a queue-depth-based load shedder.
- Per-tenant fair queues (Celery `queue=` per org prefix, or better: a Postgres-backed scheduler with weighted fair queuing). One tenant's 10k-job campaign must not starve another's single run.
- KEDA/HPA scaling on queue depth, not CPU.
- Quotas: `runs/month`, `concurrent_probes`, `requests/sec`, `bytes/month` — enforced at plan time with a clear 402/429.
- Targets: p95 API <120 ms, p95 enqueue→start <5 s, 10k concurrent runs, 1M findings/tenant without a query >200 ms.

### 2.8 Observability

- OpenTelemetry traces spanning API → outbox → worker → probe → egress proxy, with `run_id`/`org_id` as span attributes. One trace shows exactly where a job spent its time.
- Metrics per tenant and per probe (success rate, latency, budget consumed, findings/precision).
- SLOs with error budgets: API availability 99.9%, run completion 99.5%, enqueue latency p95 <5 s. Alert on burn rate, not on thresholds.
- Logs: structured, sampled at high volume, always carrying `trace_id`.
- Error tracking (Sentry or GlitchTip) with release tagging — you currently have none, so a worker exception in production is invisible unless someone reads stdout.
- **Fix the current gap first:** worker Prometheus counters are process-local and never scraped (AUDIT §3.5). Export via `prometheus_client` HTTP server on the worker, or push to a Pushgateway.

### 2.9 Testing & quality engineering

- `conftest.py` with `testcontainers` Postgres + `fakeredis`; transactional rollback per test; factories (`factory_boy`) for every model.
- Unit tests for every pure function, starting with the authorization predicate and the state machine.
- Contract tests: `schemathesis` fuzzing your own OpenAPI on every PR.
- Golden-file tests for probes against recorded HTTP fixtures (`respx` or `pytest-httpserver`) — deterministic, no network.
- Mutation testing (`mutmut`) on `app/core` and `app/services`; kill the mutants in the auth path specifically.
- Security tests: IDOR matrix (every endpoint × every role × every foreign object), auth-bypass corpus, SSRF target corpus.
- Load tests (k6): 1k rps on reads, 100 concurrent campaign executions.
- Coverage gates: 90% on services/core, 70% overall; fail the build.

### 2.10 DevEx, CI/CD & supply chain

- GitHub Actions: ruff (lint+format), mypy `--strict` on `app/core`+`app/services` (incremental), pytest with coverage, `alembic heads` uniqueness check, import-smoke across every module, `pip-audit`, Trivy image scan, `alembic check` for model/migration drift.
- Lock dependencies (`uv lock` or `pip-compile --generate-hashes`), pin base images by digest, build SBOM (syft), sign (cosign), attach SLSA provenance.
- pre-commit: ruff, mypy, detect-secrets, conventional-commit lint, end-of-file-fixer.
- Release: semantic-release → CHANGELOG → signed git tag → GHCR image → Helm chart.
- Infra as code: Terraform for cloud, Helm chart for k8s, one `docker compose` profile for local dev, one for demo.
- `make dev` / `make test` / `make migrate` so onboarding is one command, not six scripts.

### 2.11 Product & UX

- **Web console** (Next.js app router, or HTMX+Alpine if you want to stay Python-only): asset inventory → engagement/scope → campaign builder (form + YAML view, live validation) → run timeline (SSE streaming of probe events) → findings board (kanban triage, bulk actions, keyboard-driven) → evidence viewer (rendered request/response, diff view for verification runs) → dashboards → reports.
- Campaign **spec DSL** in YAML, versioned, diffable, reviewable in a PR:
  ```yaml
  spec: hcvf/v1
  target: https://app.customer.com
  engagement: eng_01H...
  probes: [security-headers, cors-policy, jwt-posture, xss-reflection]
  budget: {requests: 5000, seconds: 900, rps: 10}
  safety: read_only
  schedule: "cron:0 3 * * 1"
  ```
- Integrations: Slack/Teams (run summaries, triage actions), PagerDuty (critical findings), Jira/Linear/GitHub Issues (finding → ticket, two-way status), GitHub PR checks (fail a PR that introduces a finding), SIEM export (CEF/OCSF), webhooks with HMAC + exponential retry + replay protection.
- Onboarding: a 10-minute "first validated finding" path with a deliberately vulnerable sandbox target you host. Time-to-first-value is the only activation metric that matters.

### 2.12 AI layer (do this late, and only on top of determinism)

Sequence matters: deterministic probes → sealed evidence → *then* models. Never the reverse.

- **Triage:** classify dedupe candidates, calibrate severity against evidence, propose false-positive with a cited reason. Human confirms; the model never closes a finding.
- **Reproduction advisor:** given evidence, generate a minimal `curl`/Python reproducer for the customer's engineers.
- **Remediation PRs:** for findings with a known pattern (missing CSP, cookie flags, CORS wildcard), open a PR against the customer's repo with a patch + test. Gated by human approval and by repo-scope grant.
- **Campaign planner:** given an OpenAPI spec and asset inventory, propose a probe set and budget. Output is a *spec diff* a human reviews, never an autonomous execution.
- **Report narrative:** drafts the executive summary from findings + trend; humans edit.
- **Guardrails:** no target credentials leave the tenant boundary; prompts and outputs logged and tenant-scoped; every AI claim must cite an evidence hash; eval suite with a golden set of 200 findings and a precision/recall gate before any model upgrade; cost budget per org.

### 2.13 Business, compliance & legal

- **Compliance path:** SOC 2 Type II (start with the controls you already have: audit trail, access review, change management — you're closer than you think), ISO 27001 later. Publish a subprocessor list, DPA, and a pen-test summary.
- **Data handling:** per-tenant encryption keys (envelope encryption in the object store), configurable residency (US/EU), customer-managed keys for enterprise, contractual retention and deletion with a certificate of destruction.
- **Pricing:** seats (analysts) + validated runs (or "assets monitored") + enterprise (SSO, residency, CMK, on-prem). Free tier limited to your own sandbox target — that's both a funnel and a safety rail.
- **Legal artifacts:** RoE template reviewed by counsel per jurisdiction; a hard prohibition on third-party targets without a signed grant; a published abuse-reporting path with a 24h SLA; geo-blocking of sanctioned regions.
- **Trust page** with live status, subprocessors, security.txt, disclosure policy, and a public changelog of probe additions.

### 2.14 Operations & support

- Runbooks for: stuck run, Redis loss, Postgres failover, egress proxy block, kill switch, tenant offboarding (data destruction proof).
- On-call rotation with SLO-based alerts; incident postmortem template; status page.
- Customer support: in-app, with automatic diagnostic bundle export (run id, trace id, evidence hash — never raw customer data).
- Capacity planning: cost per validated run, cost per probe, gross margin per tenant. Know these before you price.

---

## 3. Probe catalog — the safety taxonomy that makes it sellable

Every probe declares one of three classes, and the class gates execution:

| Class | Meaning | Default | Approval |
|---|---|---|---|
| `read_only` | GET/HEAD/OPTIONS, no state change, no payload that could persist | allowed | none |
| `state_changing` | POST/PUT, payloads that may create/modify/delete state | requires explicit engagement opt-in | one approver |
| `destructive` | could cause outage, data loss, or persistent compromise | off; per-technique feature flag | two approvers + time window |

This taxonomy is not bureaucracy — it is the product. It is what lets a CISO say yes. Put it in the UI as a visible badge on every campaign, and in the API as a required field.

---

## 4. Data model v2 (target sketch)

```sql
organizations(id, name, slug, plan, data_region, retention_days, created_at)
users(id, org_id, email, oidc_sub, role, mfa_enforced, last_login_at)
api_keys(id, org_id, key_id, secret_hash, scopes[], expires_at, last_used_at, revoked_at)
engagements(id, org_id, name, customer, starts_at, ends_at, jurisdiction,
            status, roe_blob_sha256, halted_at)
assets(id, org_id, engagement_id, kind, identifier, environment, owner, tags JSONB)
scope_grants(id, asset_id, allowed_methods[], rate_cap, window, safety_class,
             created_by, approved_by, approved_at, expires_at, evidence_sha256)
campaign_specs(id, org_id, name, version, spec JSONB, spec_sha256, created_by)
campaigns(id, org_id, spec_id, target_asset_id, status, scheduled_cron, created_at)
runs(id, org_id, campaign_id, status, lease_expires_at, budget JSONB, consumed JSONB,
     started_at, completed_at, error_code, error_message, trace_id)
run_events(id, run_id, seq, type, payload JSONB, at)          -- partitioned/month
probes(id, run_id, probe_id, probe_version, status, started_at, ended_at,
       requests_sent, bytes_out, exit_code)
findings(id, org_id, asset_id, run_id, probe_id, fingerprint, kind, cwe, cvss_vector,
         severity, confidence, title, detail, status, first_seen_at, last_seen_at,
         fixed_verified_at, risk_accepted_until, owner)
evidence_blobs(sha256 PK, s3_key, bytes, content_type, created_at, worm_until)
finding_evidence(finding_id, blob_sha256, role)               -- request|response|artifact|trace
reports(id, org_id, engagement_id, kind, blob_sha256, generated_at, generated_by)
webhooks(id, org_id, url, secret, events[], active, last_delivery_at)
idempotency(key, org_id, request_hash, status_code, response_body, expires_at)
outbox(id, topic, payload, available_at, attempts, published_at)
audit_log(id, org_id, actor_type, actor_id, action, resource_type, resource_id,
          request_id, trace_id, detail JSONB, prev_hash, hash, at)   -- hash-chained
```

Note what changed conceptually: `org → engagement → asset → grant` replaces `tenant.authorized_targets`. The allowlist becomes a first-class, auditable, time-boxed, dual-approved object. That single change is the difference between a tool and a platform.

---

## 5. API v2 conventions

- Versioned prefix (`/v2`), deprecation headers, at least 2 minor versions supported.
- Cursor pagination everywhere: `?limit=50&cursor=…` → `{data, next_cursor}`; hard cap 200.
- `Idempotency-Key` required on all POSTs that create runs/campaigns.
- Problem Details (RFC 9457) error envelope: `type, title, status, detail, instance, trace_id, errors[]`.
- Consistent errors: 404 for absent-or-unauthorized resources (keep this — it's already right).
- Webhooks: HMAC-SHA256 signature header, timestamp, `Idempotency-Key`, exponential retry for 24h, dead-letter endpoint.
- OpenAPI 3.1 as the source of truth; generate TypeScript and Python clients in CI; publish to a registry.
- Rate-limit headers (`RateLimit-Limit/Remaining/Reset`) on every response.

---

## 6. Roadmap with exit criteria

| Phase | Window | Ship | Exit criteria |
|---|---|---|---|
| **0 — Unbreak** | days 0–2 | AUDIT §10: migration chain, scheduler import, key auth, tenant IDOR, metrics, SSRF guard, outbox-lite, reaper, conftest, CI | Fresh clone → `docker compose up` → green smoke in <10 min; CI enforces 9 gates; no P0 open |
| **1 — Trustworthy** | weeks 1–2 | State machines, RLS, RBAC-lite, idempotency, pagination, scope-grant table, kill switch, audit hash chain, OTel, Sentry, worker metrics | External pentest: zero cross-tenant findings; kill switch verified in CI; every mutation idempotent |
| **2 — Real product** | weeks 3–6 | Probe framework + Wave 1 (20 probes), evidence blobs, finding fingerprints + lifecycle, SARIF/PDF reports, web console v1, Slack + Jira, signed RoE | 10 design partners running weekly campaigns; precision ≥80% on Juice Shop/DVWA/WebGoat; time-to-first-finding <10 min |
| **3 — Scale** | weeks 6–10 | Per-tenant fair queues, KEDA, quotas, retention/legal hold, SSO+SCIM, read replica, ClickHouse (if needed), Helm/Terraform, SOC 2 readiness | 10k concurrent runs; p95 enqueue <5 s; one enterprise customer on SSO |
| **4 — Depth** | weeks 10–20 | Fuzzing adapters (native/Python/Java), OAST server, differential testing, fix-verification runs, AI triage, remediation PRs | 3× finding recall vs Wave 1; false-positive rate <15%; a customer's CI blocks a real regression |
| **5 — Category** | months 5–12 | Concolic engine, probe marketplace, multi-region, on-prem, partner API, compliance certifications | Analyst mention; 20+ paying orgs; NRR >115% |

Sequencing rule: **never ship a capability whose evidence you cannot prove.** Depth without proof is just a noisier scanner.

---

## 7. Metrics that should drive every decision

**Product truth**
- Time to first validated finding (target <10 min)
- Validated-runs/week per active org (leading indicator of value)
- Finding precision (confirmed / total) — target >80%
- Finding recall vs. ground-truth corpus (benchmark, not customer)
- Evidence reproducibility rate — target 100%
- Fix-verification rate (findings later confirmed fixed)

**Platform health**
- Run completion rate >99.5%; p95 enqueue→start <5 s
- Orphaned/stuck runs = 0 (hard invariant)
- Cross-tenant access attempts = 0 (should be impossible, alert if >0)
- Audit chain verification = pass (nightly job)
- Cost per validated run; gross margin per org

**Anti-metrics** (track to avoid vanity): number of probes, number of findings, DAU. A million low-confidence findings destroys trust faster than any outage.

---

## 8. The operating model — how to actually be in the top 10⁻⁹

Talent isn't the differentiator at the top; **feedback loops** are. Build these five and the platform improves without you:

1. **A ground-truth corpus.** Deliberately vulnerable apps (Juice Shop, DVWA, WebGoat, `vulhub` set) with known findings. Every probe change runs against it and reports precision/recall deltas. No probe merges without a corpus result.
2. **A threat model of your own platform, refreshed quarterly.** STRIDE against HCVF itself; every new endpoint gets a STRIDE pass in its PR description. You are building a tool that attackers will target precisely because it holds scope grants and evidence.
3. **Adversarial review of the reviewer.** Once a quarter, hire/borrow a red teamer to attack HCVF. Publish the results internally with the same severity rubric you sell.
4. **ADR discipline.** One page per irreversible decision (Celery vs. Postgres queue; sync vs. async SQLAlchemy; JSONB vs. normalized scope; single vs. multi-tenant DB). Six months from now the *why* is worth more than the code.
5. **A public changelog of capability, with evidence.** Every probe addition ships with a demo target, a recorded run, and the finding it produces. This is simultaneously marketing, regression testing, and documentation.

And the discipline that matters most: **write down what the product cannot do.** The README's authorized-use blockquote is a good start. Extend it to a "Capability status" table (probe × maturity: planned / alpha / beta / GA, each with precision numbers). That table is the single most trust-building artifact a security product can publish — and it is the thing that will keep you from shipping the next overclaim.

---

## 9. What not to build

- **A generic vulnerability scanner.** You will lose to free. Your wedge is proof + authorization + trend.
- **Exploit development / weaponization.** It changes your legal posture, your customer, and your insurance. Stay validation-only; let findings point at remediation.
- **A SIEM.** Ingest and forward; do not store and correlate all security telemetry.
- **An autonomous agent that scans without approval.** One bad autonomous run ends the company. Every autonomous action must be plan-time reviewed and kill-switchable.
- **Your own auth provider.** OIDC exists; use it.
- **A second database before you have measured the first one's ceiling.** Postgres will carry you to 100M findings with partitioning.
- **More probes before the evidence pipeline is trustworthy.** Depth multiplies whatever precision you already have — including bad precision.

---

## 10. The next two weeks, concretely

| Day | Work |
|---|---|
| 1 | All of AUDIT §10 items 1–3,5,7. Tag `v0.2.0`. |
| 2 | Tenant IDOR fix + `scope_grants` table + dual-approval endpoint. Egress guard in `FuzzRunner` (IP pinning, no auto-redirect, per-hop authorize). |
| 3 | `conftest.py` + testcontainers + factories; make `pytest` service-free and green. |
| 4 | CI workflow with 9 gates; ruff + mypy baseline; `alembic heads` check; import-smoke. |
| 5 | State machine module + lease/heartbeat + reaper + chaos test (kill worker). |
| 6 | Outbox + relay; remove direct `.delay()` from the request path; idempotency middleware. |
| 7 | Evidence blob store (S3/MinIO) + `finding.fingerprint` + lifecycle states. |
| 8 | Probe framework interfaces + port the existing GET into `probe:http-reachability`. |
| 9–10 | Six Wave-1 probes: security-headers, tls-config, cookie-flags, cors-policy, http-methods, error-disclosure. |
| 11 | SARIF export + minimal HTML report from evidence. |
| 12 | Ground-truth harness: Juice Shop + DVWA, precision/recall script. |
| 13 | OTel instrumentation + Sentry + worker metrics endpoint. |
| 14 | Write `docs/architecture.md`, `SECURITY.md`, and the README "Capability status" table. Record a 5-minute demo. |

At the end of those two weeks you will have: a platform that boots, isolates tenancy, proves authorization, seals evidence, runs 7 probes, reports in SARIF, and has a CI gate that prevents regression. That is a product someone can pilot. Everything in §2 is then additive rather than foundational.

---

*The name "Hybrid Concolic Validation Fabric" is currently a promise, not a description. Two paths exist: earn it (Wave 4), or rename to what you actually are today — "authorized validation control plane" — and grow into the harder name. The second is faster to ship and infinitely more honest. The first is worth building toward, deliberately, one probe at a time.*
