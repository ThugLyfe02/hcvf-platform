# HCVF Platform

**Hybrid Concolic Validation Fabric** is an authorization-first control plane for bounded defensive security validation campaigns. The current operational foundation connects FastAPI, PostgreSQL, Redis, Celery, a database-backed scheduler, a constrained HTTP validation runner, structured audit events, and Prometheus-compatible metrics.

> **Authorized defensive use only.** Run HCVF only against systems you own or are explicitly authorized in writing to test. The platform is not intended for opportunistic scanning, third-party bug-bounty automation, or testing outside an approved scope.

## Current execution model

A campaign is created for one explicitly authorized HTTP or HTTPS target. The API validates the target policy and stores the campaign and authorization reference. Immediate executions create a persisted run and dispatch it to Celery; scheduled executions are claimed by the scheduler with PostgreSQL row locking and then dispatched. The worker executes a bounded, non-destructive GET-only validation pass, persists findings and terminal state, and appends audit events.

The current runner deliberately:

- targets one URL and does not crawl;
- uses GET requests only;
- does not follow redirects;
- caps probe count, response bytes, request duration, and Celery task duration;
- blocks targets outside configured CIDRs by default;
- revalidates DNS resolution during execution;
- records only bounded evidence metadata, not full response bodies.

## Architecture

| Service | Technology | Responsibility |
|---|---|---|
| API | FastAPI | Authentication, campaign control, health, request tracing, rate limiting, metrics |
| Database | PostgreSQL 16 | Tenant, campaign, run, finding, and audit persistence |
| Broker/backend | Redis 7 | Celery transport, task results, and API rate-limit counters |
| Worker | Celery | Idempotent campaign run state machine and validation execution |
| Scheduler | Python service | Claims due campaigns with `FOR UPDATE SKIP LOCKED` and dispatches runs |
| Migration/bootstrap | Alembic | Applies schema revisions and provisions the configured bootstrap tenant |

## Prerequisites

- Python 3.13
- Docker with Docker Compose v2
- PostgreSQL 16 and Redis 7 when running without Docker Compose

The PostgreSQL SQLAlchemy URL must use psycopg 3:

```text
postgresql+psycopg://hcvf:password@localhost:5432/hcvf
```

## Docker Compose quick start

Create local configuration and replace the configured API key before starting the stack:

```bash
git clone https://github.com/ThugLyfe02/hcvf-platform.git
cd hcvf-platform
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Place the generated value in `.env` as `HCVF_API_KEYS`, then start the stack:

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f api worker scheduler
```

The one-shot `migrate` service waits for PostgreSQL, applies `alembic upgrade head`, and creates or updates the configured bootstrap tenants. It is expected to exit successfully after initialization. The API is available at `http://localhost:8000`, and OpenAPI documentation is available at `/docs`.

Verify the process and dependency checks:

```bash
curl --fail http://localhost:8000/api/v1/health/live
curl --fail http://localhost:8000/api/v1/health/ready
curl --fail http://localhost:8000/metrics
```

Stop the stack without deleting persisted PostgreSQL and Redis volumes:

```bash
docker compose down
```

Delete the development data volumes only when an intentional reset is required:

```bash
docker compose down -v
```

## Local development without containerized application services

Start PostgreSQL and Redis, create a virtual environment, install dependencies, initialize the database, and run each process:

```bash
docker compose up -d postgres redis

python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

cp .env.example .env
python -m app.db.init_db
```

API:

```bash
uvicorn app.main:app --reload
```

Celery worker:

```bash
celery -A worker.celery_app:celery_app worker --loglevel=INFO
```

Scheduler:

```bash
python -m worker.scheduler
```

## Campaign API

Set the same API key configured as `HCVF_API_KEYS`:

```bash
export HCVF_API_KEY='replace-with-your-configured-key'
```

Create an immediate campaign for an authorized private target:

```bash
curl --fail-with-body \
  -X POST http://localhost:8000/api/v1/campaigns \
  -H "X-API-Key: ${HCVF_API_KEY}" \
  -H "X-Request-ID: operator-create-001" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Owned service validation",
    "target_url": "http://10.0.0.25:8080/health",
    "authorization_reference": "CHANGE-2026-0042",
    "config": {
      "probe_values": ["baseline", "0", "-1", "unicode-check-✓"]
    }
  }'
```

Create a scheduled campaign by adding an offset-aware timestamp:

```json
{
  "schedule_at": "2026-08-27T02:00:00-04:00"
}
```

Execute a persisted campaign:

```bash
export CAMPAIGN_ID='replace-with-campaign-uuid'

curl --fail-with-body \
  -X POST "http://localhost:8000/api/v1/campaigns/${CAMPAIGN_ID}/execute" \
  -H "X-API-Key: ${HCVF_API_KEY}" \
  -H "X-Request-ID: operator-execute-001"
```

Read state, runs, and findings:

```bash
curl --fail-with-body \
  "http://localhost:8000/api/v1/campaigns/${CAMPAIGN_ID}" \
  -H "X-API-Key: ${HCVF_API_KEY}"

curl --fail-with-body \
  "http://localhost:8000/api/v1/campaigns/${CAMPAIGN_ID}/runs" \
  -H "X-API-Key: ${HCVF_API_KEY}"

curl --fail-with-body \
  "http://localhost:8000/api/v1/campaigns/${CAMPAIGN_ID}/findings" \
  -H "X-API-Key: ${HCVF_API_KEY}"
```

Cancel a created, scheduled, queued, or running campaign:

```bash
curl --fail-with-body \
  -X POST "http://localhost:8000/api/v1/campaigns/${CAMPAIGN_ID}/cancel" \
  -H "X-API-Key: ${HCVF_API_KEY}" \
  -H "X-Request-ID: operator-cancel-001"
```

Every response carries an `X-Request-ID`. A valid caller-supplied ID is preserved; otherwise HCVF generates one. Mutating API operations append audit records in the same database transaction as their state changes.

## Target authorization policy

By default, `ALLOW_PUBLIC_TARGETS=false`. Every resolved address must fall within `ALLOWED_TARGET_CIDRS`, whose development default is limited to loopback and private address space. A hostname resolving to any disallowed address is rejected.

Only an authorized operator should change either control. Enabling public targets does not establish authorization; the operator remains responsible for obtaining and retaining explicit scope approval. HCVF still blocks unspecified, multicast, link-local, reserved, and other non-global destinations unless they are explicitly included in `ALLOWED_TARGET_CIDRS` and not categorically blocked by the runner.

## Migrations and database initialization

All ORM models are imported by `app/models/__init__.py`, and Alembic reads the shared `Base.metadata` from `alembic/env.py`.

Apply migrations only:

```bash
alembic upgrade head
```

Apply migrations and provision the configured bootstrap tenant:

```bash
python -m app.db.init_db
```

Create and verify a new migration after an intentional model change:

```bash
alembic revision --autogenerate -m "describe the schema change"
alembic check
alembic upgrade head
```

Review every autogenerated migration before applying it. The initial revision is `0001_initial_schema`.

## Operational visibility

Structured logs are emitted by the API, worker, migration/bootstrap path, and scheduler. HTTP events include request IDs, normalized routes, status codes, and durations without logging API-key material.

Prometheus metrics are exposed at `/metrics`. They include HTTP volume and latency, rate-limit rejections, API campaign activity, and database-backed gauges for current campaign states, run states, finding severities, and audit-log volume. Database-backed gauges make worker and scheduler progress visible even though those components run in separate processes.

Readiness returns HTTP 503 unless both PostgreSQL `SELECT 1` and Redis `PING` succeed. Liveness verifies only that the API process is serving requests.

## Rate limiting

Campaign routes use a Redis-backed fixed-window limiter. The identity combines the direct client address with a one-way hash of the presented API key; raw keys are never stored in Redis or logs. The limiter returns standard operational headers:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `Retry-After` on HTTP 429

The limiter fails closed with HTTP 503 if Redis is unavailable, and readiness simultaneously reports the dependency outage.

## Tests

Run the isolated suite, which uses SQLite, Celery eager mode, and a local authorized HTTP fixture:

```bash
pytest -q
```

Run the real PostgreSQL, Redis, Celery worker, scheduler-dispatch, and API integration test after starting PostgreSQL and Redis locally:

```bash
HCVF_STACK_TEST=true \
DATABASE_URL=postgresql+psycopg://hcvf:password@127.0.0.1:5432/hcvf \
REDIS_URL=redis://127.0.0.1:6379/15 \
CELERY_BROKER_URL=redis://127.0.0.1:6379/15 \
CELERY_RESULT_BACKEND=redis://127.0.0.1:6379/15 \
pytest -q tests/test_stack_integration.py
```

The CI workflow runs both modes on Python 3.13 with PostgreSQL 16 and Redis 7 service containers.

## Important configuration

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | psycopg 3 local PostgreSQL URL | SQLAlchemy and Alembic database connection |
| `REDIS_URL` | `redis://localhost:6379/0` | Health checks and rate limiting |
| `CELERY_BROKER_URL` | `redis://localhost:6379/1` | Celery broker |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` | Celery result backend |
| `HCVF_API_KEYS` | insecure development placeholder | Comma-separated tenant bootstrap credentials; every production key must be at least 32 characters |
| `RATE_LIMIT_REQUESTS` | `120` | Requests allowed per window and identity |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Fixed-window duration |
| `ALLOW_PUBLIC_TARGETS` | `false` | Whether globally routable target addresses may pass policy |
| `ALLOWED_TARGET_CIDRS` | private and loopback ranges | Explicitly approved address ranges |
| `TARGET_REQUEST_TIMEOUT_SECONDS` | `5.0` | Per-request timeout |
| `TARGET_MAX_RESPONSE_BYTES` | `1048576` | Maximum retained bytes per response |
| `FUZZ_MAX_CASES` | `8` | Maximum configured probe variations |
| `SCHEDULER_POLL_SECONDS` | `5.0` | Scheduler polling interval |
| `SCHEDULER_BATCH_SIZE` | `25` | Maximum campaigns claimed per scheduler iteration |

See `.env.example` for the complete configuration surface.

## License

See [LICENSE](LICENSE).
