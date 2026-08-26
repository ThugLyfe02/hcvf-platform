# HCVF Platform

**Hybrid Concolic Validation Fabric**

HCVF is an authorized defensive security validation control plane built with FastAPI, Celery, PostgreSQL, and Redis. Campaigns are tenant-scoped, require explicit authorization attestation before execution, and produce auditable run state.

> **Authorized use only:** Execute HCVF only against systems you own or are explicitly authorized to test. It is not intended for unauthorized third-party scanning or bug-bounty automation against targets without permission.

## Current operational baseline

- FastAPI campaign control plane
- API-key tenant isolation
- Tenant management with one-time secure API-key issuance
- PostgreSQL persistence via SQLAlchemy 2 and psycopg 3
- Alembic migrations with all application models registered in metadata
- Celery worker execution through Redis
- Scheduler loop for due campaigns
- Bounded authorized target validation through `FuzzRunner`
- Structured JSON logging
- Prometheus metrics at `/metrics`
- PostgreSQL and Redis health checks at `/health`
- Circuit breakers around dependency health checks
- Redis-backed fixed-window API rate limiting
- Redis-backed distributed lock primitive with ownership-safe release
- Exponential retry utility with jitter
- Request IDs via `X-Request-ID`
- Security headers on every API response
- Centralized audit service for mutating operations
- Campaign creation, listing, retrieval, cancellation, and execution
- Run and finding retrieval with tenant isolation
- Tenant creation, listing, retrieval, and authorized-target updates
- Integration tests covering campaign, run, finding, tenant, isolation, security-header, smoke, and execution flows

## Requirements

- Python 3.13
- PostgreSQL 16
- Redis 7
- Docker with Docker Compose

## Configuration

Create local configuration from the safe development template:

```bash
cp .env.example .env
```

The default local database URL uses psycopg 3:

```text
postgresql+psycopg://hcvf:password@localhost:5432/hcvf
```

Configured API keys are supplied as a comma-separated `HCVF_API_KEYS` value. On application bootstrap, each configured key is hashed with SHA-256 and provisioned to a tenant record; plaintext keys are not stored in PostgreSQL.

## Local environment

Create a Python environment and install dependencies:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
chmod +x scripts/*.sh
```

The scripts contain `#!/usr/bin/env bash` shebangs. If executable mode has not yet been set in a local checkout, each script can also be invoked explicitly with `bash scripts/<name>.sh`.

## Runtime verification

Before preflight or Docker startup, verify the local Python/runtime prerequisites without requiring containers to be running:

```bash
python3 scripts/verify_runtime.py
```

The verifier checks that `DATABASE_URL` uses psycopg 3, `REDIS_URL` and `API_KEY_HEADER` are present, required Python packages import successfully, and the Docker CLI is installed. Each check prints `PASS` or `FAIL` and the process exits nonzero if any required runtime prerequisite fails.

## Preflight

Before starting Docker or applying migrations, run the static sanity check:

```bash
bash scripts/preflight.sh
```

Preflight verifies required repository files, Python syntax, psycopg 3 configuration, absence of `psycopg2`, and Docker Compose/YAML validity. A failure exits nonzero before containers or database state are changed.

## Validation

For a fresh clone, use this sequence:

```bash
python3 scripts/verify_runtime.py
bash scripts/preflight.sh
./scripts/diagnostics.sh
./scripts/bootstrap.sh
./scripts/test.sh
./scripts/smoke_test.sh
```

`diagnostics.sh` is intentionally safe to run before bootstrap. Containers that have not been created yet and a missing `.env` are warnings rather than fatal errors, because `bootstrap.sh` creates/starts them. Docker, Docker Compose, Python 3.13, and required Python packages remain hard prerequisites.

## Operational endpoints

The root endpoint provides minimal service liveness:

```text
GET /
```

Expected payload:

```json
{
  "service": "hcvf",
  "status": "ok"
}
```

Dependency health and Prometheus metrics are available at:

```text
GET /health
GET /metrics
```

The health endpoint returns HTTP 200 whenever the API can respond and reports either `ok` or `degraded` in the payload.

## Docker Compose

Start the complete stack:

```bash
docker compose up --build
```

The API applies `alembic upgrade head` before startup. PostgreSQL and Redis use named persistent volumes. API, worker, and scheduler use `restart: unless-stopped`. Every service has a health check and explicit container name.

## Campaign API

Create an authorized local-development campaign:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-hcvf-key' \
  -d '{
    "name": "local-owned-service validation",
    "target_url": "http://127.0.0.1:8001/",
    "authorization_attested": true
  }'
```

List campaigns:

```bash
curl http://localhost:8000/api/v1/campaigns \
  -H 'X-API-Key: dev-hcvf-key'
```

Retrieve a campaign:

```bash
curl http://localhost:8000/api/v1/campaigns/<campaign-id> \
  -H 'X-API-Key: dev-hcvf-key'
```

Cancel a non-running campaign:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns/<campaign-id>/cancel \
  -H 'X-API-Key: dev-hcvf-key'
```

Execute a campaign:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns/<campaign-id>/execute \
  -H 'X-API-Key: dev-hcvf-key'
```

## Run and finding API

Run and finding endpoints are nested under their campaign and enforce the authenticated tenant boundary on every database query.

List runs for a campaign:

```bash
curl http://localhost:8000/api/v1/campaigns/<campaign-id>/runs \
  -H 'X-API-Key: dev-hcvf-key'
```

Retrieve a single run:

```bash
curl http://localhost:8000/api/v1/campaigns/<campaign-id>/runs/<run-id> \
  -H 'X-API-Key: dev-hcvf-key'
```

List findings for a run:

```bash
curl http://localhost:8000/api/v1/campaigns/<campaign-id>/runs/<run-id>/findings \
  -H 'X-API-Key: dev-hcvf-key'
```

Retrieve a single finding:

```bash
curl http://localhost:8000/api/v1/campaigns/<campaign-id>/runs/<run-id>/findings/<finding-id> \
  -H 'X-API-Key: dev-hcvf-key'
```

A run or finding outside the authenticated tenant's campaign scope is returned as `404` rather than disclosing cross-tenant existence.

## Tenant management

Tenant administration is available under `/api/v1/tenants`. Every endpoint requires an already provisioned API key. Tenant creation returns a newly generated API key exactly once; only its SHA-256 hash is persisted.

Create a tenant:

```bash
curl -X POST http://localhost:8000/api/v1/tenants \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-hcvf-key' \
  -d '{
    "name": "security-team",
    "authorized_targets": ["https://owned.example.test"]
  }'
```

List tenants:

```bash
curl http://localhost:8000/api/v1/tenants \
  -H 'X-API-Key: dev-hcvf-key'
```

Retrieve a tenant:

```bash
curl http://localhost:8000/api/v1/tenants/<tenant-id> \
  -H 'X-API-Key: dev-hcvf-key'
```

Update authorized targets:

```bash
curl -X PATCH http://localhost:8000/api/v1/tenants/<tenant-id> \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-hcvf-key' \
  -d '{"authorized_targets": ["https://new-owned.example.test"]}'
```

## Logging

HCVF emits structured JSON logs to stdout from FastAPI and Celery. Records include timestamp, level, message, logger, exception context when present, and structured request/campaign/run context when available.

## Metrics

Prometheus metrics are exposed at `GET /metrics`, including campaign creation/completion counters, finding counters, task-duration histograms, and HTTP request metrics.

## Health checks

`GET /health` executes `SELECT 1` against PostgreSQL and `PING` against Redis. Each dependency is protected by a circuit breaker. The endpoint returns HTTP 200 whenever the API can respond and reports `status: ok` or `status: degraded` with dependency and circuit state.

## Security and control primitives

- Request IDs are propagated through `X-Request-ID` and `contextvars`.
- Redis-backed fixed-window rate limiting excludes `/health` and `/metrics`.
- Security headers are added to every response.
- Distributed locks use UUID ownership, Redis `SET NX EX`, and atomic compare-and-delete release.
- Retry support uses bounded exponential backoff with optional jitter.
- Mutating API requests are recorded through the centralized audit service when an authenticated tenant is present.

## Tests

After bootstrap, run:

```bash
./scripts/test.sh
```

The test suite covers campaign flows, run/finding retrieval, cross-tenant run isolation, tenant flows, security headers, health, smoke behavior, and synchronous campaign execution against a local authorized HTTP fixture.

## Alembic development workflow

All models are imported before `Base.metadata` is supplied to Alembic. Generate and apply future schema changes with:

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Review generated migrations before applying them.
