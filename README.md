# HCVF Platform

**Hybrid Concolic Validation Fabric**

HCVF is an authorized defensive security validation control plane built with FastAPI, Celery, PostgreSQL, and Redis. Campaigns are tenant-scoped, require explicit authorization attestation before execution, and produce auditable run state.

> **Authorized use only:** Execute HCVF only against systems you own or are explicitly authorized to test. It is not intended for unauthorized third-party scanning or bug-bounty automation against targets without permission.

## Current operational baseline

- FastAPI campaign control plane
- API-key tenant isolation
- PostgreSQL persistence via SQLAlchemy 2 and psycopg 3
- Alembic migrations with all application models registered in metadata
- Celery worker execution through Redis
- Scheduler loop for due campaigns
- Bounded authorized target validation through `FuzzRunner`
- Structured JSON logging
- Prometheus metrics at `/metrics`
- PostgreSQL and Redis health checks at `/health`
- Redis-backed fixed-window API rate limiting
- Request IDs via `X-Request-ID`
- Audit records for mutating API operations
- Campaign creation, listing, retrieval, cancellation, and execution
- Integration tests covering API campaign flow and execution

## Requirements

- Python 3.13
- PostgreSQL 16
- Redis 7
- Docker and Docker Compose, if using containers

## Configuration

Copy the example configuration and change the development API key before using the service outside a local environment:

```bash
cp .env.example .env
```

The default local database URL uses psycopg 3:

```text
postgresql+psycopg://hcvf:password@localhost:5432/hcvf
```

Configured API keys are supplied as a comma-separated `HCVF_API_KEYS` value. On application bootstrap, each configured key is hashed with SHA-256 and provisioned to a tenant record; plaintext keys are not stored in PostgreSQL.

## Local startup

Install dependencies:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start PostgreSQL and Redis:

```bash
docker compose up -d postgres redis
```

Initialize the database and provision configured tenants:

```bash
python -m app.db.init_db
```

Equivalent migration-only command:

```bash
alembic upgrade head
```

Start the API:

```bash
uvicorn app.main:app --reload
```

Start a worker in another shell:

```bash
celery -A worker.celery_app:celery_app worker --loglevel=info
```

Start the scheduler in another shell:

```bash
python -m worker.scheduler
```

## Docker Compose

The full stack applies `alembic upgrade head` before API startup and persists PostgreSQL and Redis data using named volumes:

```bash
docker compose up --build
```

All services use restart policies and health checks. The API health check calls `/health`; the worker uses Celery inspect ping; the scheduler verifies Redis connectivity.

## API example

Create an authorized campaign:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: dev-hcvf-key' \
  -d '{
    "name": "owned-service validation",
    "target_url": "https://service.example.test/",
    "authorization_attested": true
  }'
```

List campaigns:

```bash
curl http://localhost:8000/api/v1/campaigns \
  -H 'X-API-Key: dev-hcvf-key'
```

Cancel a non-running campaign:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns/<campaign-id>/cancel \
  -H 'X-API-Key: dev-hcvf-key'
```

Execute it using the returned campaign ID:

```bash
curl -X POST http://localhost:8000/api/v1/campaigns/<campaign-id>/execute \
  -H 'X-API-Key: dev-hcvf-key'
```

## Logging

HCVF emits structured JSON logs to stdout from both FastAPI and Celery. Each record includes:

- `timestamp`
- `level`
- `message`
- `logger`
- exception details when present

Operational context such as `request_id`, `tenant_id`, `campaign_id`, `run_id`, task duration, and finding identifiers is included as structured fields when available. Container runtimes can forward stdout directly to a centralized logging system without custom file rotation inside HCVF.

## Metrics

Prometheus metrics are exposed at:

```text
GET /metrics
```

The endpoint includes application metrics such as:

- `hcvf_campaigns_created_total`
- `hcvf_campaigns_completed_total`
- `hcvf_findings_detected_total`
- `hcvf_task_duration_seconds`

Prometheus can scrape the API service directly at `http://<api-host>:8000/metrics`.

## Health checks

Dependency health is exposed at:

```text
GET /health
```

The handler executes `SELECT 1` against PostgreSQL and `PING` against Redis. A fully healthy response returns HTTP 200 with `status: ok`. If either dependency is unavailable, HCVF returns HTTP 503 with `status: degraded` and per-dependency state.

Example:

```json
{
  "status": "ok",
  "dependencies": {
    "postgres": {"status": "ok"},
    "redis": {"status": "ok"}
  }
}
```

## Request IDs

Every request receives an `X-Request-ID`. If the client supplies one, HCVF propagates it; otherwise HCVF generates a UUID. The request ID is stored in request state, propagated using `contextvars`, returned in the response header, and included in audit/logging context where applicable.

## Rate limiting

API traffic is protected by a Redis-backed fixed-window limiter. `/health` and `/metrics` are excluded so orchestration and monitoring remain functional.

Configuration:

```text
RATE_LIMIT_REQUESTS=120
RATE_LIMIT_WINDOW_SECONDS=60
```

The limiter keys requests by a SHA-256-derived identifier rather than storing plaintext API keys in Redis. Requests exceeding the configured limit receive HTTP 429 and a `Retry-After` header. If Redis is unavailable, protected requests fail closed with HTTP 503 because the service cannot reliably enforce the configured policy.

## Audit logging

POST, PUT, PATCH, and DELETE operations are written to the `audit_logs` table when an authenticated tenant is present. GET operations are not written by the audit middleware. Audit records include tenant, actor, action, resource context, request ID, response status, and timestamps.

## Tests

With PostgreSQL and Redis running and the database migrated:

```bash
pytest -q
```

`tests/test_campaign_flow.py` verifies campaign creation, listing, and cancellation through FastAPI. The execution integration test starts a local authorized HTTP fixture, executes the Celery task synchronously, and verifies the persisted run and finding.

## Alembic development workflow

All models are imported by `app/models/__init__.py`, and `alembic/env.py` points `target_metadata` at the shared declarative `Base`. New schema changes can therefore be generated with:

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Review generated migrations before applying them.
