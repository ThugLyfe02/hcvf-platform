#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE=(docker compose)
if ! docker compose version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    echo "ERROR: Docker Compose is not available." >&2
    exit 1
  fi
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

wait_for_health() {
  local service="$1"
  local timeout_seconds="${2:-90}"
  local start_time
  start_time="$(date +%s)"

  while true; do
    local container_id
    container_id="$(${COMPOSE[@]} ps -q "$service")"
    if [[ -n "$container_id" ]]; then
      local health
      health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
      if [[ "$health" == "healthy" ]]; then
        echo "$service is healthy"
        return 0
      fi
      if [[ "$health" == "unhealthy" || "$health" == "exited" || "$health" == "dead" ]]; then
        echo "ERROR: $service entered state: $health" >&2
        ${COMPOSE[@]} logs "$service" >&2 || true
        return 1
      fi
    fi

    if (( $(date +%s) - start_time >= timeout_seconds )); then
      echo "ERROR: Timed out waiting for $service to become healthy." >&2
      ${COMPOSE[@]} logs "$service" >&2 || true
      return 1
    fi

    sleep 2
  done
}

echo "Starting PostgreSQL and Redis..."
${COMPOSE[@]} up -d postgres redis

wait_for_health postgres
wait_for_health redis

echo "Applying Alembic migrations..."
if command -v alembic >/dev/null 2>&1; then
  alembic upgrade head
elif [[ -x .venv/bin/alembic ]]; then
  .venv/bin/alembic upgrade head
else
  echo "Alembic is not installed in the active environment." >&2
  echo "Install dependencies with: python3.13 -m pip install -r requirements.txt" >&2
  exit 1
fi

echo "HCVF bootstrap complete: PostgreSQL and Redis are healthy and migrations are at head."
