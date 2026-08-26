#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failures=0

print_check() {
  local label="$1"
  local ok="$2"
  local detail="$3"
  if [[ "$ok" == "1" ]]; then
    printf '[OK]   %-28s %s\n' "$label" "$detail"
  else
    printf '[FAIL] %-28s %s\n' "$label" "$detail"
    failures=$((failures + 1))
  fi
}

echo "HCVF diagnostics"
echo "================"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  print_check "Docker daemon" 1 "running"
else
  print_check "Docker daemon" 0 "not available or not running"
fi

PYTHON_BIN=""
if command -v python3.13 >/dev/null 2>&1; then
  PYTHON_BIN="python3.13"
elif [[ -x .venv/bin/python ]]; then
  PYTHON_BIN=".venv/bin/python"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
fi

if [[ -n "$PYTHON_BIN" ]]; then
  version="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || true)"
  major_minor="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
  if [[ "$major_minor" == "3.13" ]]; then
    print_check "Python version" 1 "$version"
  else
    print_check "Python version" 0 "found $version; Python 3.13 required"
  fi
else
  print_check "Python version" 0 "Python not found"
fi

required_packages=(fastapi celery sqlalchemy alembic redis psycopg prometheus_client pydantic pydantic_settings)
if [[ -n "$PYTHON_BIN" ]]; then
  missing=()
  for package in "${required_packages[@]}"; do
    if ! "$PYTHON_BIN" -c "import ${package}" >/dev/null 2>&1; then
      missing+=("$package")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    print_check "Python packages" 1 "all required packages import successfully"
  else
    print_check "Python packages" 0 "missing: ${missing[*]}"
  fi
else
  print_check "Python packages" 0 "cannot check without Python"
fi

COMPOSE=()
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
fi

check_service() {
  local service="$1"
  if [[ ${#COMPOSE[@]} -eq 0 ]]; then
    print_check "$service container" 0 "Docker Compose unavailable"
    return
  fi
  local container_id
  container_id="$(${COMPOSE[@]} ps -q "$service" 2>/dev/null || true)"
  if [[ -z "$container_id" ]]; then
    print_check "$service container" 0 "not created"
    return
  fi
  local running
  running="$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)"
  local health
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$container_id" 2>/dev/null || true)"
  if [[ "$running" == "true" ]]; then
    print_check "$service container" 1 "running ($health)"
  else
    print_check "$service container" 0 "not running"
  fi
}

check_service postgres
check_service redis

if [[ -f .env ]]; then
  print_check ".env file" 1 "present"
else
  print_check ".env file" 0 "missing; run: cp .env.example .env"
fi

echo "================"
if [[ "$failures" -eq 0 ]]; then
  echo "HCVF diagnostics: ALL CHECKS PASSED"
  exit 0
else
  echo "HCVF diagnostics: $failures CHECK(S) FAILED"
  exit 1
fi
