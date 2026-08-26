#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failures=0
warnings=0

print_check() {
  local label="$1"
  local level="$2"
  local detail="$3"
  case "$level" in
    ok)
      printf '[OK]   %-28s %s\n' "$label" "$detail"
      ;;
    warn)
      printf '[WARN] %-28s %s\n' "$label" "$detail"
      warnings=$((warnings + 1))
      ;;
    fail)
      printf '[FAIL] %-28s %s\n' "$label" "$detail"
      failures=$((failures + 1))
      ;;
  esac
}

echo "HCVF diagnostics"
echo "================"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  print_check "Docker daemon" ok "running"
else
  print_check "Docker daemon" fail "not available or not running"
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
    print_check "Python version" ok "$version"
  else
    print_check "Python version" fail "found $version; Python 3.13 required"
  fi
else
  print_check "Python version" fail "Python not found"
fi

required_packages=(fastapi celery sqlalchemy alembic redis psycopg prometheus_client pydantic pydantic_settings pytest uvicorn)
if [[ -n "$PYTHON_BIN" ]]; then
  missing=()
  for package in "${required_packages[@]}"; do
    if ! "$PYTHON_BIN" -c "import ${package}" >/dev/null 2>&1; then
      missing+=("$package")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    print_check "Python packages" ok "all required packages import successfully"
  else
    print_check "Python packages" fail "missing: ${missing[*]}"
  fi
else
  print_check "Python packages" fail "cannot check without Python"
fi

COMPOSE=()
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
fi

if [[ ${#COMPOSE[@]} -gt 0 ]]; then
  print_check "Docker Compose" ok "available"
else
  print_check "Docker Compose" fail "not available"
fi

check_service() {
  local service="$1"
  if [[ ${#COMPOSE[@]} -eq 0 ]]; then
    print_check "$service container" warn "not checked because Docker Compose is unavailable"
    return
  fi
  local container_id
  container_id="$(${COMPOSE[@]} ps -q "$service" 2>/dev/null || true)"
  if [[ -z "$container_id" ]]; then
    print_check "$service container" warn "not created yet; bootstrap will start it"
    return
  fi
  local running
  running="$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)"
  local health
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$container_id" 2>/dev/null || true)"
  if [[ "$running" == "true" ]]; then
    print_check "$service container" ok "running ($health)"
  else
    print_check "$service container" warn "created but not running; bootstrap will start it"
  fi
}

check_service postgres
check_service redis

if [[ -f .env ]]; then
  print_check ".env file" ok "present"
elif [[ -f .env.example ]]; then
  print_check ".env file" warn "missing; bootstrap will create it from .env.example"
else
  print_check ".env file" fail "missing and .env.example is unavailable"
fi

echo "================"
if [[ "$failures" -eq 0 ]]; then
  if [[ "$warnings" -gt 0 ]]; then
    echo "HCVF diagnostics: PASSED WITH $warnings WARNING(S)"
  else
    echo "HCVF diagnostics: ALL CHECKS PASSED"
  fi
  exit 0
else
  echo "HCVF diagnostics: $failures CHECK(S) FAILED, $warnings WARNING(S)"
  exit 1
fi
