#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failures=0

pass() {
  printf '[PASS] %s\n' "$1"
}

fail() {
  printf '[FAIL] %s\n' "$1"
  failures=$((failures + 1))
}

section() {
  printf '\n%s\n' "$1"
  printf '%*s\n' "${#1}" '' | tr ' ' '-'
}

section "HCVF preflight"

required_files=(
  "app/main.py"
  "app/core/config.py"
  "app/db/base.py"
  "app/models/__init__.py"
  "alembic/env.py"
  "alembic.ini"
  "requirements.txt"
  "docker-compose.yml"
  ".env.example"
  "README.md"
  "scripts/bootstrap.sh"
  "scripts/diagnostics.sh"
  "scripts/test.sh"
  "scripts/smoke_test.sh"
)

missing_files=()
for path in "${required_files[@]}"; do
  [[ -e "$path" ]] || missing_files+=("$path")
done
if [[ ${#missing_files[@]} -eq 0 ]]; then
  pass "Required repository files are present"
else
  fail "Missing required files: ${missing_files[*]}"
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
  if "$PYTHON_BIN" - <<'PY'
from pathlib import Path
import py_compile
import sys

failures = []
for path in sorted(Path('.').rglob('*.py')):
    parts = set(path.parts)
    if parts & {'.venv', 'venv', 'fuzz_env'}:
        continue
    try:
        py_compile.compile(str(path), doraise=True)
    except Exception as exc:
        failures.append(f"{path}: {exc}")

if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)
PY
  then
    pass "Python syntax check passed for all repository Python files"
  else
    fail "Python syntax check failed"
  fi
else
  fail "Python interpreter not found for syntax validation"
fi

psycopg2_hits="$(grep -RIn --exclude-dir=.git --exclude-dir=.venv --exclude-dir=venv --exclude-dir=fuzz_env --exclude='README.md' --exclude='scripts/preflight.sh' 'psycopg2' . 2>/dev/null || true)"
if [[ -z "$psycopg2_hits" ]]; then
  pass "No psycopg2 references found"
else
  printf '%s\n' "$psycopg2_hits"
  fail "psycopg2 references remain"
fi

if grep -q 'postgresql+psycopg://' .env.example \
  && grep -q 'postgresql+psycopg://' app/core/config.py \
  && grep -q 'postgresql+psycopg://' docker-compose.yml \
  && grep -q 'settings.database_url' alembic/env.py; then
  pass "psycopg 3 database configuration is consistent"
else
  fail "psycopg 3 database configuration is inconsistent"
fi

COMPOSE=()
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
fi

if [[ ${#COMPOSE[@]} -gt 0 ]]; then
  if "${COMPOSE[@]}" config -q >/dev/null 2>&1; then
    pass "Docker Compose configuration is valid"
  else
    "${COMPOSE[@]}" config >&2 || true
    fail "Docker Compose configuration is invalid"
  fi
elif [[ -n "$PYTHON_BIN" ]] && "$PYTHON_BIN" -c 'import yaml' >/dev/null 2>&1; then
  if "$PYTHON_BIN" - <<'PY'
from pathlib import Path
import yaml

with Path('docker-compose.yml').open('r', encoding='utf-8') as handle:
    data = yaml.safe_load(handle)
if not isinstance(data, dict) or not isinstance(data.get('services'), dict):
    raise SystemExit(1)
PY
  then
    pass "docker-compose.yml is valid YAML"
  else
    fail "docker-compose.yml is invalid YAML"
  fi
else
  fail "Cannot validate docker-compose.yml: Docker Compose or PyYAML is required"
fi

section "Result"
if [[ "$failures" -eq 0 ]]; then
  echo "HCVF PREFLIGHT: PASSED"
  exit 0
fi

echo "HCVF PREFLIGHT: FAILED ($failures check(s))"
exit 1
