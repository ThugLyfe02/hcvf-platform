#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HOST="127.0.0.1"
PORT="${HCVF_SMOKE_PORT:-8000}"
BASE_URL="http://${HOST}:${PORT}"
TIMEOUT_SECONDS="${HCVF_SMOKE_TIMEOUT:-30}"
LOG_FILE="${HCVF_SMOKE_LOG:-/tmp/hcvf-smoke-uvicorn.log}"

UVICORN_CMD=()
if command -v uvicorn >/dev/null 2>&1; then
  UVICORN_CMD=(uvicorn)
elif [[ -x .venv/bin/uvicorn ]]; then
  UVICORN_CMD=(.venv/bin/uvicorn)
else
  echo "HCVF SMOKE TEST: FAILED"
  echo "uvicorn is not installed. Install dependencies with: python3.13 -m pip install -r requirements.txt" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${API_PID:-}" ]] && kill -0 "$API_PID" >/dev/null 2>&1; then
    kill "$API_PID" >/dev/null 2>&1 || true
    wait "$API_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "Starting HCVF API on ${BASE_URL}..."
"${UVICORN_CMD[@]}" app.main:app --host "$HOST" --port "$PORT" >"$LOG_FILE" 2>&1 &
API_PID=$!

start_time="$(date +%s)"
health_body=""
health_code=""
while true; do
  if ! kill -0 "$API_PID" >/dev/null 2>&1; then
    echo "HCVF SMOKE TEST: FAILED"
    echo "API process exited before becoming reachable." >&2
    cat "$LOG_FILE" >&2 || true
    exit 1
  fi

  response="$(curl -sS --max-time 3 -w $'\n%{http_code}' "${BASE_URL}/health" 2>/dev/null || true)"
  health_code="${response##*$'\n'}"
  health_body="${response%$'\n'*}"

  if [[ "$health_code" == "200" ]]; then
    break
  fi

  if (( $(date +%s) - start_time >= TIMEOUT_SECONDS )); then
    echo "HCVF SMOKE TEST: FAILED"
    echo "Timed out waiting for ${BASE_URL}/health" >&2
    cat "$LOG_FILE" >&2 || true
    exit 1
  fi

  sleep 1
done

if ! printf '%s' "$health_body" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"(ok|degraded)"'; then
  echo "HCVF SMOKE TEST: FAILED"
  echo "Health endpoint returned an unexpected payload: $health_body" >&2
  exit 1
fi

echo "Health endpoint: PASS (HTTP 200)"
echo "Health payload: $health_body"

metrics_headers="$(mktemp)"
metrics_body="$(mktemp)"
trap 'rm -f "$metrics_headers" "$metrics_body"; cleanup' EXIT INT TERM

metrics_code="$(curl -sS --max-time 5 -D "$metrics_headers" -o "$metrics_body" -w '%{http_code}' "${BASE_URL}/metrics")"
if [[ "$metrics_code" != "200" ]]; then
  echo "HCVF SMOKE TEST: FAILED"
  echo "Metrics endpoint returned HTTP $metrics_code" >&2
  exit 1
fi

if ! grep -qi '^content-type:.*text/plain' "$metrics_headers"; then
  echo "HCVF SMOKE TEST: FAILED"
  echo "Metrics endpoint did not return Prometheus-compatible text content." >&2
  cat "$metrics_headers" >&2
  exit 1
fi

if ! grep -Eq '^# (HELP|TYPE) ' "$metrics_body"; then
  echo "HCVF SMOKE TEST: FAILED"
  echo "Metrics endpoint response does not look like Prometheus exposition format." >&2
  exit 1
fi

echo "Metrics endpoint: PASS (HTTP 200, Prometheus exposition detected)"
echo "HCVF SMOKE TEST: PASSED"
