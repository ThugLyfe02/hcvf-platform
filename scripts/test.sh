#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTEST_CMD=()
if command -v pytest >/dev/null 2>&1; then
  PYTEST_CMD=(pytest)
elif [[ -x .venv/bin/pytest ]]; then
  PYTEST_CMD=(.venv/bin/pytest)
else
  echo "HCVF TESTS: FAILED"
  echo "pytest is not installed. Install dependencies with: python3.13 -m pip install -r requirements.txt" >&2
  exit 1
fi

echo "Running HCVF test suite..."
if "${PYTEST_CMD[@]}" -vv -x; then
  echo "HCVF TESTS: PASSED"
  exit 0
else
  status=$?
  echo "HCVF TESTS: FAILED (exit code $status)" >&2
  exit "$status"
fi
