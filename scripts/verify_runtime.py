from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.core.config import settings


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str


def check_database_url() -> CheckResult:
    passed = settings.database_url.startswith("postgresql+psycopg://")
    detail = settings.database_url if passed else f"unexpected DATABASE_URL: {settings.database_url}"
    return CheckResult("DATABASE_URL uses psycopg 3", passed, detail)


def check_redis_url() -> CheckResult:
    passed = bool(settings.redis_url.strip()) and settings.redis_url.startswith("redis://")
    detail = settings.redis_url if passed else "REDIS_URL is missing or invalid"
    return CheckResult("REDIS_URL is present", passed, detail)


def check_api_key_header() -> CheckResult:
    passed = bool(settings.api_key_header.strip())
    detail = settings.api_key_header if passed else "API_KEY_HEADER is missing"
    return CheckResult("API_KEY_HEADER is present", passed, detail)


def check_python_packages() -> CheckResult:
    packages = (
        "fastapi",
        "celery",
        "sqlalchemy",
        "alembic",
        "redis",
        "psycopg",
        "prometheus_client",
        "pydantic",
        "pydantic_settings",
        "httpx",
        "pytest",
        "uvicorn",
    )
    missing: list[str] = []
    for package in packages:
        try:
            importlib.import_module(package)
        except Exception:
            missing.append(package)

    passed = not missing
    detail = "all required packages import successfully" if passed else f"missing or broken imports: {', '.join(missing)}"
    return CheckResult("Required Python packages", passed, detail)


def check_docker() -> CheckResult:
    docker = shutil.which("docker")
    if docker is None:
        return CheckResult("Docker CLI is available", False, "docker command not found")

    try:
        result = subprocess.run(
            [docker, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CheckResult("Docker CLI is available", False, f"docker check failed: {exc}")

    output = (result.stdout or result.stderr).strip()
    return CheckResult("Docker CLI is available", result.returncode == 0, output or "docker command returned no output")


def main() -> int:
    checks = (
        check_database_url(),
        check_redis_url(),
        check_api_key_header(),
        check_python_packages(),
        check_docker(),
    )

    print("HCVF runtime verification")
    print("=========================")
    failures = 0
    for check in checks:
        status = "PASS" if check.passed else "FAIL"
        print(f"[{status}] {check.name}: {check.detail}")
        if not check.passed:
            failures += 1

    print("=========================")
    if failures:
        print(f"HCVF RUNTIME VERIFY: FAILED ({failures} check(s))")
        return 1

    print("HCVF RUNTIME VERIFY: PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
