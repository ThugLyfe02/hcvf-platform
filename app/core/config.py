from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore")

    environment: str = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://hcvf:password@localhost:5432/hcvf"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    api_key_header: str = "X-API-Key"
    hcvf_api_keys: str = "dev-hcvf-key"
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    rate_limit_enabled: bool = True
    scheduler_interval_seconds: int = 5

    #: Agentic engine defaults.
    hunt_budget_requests: int = 200
    hunt_max_rps: float = 5.0
    hunt_lease_seconds: int = 600
    hunt_timeout_seconds: int = 300
    evidence_dir: str = "evidence"
    #: HMAC key for console session cookies. Set HCVF_CONSOLE_SECRET in production.
    console_secret: str = ""
    #: Objective worker pool size and per-batch task cap.
    objective_workers: int = 4
    objective_tasks_per_batch: int = 8
    #: Enforce PostgreSQL row-level security; bind app.tenant_id per request.
    rls_enabled: bool = False
    evidence_key: str = ""
    #: Development only: permit the engine to reach private/loopback addresses.
    allow_private_targets: bool = False

    #: Autonomy. Off by default: a deployment opts in, and each tenant must still
    #: hold an approved autonomy policy before the controller will act.
    autonomy_enabled: bool = False
    autonomy_interval_seconds: int = 60
    autonomy_default_budget_requests: int = 120

    #: Governance and hardening knobs.
    max_request_bytes: int = 1_048_576
    log_redaction: bool = True
    idempotency_ttl_hours: int = 24
    quota_enforced: bool = True
    webhook_timeout_seconds: float = 5.0
    rls_enforced: bool = False

    @property
    def api_keys(self) -> list[str]:
        return [item.strip() for item in self.hcvf_api_keys.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
