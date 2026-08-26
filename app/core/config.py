from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables and ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "HCVF Platform"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    json_logs: bool = True

    database_url: str = "postgresql+psycopg://hcvf:password@localhost:5432/hcvf"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str | None = "redis://localhost:6379/1"
    celery_result_backend: str | None = "redis://localhost:6379/2"
    celery_task_always_eager: bool = False
    celery_task_eager_propagates: bool = True

    api_key_header: str = "X-API-Key"
    bootstrap_tenant_name: str = "HCVF Development Tenant"
    hcvf_api_keys: SecretStr | None = None
    bootstrap_api_key: SecretStr | None = SecretStr("change-me-before-use")

    rate_limit_enabled: bool = True
    rate_limit_requests: int = Field(default=120, ge=1, le=100_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=86_400)

    allow_public_targets: bool = False
    allowed_target_cidrs: str = (
        "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
        "::1/128,fc00::/7"
    )
    target_request_timeout_seconds: float = Field(default=5.0, gt=0.1, le=60.0)
    target_max_response_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)
    fuzz_max_cases: int = Field(default=8, ge=1, le=64)

    scheduler_poll_seconds: float = Field(default=5.0, ge=0.25, le=300.0)
    scheduler_batch_size: int = Field(default=25, ge=1, le=500)

    database_connect_retries: int = Field(default=30, ge=1, le=300)
    database_connect_retry_seconds: float = Field(default=1.0, ge=0.1, le=30.0)

    @field_validator("database_url")
    @classmethod
    def require_psycopg3_for_postgres(cls, value: str) -> str:
        lowered = value.lower()
        is_postgres = lowered.startswith(("postgresql://", "postgres://", "postgresql+"))
        if is_postgres and not lowered.startswith("postgresql+psycopg://"):
            raise ValueError(
                "PostgreSQL DATABASE_URL must use the psycopg 3 dialect: "
                "postgresql+psycopg://"
            )
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        return value.upper()

    @property
    def configured_api_keys(self) -> tuple[str, ...]:
        """
        Return the unique bootstrap keys configured for tenant provisioning.

        ``HCVF_API_KEYS`` is the primary setting and accepts a comma-separated list.
        ``BOOTSTRAP_API_KEY`` remains as a backward-compatible single-key fallback.
        """

        configured = self.hcvf_api_keys
        if configured is not None and configured.get_secret_value().strip():
            raw_value = configured.get_secret_value()
        elif self.bootstrap_api_key is not None:
            raw_value = self.bootstrap_api_key.get_secret_value()
        else:
            raw_value = ""

        unique_keys: list[str] = []
        seen: set[str] = set()
        for item in raw_value.split(","):
            api_key = item.strip()
            if api_key and api_key not in seen:
                unique_keys.append(api_key)
                seen.add(api_key)
        return tuple(unique_keys)

    @property
    def effective_celery_broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def effective_celery_result_backend(self) -> str:
        return self.celery_result_backend or self.redis_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
