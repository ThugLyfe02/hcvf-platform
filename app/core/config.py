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
    scheduler_interval_seconds: int = 5

    @property
    def api_keys(self) -> list[str]:
        return [item.strip() for item in self.hcvf_api_keys.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
