from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEVELOPMENT_SECRET = "development-only-secret-change-me"  # noqa: S105


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINEL_", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    secret_key: str = DEVELOPMENT_SECRET

    database_url: str = "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel"
    redis_url: str = "redis://localhost:6379/0"

    # Browser origins allowed to call the API directly. The web app normally proxies
    # API calls through its own origin, so this list can stay empty.
    cors_origins: list[str] = Field(default_factory=list)

    # Only enable when the API is reachable exclusively through a proxy that sets
    # X-Forwarded-For; otherwise clients could spoof their address to dodge rate limits.
    trust_forwarded_for: bool = False

    session_cookie_name: str = "sentinel_session"
    session_lifetime_hours: int = 24 * 7
    session_cookie_secure: bool = True

    rate_limit_backend: Literal["redis", "memory"] = "redis"

    upload_dir: Path = Path("/var/lib/sentinel/uploads")
    max_upload_bytes: int = 25 * 1024 * 1024

    # Run scans inside the API process instead of handing them to a Celery worker.
    # Intended for tests and single-process demos only.
    run_scans_inline: bool = False

    # --- Providers. Anything left unset is reported to users as unavailable. ---
    urlhaus_auth_key: str | None = None
    urlhaus_feed_url: str = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    malwarebazaar_feed_url: str = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
    feed_sync_enabled: bool = True
    feed_stale_after_hours: int = 48
    indicator_retention_days: int = 90

    rdap_base_url: str = "https://rdap.org"

    clamav_host: str | None = None
    clamav_port: int = 3310

    @model_validator(mode="after")
    def _refuse_default_secret_in_production(self) -> "Settings":
        if self.environment == "production" and self.secret_key == DEVELOPMENT_SECRET:
            raise ValueError("SENTINEL_SECRET_KEY must be set to a unique value in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
