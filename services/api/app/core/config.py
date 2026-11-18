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
    # Connection used by scan workers. Point it at a restricted role (see
    # infrastructure/database/worker-role.sql); defaults to database_url.
    worker_database_url: str | None = None

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
    # Free abuse.ch Auth-Key (https://auth.abuse.ch/). Since October 2026 abuse.ch serves
    # its URLhaus, ThreatFox and MalwareBazaar data only with a key; it is also used for
    # live URLhaus lookups.
    urlhaus_auth_key: str | None = None
    # Leave empty to use abuse.ch's keyed exports. An override may contain "{auth_key}".
    urlhaus_feed_url: str = ""
    malwarebazaar_feed_url: str = ""
    threatfox_feed_url: str = ""
    # Free for non-commercial use; see https://openphish.com/terms.html.
    openphish_feed_url: str = "https://openphish.com/feed.txt"
    feed_sync_enabled: bool = True
    feed_stale_after_hours: int = 48
    indicator_retention_days: int = 90

    rdap_base_url: str = "https://rdap.org"

    clamav_host: str | None = None
    clamav_port: int = 3310

    # Outgoing email. "smtp" sends for real; "outbox" stores messages in the database
    # (development and tests); "disabled" turns off every feature that needs email.
    email_backend: Literal["smtp", "outbox", "disabled"] = "disabled"
    email_from: str = "Qalaa <no-reply@localhost>"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_starttls: bool = True
    # Public address of the web app, used to build links in emails.
    public_url: str = "http://localhost:8080"

    # Scales every rate limit. Raise it only for load tests on a private instance;
    # production refuses values other than 1.
    rate_limit_multiplier: float = 1.0

    # Bearer token Prometheus uses to read /api/v1/system/metrics. Unset: no metrics.
    metrics_token: str | None = None

    # Extra YARA rule files (*.yar) to load next to the built-in ones.
    yara_rules_dir: Path | None = None
    max_apk_bytes: int = 100 * 1024 * 1024
    max_image_bytes: int = 10 * 1024 * 1024

    # Render pages in an isolated headless browser during website analysis. Every
    # request the browser makes is fulfilled by the SSRF-protected fetcher.
    browser_rendering: bool = False
    browser_executable: str | None = None
    # Hashes of real sign-in pages for visual phishing detection (see analyzers/visual.py).
    brand_reference_file: Path | None = None

    # Optional reputation services. Each is reported as unavailable until configured.
    web_risk_api_key: str | None = None
    virustotal_api_key: str | None = None
    crtsh_base_url: str = "https://crt.sh"

    # Web Push (VAPID). Generate a key pair once: python -m app.cli generate-vapid-keys
    vapid_public_key: str | None = None
    vapid_private_key: str | None = None
    vapid_subject: str = "mailto:security@localhost"

    # Have I Been Pwned (breached-account search). Pwned Passwords needs no key and
    # is queried from the browser with k-anonymity, never through this server.
    hibp_api_key: str | None = None
    # STIX export of community-verified indicators (/intelligence/stix):
    # "off", "account" (signed-in users and API keys; the default) or "public".
    share_feed: Literal["off", "account", "public"] = "account"

    # Messaging bots. Each is off until its credentials are set.
    telegram_bot_token: str | None = None
    # Random value Telegram echoes in X-Telegram-Bot-Api-Secret-Token on every update.
    telegram_webhook_secret: str | None = None
    whatsapp_access_token: str | None = None
    whatsapp_phone_number_id: str | None = None
    # Echoed back during Meta's webhook verification handshake.
    whatsapp_verify_token: str | None = None
    # Used to check the X-Hub-Signature-256 header on every delivery.
    whatsapp_app_secret: str | None = None

    # Scan-by-email: the mail provider's inbound webhook (Mailgun, Postmark, SES via
    # SNS, Cloudflare Email Workers…) posts the raw message with this bearer token.
    inbound_email_token: str | None = None
    inbound_email_address: str | None = None

    # MobSF (Mobile Security Framework) for deeper APK static analysis. Optional.
    mobsf_url: str | None = None
    mobsf_api_key: str | None = None

    # AI explanations. Both are required; without them the feature is reported as
    # unavailable. Only sanitised findings are ever sent, never files or message text.
    openai_api_key: str | None = None
    openai_model: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    # Vision-capable model for screenshot reading; falls back to openai_model.
    openai_vision_model: str | None = None

    # Self-hosted WireGuard VPN (docker compose --profile vpn). Off until an endpoint is set.
    # The endpoint is what devices connect to: the server's public name or address and UDP port.
    vpn_endpoint: str | None = None
    vpn_subnet: str = "10.13.13.0/24"
    vpn_dns: str = "1.1.1.1"
    vpn_max_peers_per_user: int = 5
    # Shared with the wireguard container, which fetches peers and reports traffic with it.
    vpn_sync_token: str | None = None

    @model_validator(mode="after")
    def _refuse_default_secret_in_production(self) -> "Settings":
        if self.environment == "production" and self.secret_key == DEVELOPMENT_SECRET:
            raise ValueError("SENTINEL_SECRET_KEY must be set to a unique value in production")
        if self.vpn_endpoint and (not self.vpn_sync_token or len(self.vpn_sync_token) < 32):
            raise ValueError(
                "SENTINEL_VPN_SYNC_TOKEN must be at least 32 characters when the VPN is on"
            )
        if self.environment == "production" and self.rate_limit_multiplier != 1.0:
            raise ValueError("SENTINEL_RATE_LIMIT_MULTIPLIER cannot be used in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
