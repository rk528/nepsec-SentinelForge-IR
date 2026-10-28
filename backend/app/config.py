"""Application settings.

All configuration comes from environment variables (or a local, git-ignored
``.env`` file during development). Secrets are never given defaults.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: Literal["development", "test", "production"] = "development"
    app_version: str = "0.1.0"

    # Pooled connection string for request handling (Neon "-pooler" host in production).
    database_url: SecretStr = Field(default=SecretStr(""))
    # Direct (unpooled) connection string, used only for migrations.
    database_url_unpooled: SecretStr | None = None

    # Session cookies
    session_ttl_hours: int = 12
    session_idle_minutes: int = 120
    cookie_secure: bool = True
    session_cookie_name: str = "sf_session"
    csrf_cookie_name: str = "sf_csrf"

    # Comma separated list of origins allowed to call the API directly (CORS).
    # The frontend normally reaches the API through a same-origin rewrite, so
    # this can stay empty.
    cors_origins: str = ""

    # Demo mode allows passwordless sign-in as synthetic demo users.
    demo_mode: bool = False

    # Request body limits (bytes)
    max_body_bytes: int = 256 * 1024
    max_ingest_body_bytes: int = 1024 * 1024

    # Rate limits (requests per window)
    login_rate_limit: int = 10
    login_rate_window_seconds: int = 300
    ingest_rate_limit: int = 60
    ingest_rate_window_seconds: int = 60
    intel_rate_limit: int = 30
    intel_rate_window_seconds: int = 60

    # Threat intelligence providers (optional; the app works without them)
    virustotal_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    # NepSec Intel (https://nepsecintel.kuinkel.com): aggregates many sources behind one API key.
    nepsecintel_api_key: SecretStr | None = None
    nepsecintel_base_url: str = "https://nepsecintel.kuinkel.com"
    nepsecintel_timeout_seconds: float = 25.0
    intel_cache_hours: int = 24
    intel_http_timeout_seconds: float = 8.0

    # Transactional email (onboarding and password reset) through Resend (https://resend.com).
    # Without a key, invitations are not emailed and the admin is shown the temporary password once.
    resend_api_key: SecretStr | None = None
    mail_from: str = "SentinelForge IR <no-reply@kuinkel.com>"
    # Optional monitored mailbox for replies; a real reply path also helps deliverability.
    mail_reply_to: str | None = None
    mail_timeout_seconds: float = 10.0
    # Public URL of the frontend, used to build sign-in and password links in emails.
    app_base_url: str = "http://127.0.0.1:3000"
    password_link_hours: int = 24

    # Trust X-Forwarded-For from the hosting platform's proxy for client IPs.
    trust_proxy_headers: bool = True

    @field_validator("database_url", mode="after")
    @classmethod
    def _normalise_driver(cls, value: SecretStr) -> SecretStr:
        return SecretStr(normalise_db_url(value.get_secret_value()))

    @field_validator("database_url_unpooled", mode="after")
    @classmethod
    def _normalise_unpooled(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None or not value.get_secret_value():
            return None
        return SecretStr(normalise_db_url(value.get_secret_value()))

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


def normalise_db_url(url: str) -> str:
    """Force the psycopg 3 driver for SQLAlchemy regardless of how the URL was copied."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


@lru_cache
def get_settings() -> Settings:
    return Settings()
