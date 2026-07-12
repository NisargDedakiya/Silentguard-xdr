"""Centralized application configuration.

Before M1, environment variables were read with ``os.environ.get`` scattered
across ``auth.py``, ``database.py``, ``monitor.py`` and ``alerting.py`` with the
same defaults duplicated in several places (Audit §16). This module makes the
settings a single, typed, documented object so every subsequent feature reads
its configuration from one place.

Backward compatibility: **every environment variable name and default value is
unchanged** from the pre-M1 code, so existing deployments and the Docker
Compose demo behave identically. New settings are additive and default to
values that preserve current behavior.
"""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings, sourced from environment variables.

    Field env aliases keep the historical ``SG_*`` names so nothing about the
    runtime contract changes.
    """

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    # -- identity of the service ------------------------------------------
    service_name: str = "silentguard-xdr"
    environment: str = Field(default="development", alias="SG_ENV")

    # -- auth (unchanged names + defaults) --------------------------------
    admin_token: str = Field(default="silentguard-admin-demo", alias="SG_ADMIN_TOKEN")
    enroll_token: str = Field(default="silentguard-enroll-demo", alias="SG_ENROLL_TOKEN")

    # -- database (unchanged name + default) ------------------------------
    database_url: str = Field(default="sqlite:///./silentguard.db", alias="DATABASE_URL")

    # -- liveness monitor (unchanged names + defaults) --------------------
    unresponsive_seconds: int = Field(default=45, alias="SG_UNRESPONSIVE_SECONDS")
    monitor_interval_seconds: int = Field(default=15, alias="SG_MONITOR_INTERVAL")

    # -- observability (new, additive) ------------------------------------
    log_level: str = Field(default="INFO", alias="SG_LOG_LEVEL")
    # "json" for production log aggregation; "console" for readable local dev.
    log_format: str = Field(default="json", alias="SG_LOG_FORMAT")

    # -- authentication (M4; new, additive) ------------------------------
    # HS256 signing secret for JWTs. Defaults to the admin token so the demo
    # works zero-config; set an independent high-entropy value in production.
    jwt_secret: str = Field(default="", alias="SG_JWT_SECRET")
    access_token_ttl_seconds: int = Field(default=900, alias="SG_ACCESS_TTL")  # 15 min
    refresh_token_ttl_seconds: int = Field(default=1209600, alias="SG_REFRESH_TTL")  # 14 days
    password_min_length: int = Field(default=12, alias="SG_PASSWORD_MIN_LENGTH")
    login_max_attempts: int = Field(default=5, alias="SG_LOGIN_MAX_ATTEMPTS")
    login_lockout_seconds: int = Field(default=900, alias="SG_LOGIN_LOCKOUT_SECONDS")
    # Sliding-window login rate limit (per client IP): N attempts per window.
    login_rate_limit: int = Field(default=10, alias="SG_LOGIN_RATE_LIMIT")
    login_rate_window_seconds: int = Field(default=60, alias="SG_LOGIN_RATE_WINDOW")
    # Optional bootstrap super-admin, created on startup if no users exist.
    bootstrap_admin_email: str = Field(default="", alias="SG_BOOTSTRAP_ADMIN_EMAIL")
    bootstrap_admin_password: str = Field(default="", alias="SG_BOOTSTRAP_ADMIN_PASSWORD")

    @property
    def effective_jwt_secret(self) -> str:
        if self.jwt_secret:
            return self.jwt_secret
        # No explicit secret: derive a 256-bit key from the admin token so the
        # demo signs tokens with an adequately long key. Set SG_JWT_SECRET to an
        # independent high-entropy value in production.
        import hashlib

        return hashlib.sha256(f"sg-jwt::{self.admin_token}".encode()).hexdigest()

    # -- web hardening (new, additive; defaults preserve current behavior) -
    # Comma-separated list. Default "*" matches the pre-M1 CORS policy; set an
    # explicit origin list in production.
    cors_origins: str = Field(default="*", alias="SG_CORS_ORIGINS")
    # Enable HSTS only when the service is actually served over TLS.
    hsts_enabled: bool = Field(default=False, alias="SG_HSTS_ENABLED")
    # Reject request bodies larger than this many bytes (0 disables the check).
    max_request_bytes: int = Field(default=5 * 1024 * 1024, alias="SG_MAX_REQUEST_BYTES")

    @property
    def cors_origin_list(self) -> list[str]:
        raw = self.cors_origins.strip()
        if raw in ("", "*"):
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("prod", "production")


@lru_cache
def get_settings() -> Settings:
    """Process-wide settings singleton (cached)."""
    return Settings()


settings = get_settings()
