"""
PhishShield Backend – App Configuration
Loads all settings from environment variables (never hardcoded secrets).
"""
from __future__ import annotations

import base64
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Application ──────────────────────────────────────────────────────────
    app_name: str = "PhishShield"
    debug: bool = False

    # ── Security ─────────────────────────────────────────────────────────────
    aes_master_key: str  # Required – 32-byte URL-safe base64
    jwt_secret: str  # Required
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # ── Admin seed credentials ────────────────────────────────────────────────
    admin_email: str = "admin@phishshield.local"
    admin_password: str  # Required

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./phishshield.db"

    # ── TLS ──────────────────────────────────────────────────────────────────
    tls_cert_file: str = "certs/server.crt"
    tls_key_file: str = "certs/server.key"
    tls_ca_file: str = "certs/ca.crt"

    # ── SMTP Ingest ──────────────────────────────────────────────────────────
    smtp_host: str = "0.0.0.0"
    smtp_port: int = 2525
    smtp_require_starttls: bool = True

    # ── API ──────────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8443
    cors_origins: str = "https://localhost:5173,https://localhost:3000"

    # ── Risk Thresholds ──────────────────────────────────────────────────────
    threshold_suspicious: int = 41
    threshold_malicious: int = 71

    # ── DNS Mode ─────────────────────────────────────────────────────────────
    auth_dns_mode: str = "live"  # "live" or "test"

    # ── VirusTotal (optional) ────────────────────────────────────────────────
    vt_api_key: str = ""

    # ── Rate Limiting ────────────────────────────────────────────────────────
    rate_limit_per_minute: int = 60

    # ── Replay Protection ────────────────────────────────────────────────────
    replay_timestamp_window_seconds: int = 300

    @property
    def aes_master_key_bytes(self) -> bytes:
        """Decode the base64-encoded AES master key to raw bytes, with sha256 fallback."""
        try:
            raw = base64.urlsafe_b64decode(self.aes_master_key + "==")
            if len(raw) == 32:
                return raw
        except Exception:
            pass
        import hashlib
        return hashlib.sha256(self.aes_master_key.encode("utf-8")).digest()

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance (singleton)."""
    return Settings()
