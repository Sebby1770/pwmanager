"""Environment-backed SaaS configuration. Never reads secrets from the vault."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
SAAS_DIR = Path(__file__).resolve().parent
WEB_DIR = ROOT / "web"
SCHEMA_PATH = SAAS_DIR / "schema.sql"

DEFAULT_DB = "pwmanager-saas.sqlite"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

FREE_VAULT_MAX_BYTES = 2 * 1024 * 1024
PRO_VAULT_MAX_BYTES = 8 * 1024 * 1024
HTTP_BODY_MAX_BYTES = PRO_VAULT_MAX_BYTES + 64 * 1024
# Every route except PUT /api/vault takes a small JSON object.
JSON_BODY_MAX_BYTES = 16 * 1024
WEBHOOK_BODY_MAX_BYTES = 512 * 1024
REQUEST_TIMEOUT_SECONDS = 30
REVISION_CAP = 20
SESSION_SECONDS = 14 * 24 * 3600
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 5
KDF_ITERATIONS = 600_000
# The browser always derives with KDF_ITERATIONS; stored values above this are
# refused so an account cannot be made to advertise an absurd work factor.
KDF_ITERATIONS_MAX = 10_000_000
LOGIN_ACCOUNT_LIMIT = 10
LOGIN_ACCOUNT_WINDOW = 300
SALT_BYTES = 32
AUTH_KEY_BYTES = 32

PRICE_MONTHLY_AUD = "4"
PRICE_YEARLY_AUD = "40"


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


@dataclass
class Config:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    db_path: str = DEFAULT_DB
    public_url: str = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
    web_root: Path = WEB_DIR
    stripe_secret: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_monthly: str = ""
    stripe_price_yearly: str = ""
    cors_origins: List[str] = field(default_factory=list)
    secure_cookies: bool = False
    trust_proxy: bool = False
    request_timeout: float = REQUEST_TIMEOUT_SECONDS
    # Passkeys: RP id defaults to the public URL's host (localhost for IPs).
    webauthn_rp_id: str = ""

    @property
    def stripe_configured(self) -> bool:
        return bool(
            self.stripe_secret
            and self.stripe_webhook_secret
            and self.stripe_price_monthly
            and self.stripe_price_yearly
        )

    def cors_allowlist(self) -> List[str]:
        origins = list(self.cors_origins)
        base = self.public_url.rstrip("/")
        if base and base not in origins:
            origins.append(base)
        for extra in (
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://127.0.0.1:8137",
            "http://localhost:8137",
        ):
            if extra not in origins:
                origins.append(extra)
        return origins


def load_config(overrides: Optional[dict] = None) -> Config:
    public = _env("PWMANAGER_PUBLIC_URL", f"http://{DEFAULT_HOST}:{DEFAULT_PORT}").rstrip("/")
    cors_raw = _env("PWMANAGER_CORS_ORIGINS", "")
    cors = [item.strip().rstrip("/") for item in cors_raw.split(",") if item.strip()]
    secure = _env("PWMANAGER_SECURE_COOKIES", "").lower() in {"1", "true", "yes"}
    if public.startswith("https://"):
        secure = True
    cfg = Config(
        host=_env("PWMANAGER_HOST", DEFAULT_HOST),
        port=int(_env("PWMANAGER_PORT", str(DEFAULT_PORT)) or DEFAULT_PORT),
        db_path=_env("PWMANAGER_DB", DEFAULT_DB) or DEFAULT_DB,
        public_url=public,
        stripe_secret=_env("PWMANAGER_STRIPE_SECRET"),
        stripe_webhook_secret=_env("PWMANAGER_STRIPE_WEBHOOK_SECRET"),
        stripe_price_monthly=_env("PWMANAGER_STRIPE_PRICE_MONTHLY"),
        stripe_price_yearly=_env("PWMANAGER_STRIPE_PRICE_YEARLY"),
        cors_origins=cors,
        secure_cookies=secure,
        trust_proxy=_env("PWMANAGER_TRUST_PROXY", "").lower() in {"1", "true", "yes"},
        webauthn_rp_id=_env("PWMANAGER_WEBAUTHN_RP_ID"),
    )
    if overrides:
        for key, value in overrides.items():
            setattr(cfg, key, value)
    return cfg
