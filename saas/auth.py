"""Auth-key hashing, sessions, IP hashing, rate limits. No vault keys here."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from saas.config import (
    AUTH_KEY_BYTES,
    KDF_ITERATIONS,
    KDF_ITERATIONS_MAX,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    SALT_BYTES,
    SESSION_SECONDS,
)

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
    from argon2.low_level import Type as Argon2Type

    _HASHER = PasswordHasher(
        time_cost=2,
        memory_cost=64 * 1024,
        parallelism=1,
        hash_len=32,
        salt_len=16,
        type=Argon2Type.ID,
    )
    ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover - optional extra
    _HASHER = None
    ARGON2_AVAILABLE = False


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: Optional[datetime] = None) -> str:
    value = dt or utcnow()
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def valid_email(email: str) -> bool:
    text = normalize_email(email)
    if len(text) < 3 or len(text) > 254 or " " in text or text.count("@") != 1:
        return False
    local, _, domain = text.partition("@")
    if not local or not domain or "." not in domain or domain.startswith(".") or domain.endswith("."):
        return False
    return True


def new_id() -> str:
    return secrets.token_hex(16)


def hash_ip(ip: str, pepper: bytes) -> str:
    return hmac.new(pepper, (ip or "").encode("utf-8"), hashlib.sha256).hexdigest()


def hash_user_agent(ua: str, pepper: bytes) -> str:
    return hmac.new(pepper, (ua or "").encode("utf-8"), hashlib.sha256).hexdigest()


def dummy_kdf_salt(email: str, pepper: bytes) -> str:
    """Deterministic 32-byte salt for unknown emails (anti-enumeration)."""
    digest = hmac.new(pepper, f"kdf-salt|{normalize_email(email)}".encode("utf-8"), hashlib.sha256).digest()
    import base64

    return base64.b64encode(digest).decode("ascii")


def decode_auth_key(value: str) -> bytes:
    import base64

    if not isinstance(value, str) or not value.strip():
        raise ValueError("auth_key required")
    raw = value.strip()
    pad = (-len(raw)) % 4
    try:
        data = base64.urlsafe_b64decode(raw + ("=" * pad))
    except Exception:
        data = base64.b64decode(raw + ("=" * pad))
    if len(data) != AUTH_KEY_BYTES:
        raise ValueError("auth_key must be 32 bytes")
    return data


def decode_salt(value: str) -> bytes:
    import base64

    raw = (value or "").strip()
    pad = (-len(raw)) % 4
    try:
        data = base64.urlsafe_b64decode(raw + ("=" * pad))
    except Exception:
        data = base64.b64decode(raw + ("=" * pad))
    if len(data) != SALT_BYTES:
        raise ValueError("kdf_salt must be 32 bytes")
    return data


def hash_auth_key(auth_key: bytes) -> str:
    if ARGON2_AVAILABLE:
        return _HASHER.hash(auth_key)
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", auth_key, salt, KDF_ITERATIONS)
    import base64

    return "pbkdf2-sha256${}${}${}".format(
        KDF_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def verify_auth_key(stored: str, auth_key: bytes) -> bool:
    if not stored or stored == "deleted":
        _dummy_verify(auth_key)
        return False
    if stored.startswith("pbkdf2-sha256$"):
        try:
            _, iter_s, salt_b64, hash_b64 = stored.split("$", 3)
            iterations = int(iter_s)
            import base64

            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
            dk = hashlib.pbkdf2_hmac("sha256", auth_key, salt, iterations)
            return hmac.compare_digest(dk, expected)
        except Exception:
            return False
    if ARGON2_AVAILABLE:
        try:
            return bool(_HASHER.verify(stored, auth_key))
        except (VerifyMismatchError, VerificationError, InvalidHash, Exception):
            return False
    _dummy_verify(auth_key)
    return False


_DUMMY_VERIFIER = None


def _dummy_verify(auth_key: bytes) -> None:
    """Spend roughly the same effort as a real miss, to blunt timing leaks."""
    global _DUMMY_VERIFIER
    if _DUMMY_VERIFIER is None:
        _DUMMY_VERIFIER = hash_auth_key(os.urandom(AUTH_KEY_BYTES))
    if ARGON2_AVAILABLE:
        try:
            _HASHER.verify(_DUMMY_VERIFIER, auth_key)
        except Exception:
            pass
        return
    hashlib.pbkdf2_hmac("sha256", auth_key, b"0" * 16, min(KDF_ITERATIONS, 100_000))


def new_session_token() -> Tuple[str, str]:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    return token, token_hash


def hash_token(token: str) -> str:
    return hashlib.sha256((token or "").encode("ascii")).hexdigest()


def session_expiry(seconds: int = SESSION_SECONDS) -> str:
    return isoformat(utcnow() + timedelta(seconds=seconds))


def rate_limited(conn, key: str, limit: int = RATE_LIMIT_MAX, window: int = RATE_LIMIT_WINDOW) -> bool:
    now = int(time.time())
    row = conn.execute(
        "SELECT window_start, count FROM rate_limits WHERE key = ?",
        (key,),
    ).fetchone()
    if row is None or now - int(row["window_start"]) >= window:
        conn.execute(
            "INSERT OR REPLACE INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)",
            (key, now),
        )
        conn.commit()
        return False
    if int(row["count"]) >= limit:
        return True
    conn.execute("UPDATE rate_limits SET count = count + 1 WHERE key = ?", (key,))
    conn.commit()
    return False


def default_kdf_params() -> dict:
    return {
        "alg": "PBKDF2-HMAC-SHA256",
        "hash": "SHA-256",
        "iterations": KDF_ITERATIONS,
        "dk_len": 64,
        "salt_bytes": SALT_BYTES,
        "email_mix": "sha256(salt||email)",
    }


def canonical_kdf_params(params) -> dict:
    """Validate client-supplied KDF params and return the canonical form.

    Only the iteration count is taken from the client, and only inside
    [KDF_ITERATIONS, KDF_ITERATIONS_MAX]. Everything else is fixed by the
    protocol, so unknown keys are dropped rather than stored and echoed back.
    """
    if params is None:
        return default_kdf_params()
    if not isinstance(params, dict):
        raise ValueError("kdf_params must be an object")
    alg = str(params.get("alg") or "PBKDF2-HMAC-SHA256").upper()
    if alg != "PBKDF2-HMAC-SHA256":
        raise ValueError("kdf_params.alg must be PBKDF2-HMAC-SHA256")
    raw = params.get("iterations", KDF_ITERATIONS)
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise ValueError("kdf iterations must be an integer")
    try:
        iterations = int(raw)
    except ValueError as exc:
        raise ValueError("kdf iterations must be an integer") from exc
    if iterations < KDF_ITERATIONS:
        raise ValueError(f"kdf iterations must be at least {KDF_ITERATIONS}")
    if iterations > KDF_ITERATIONS_MAX:
        raise ValueError(f"kdf iterations must be at most {KDF_ITERATIONS_MAX}")
    out = default_kdf_params()
    out["iterations"] = iterations
    return out


def hash_email(email: str, pepper: bytes) -> str:
    return hmac.new(pepper, ("email|" + normalize_email(email)).encode("utf-8"), hashlib.sha256).hexdigest()
