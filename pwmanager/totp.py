"""RFC 6238 TOTP helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time


def totp_at(secret_b32: str, timestamp: float, digits: int = 6, period: int = 30) -> str:
    """Generate a TOTP code for a specific Unix timestamp."""
    try:
        key = base64.b32decode(secret_b32.upper().replace(" ", ""), casefold=True)
    except Exception as e:
        raise ValueError(f"Invalid TOTP secret: {e}") from e
    counter = int(timestamp // period)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (
        (h[offset] & 0x7F) << 24
        | (h[offset + 1] & 0xFF) << 16
        | (h[offset + 2] & 0xFF) << 8
        | (h[offset + 3] & 0xFF)
    )
    return str(code % (10**digits)).zfill(digits)


def totp_now(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    """Generate the current TOTP code from a base32 secret."""
    return totp_at(secret_b32, time.time(), digits=digits, period=period)


def totp_seconds_remaining(period: int = 30) -> int:
    return period - int(time.time() % period)
