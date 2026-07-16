"""RFC 6238 TOTP helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from urllib.parse import quote


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


def totp_uri(
    secret: str,
    name: str,
    issuer: str = "pwmanager",
    digits: int = 6,
    period: int = 30,
) -> str:
    """Build an otpauth://totp URI suitable for authenticator QR apps.

    Format: otpauth://totp/Issuer:Name?secret=SECRET&issuer=Issuer&digits=6&period=30
    """
    secret_clean = secret.upper().replace(" ", "").strip()
    if not secret_clean:
        raise ValueError("TOTP secret is empty")
    label = f"{issuer}:{name}" if issuer else name
    # Path segment: encode but keep colon between issuer and account
    path = quote(label, safe=":")
    params = [
        f"secret={quote(secret_clean, safe='')}",
        f"digits={digits}",
        f"period={period}",
    ]
    if issuer:
        params.append(f"issuer={quote(issuer, safe='')}")
    return f"otpauth://totp/{path}?{'&'.join(params)}"
