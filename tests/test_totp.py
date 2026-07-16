"""Tests for RFC 6238 TOTP (known vectors via fixed time)."""

from __future__ import annotations

import base64
import time

import pytest

from pwmanager.totp import totp_at, totp_now, totp_seconds_remaining


# RFC 6238 Appendix B uses ASCII secret "12345678901234567890" with SHA-1.
# Our implementation expects base32-encoded secrets (common for authenticator apps).
RFC_SECRET_ASCII = b"12345678901234567890"
RFC_SECRET_B32 = base64.b32encode(RFC_SECRET_ASCII).decode("ascii")

# Known SHA-1 TOTP values from RFC 6238 Table 1 (6 digits, 30s period)
RFC_VECTORS = [
    (59, "94287082"),  # 8-digit in RFC; we recompute for 6 via same algo
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


def _rfc_totp_8(timestamp: int) -> str:
    """Generate 8-digit TOTP matching RFC 6238 SHA-1 test vectors."""
    return totp_at(RFC_SECRET_B32, float(timestamp), digits=8, period=30)


def test_rfc6238_sha1_vectors():
    for ts, expected in RFC_VECTORS:
        assert _rfc_totp_8(ts) == expected


def test_totp_now_matches_totp_at_with_monkeypatch(monkeypatch):
    fixed = 1_111_111_111  # from RFC table
    monkeypatch.setattr(time, "time", lambda: float(fixed))
    assert totp_now(RFC_SECRET_B32, digits=8) == totp_at(
        RFC_SECRET_B32, float(fixed), digits=8
    )
    assert totp_now(RFC_SECRET_B32, digits=8) == "14050471"


def test_totp_six_digits_format():
    code = totp_at(RFC_SECRET_B32, 59.0, digits=6)
    assert len(code) == 6
    assert code.isdigit()


def test_invalid_secret_raises():
    with pytest.raises(ValueError, match="Invalid TOTP"):
        totp_now("not-valid-base32!!!")


def test_totp_seconds_remaining_range(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1000.0)  # 1000 % 30 = 10 → remaining 20
    rem = totp_seconds_remaining(period=30)
    assert 1 <= rem <= 30
    assert rem == 20
