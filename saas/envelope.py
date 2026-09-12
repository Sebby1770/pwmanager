"""Validate client-side vault envelopes. The server must never see plaintext."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, Mapping, Tuple

REQUIRED_KEYS = ("v", "nonce", "ct", "kdf")

# Top-level keys that would indicate a client uploaded vault plaintext.
FORBIDDEN_TOP_LEVEL = frozenset(
    {
        "password",
        "passwords",
        "password_plain",
        "master_password",
        "masterPassword",
        "totp_secret",
        "totp",
        "entries",
        "username",
        "card_number",
        "cardNumber",
        "pan",
        "cvv",
        "cvc",
        "plaintext",
        "secret",
        "secrets",
        "notes",
        "history",
    }
)

_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]+=*$")


class EnvelopeError(ValueError):
    """Raised when a vault payload is not an opaque ciphertext envelope."""


def _b64decode(label: str, value: str, expected_len: int = 0, min_len: int = 1) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise EnvelopeError(f"{label} must be a base64 string")
    raw = value.strip()
    if not _B64_RE.match(raw):
        raise EnvelopeError(f"{label} is not valid base64")
    pad = (-len(raw)) % 4
    try:
        data = base64.urlsafe_b64decode(raw + ("=" * pad))
    except Exception as exc:
        try:
            data = base64.b64decode(raw + ("=" * pad), validate=True)
        except Exception:
            raise EnvelopeError(f"{label} is not valid base64") from exc
    if expected_len and len(data) != expected_len:
        raise EnvelopeError(f"{label} must be {expected_len} bytes")
    if len(data) < min_len:
        raise EnvelopeError(f"{label} is too short")
    return data


def parse_envelope(payload: Any) -> Dict[str, Any]:
    """Return a normalised envelope or raise EnvelopeError.

    Required shape: ``{v, nonce, ct, kdf}``. Optional non-secret metadata
    (``updated_at``) is allowed. Anything that looks like vault plaintext is
    rejected so a buggy client cannot upload secrets in the clear.
    """
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = json.loads(bytes(payload).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EnvelopeError("envelope must be JSON") from exc
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise EnvelopeError("envelope must be JSON") from exc
    if not isinstance(payload, Mapping):
        raise EnvelopeError("envelope must be a JSON object")

    keys = set(payload.keys())
    forbidden = keys & FORBIDDEN_TOP_LEVEL
    if forbidden:
        raise EnvelopeError(
            "envelope contains plaintext fields the server refuses to store: "
            + ", ".join(sorted(forbidden))
        )

    missing = [key for key in REQUIRED_KEYS if key not in payload]
    if missing:
        raise EnvelopeError("envelope missing " + ", ".join(missing))

    version = payload["v"]
    if version != 1 and version != "1":
        raise EnvelopeError("unsupported envelope version")
    version_i = 1

    nonce = _b64decode("nonce", payload["nonce"], expected_len=12)
    # AES-GCM ciphertext is plaintext + 16-byte tag.
    ct = _b64decode("ct", payload["ct"], min_len=16)

    kdf = payload["kdf"]
    if not isinstance(kdf, Mapping):
        raise EnvelopeError("kdf must be an object")
    alg = str(kdf.get("alg") or kdf.get("name") or "")
    if "PBKDF2" not in alg.upper() and alg.upper() != "PBKDF2-HMAC-SHA256":
        raise EnvelopeError("kdf.alg must be PBKDF2-HMAC-SHA256")
    try:
        iterations = int(kdf.get("iterations"))
    except (TypeError, ValueError) as exc:
        raise EnvelopeError("kdf.iterations must be an integer") from exc
    if iterations < 600_000:
        raise EnvelopeError("kdf.iterations must be at least 600000")
    salt = kdf.get("salt")
    if not isinstance(salt, str):
        raise EnvelopeError("kdf.salt must be a base64 string")
    _b64decode("kdf.salt", salt, expected_len=32)

    normalised: Dict[str, Any] = {
        "v": version_i,
        "nonce": payload["nonce"].strip(),
        "ct": payload["ct"].strip(),
        "kdf": {
            "alg": "PBKDF2-HMAC-SHA256",
            "hash": str(kdf.get("hash") or "SHA-256"),
            "iterations": iterations,
            "dk_len": int(kdf.get("dk_len") or kdf.get("dkLen") or 64),
            "salt": salt.strip(),
            "email_mix": str(kdf.get("email_mix") or "sha256(salt||email)"),
        },
    }
    if "updated_at" in payload:
        try:
            normalised["updated_at"] = int(payload["updated_at"])
        except (TypeError, ValueError) as exc:
            raise EnvelopeError("updated_at must be an integer timestamp") from exc
    return normalised


def envelope_byte_size(envelope: Mapping[str, Any]) -> int:
    return len(json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def envelope_parts(envelope: Mapping[str, Any]) -> Tuple[str, str, int]:
    """Return (ciphertext, nonce, aad_version) for storage."""
    return str(envelope["ct"]), str(envelope["nonce"]), int(envelope["v"])
