"""Key-derivation parameter rules shared by registration, rekey and envelopes.

The server never runs these KDFs on the master password: it only stores the
parameters a client registered with and hands them back at prelogin. Bounds
here mirror ``normalizeKdfParams`` in web/saas/crypto.js, which enforces them
again client-side so a compromised server cannot weaken (or stall) derivation.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

V1_ALG = "PBKDF2-HMAC-SHA256"
V2_ALG = "argon2id"
PBKDF2_ITERATIONS = 600_000
PBKDF2_ITERATIONS_MAX = 10_000_000
ARGON2_DEFAULTS = {"m": 65_536, "t": 3, "p": 4}
ARGON2_LIMITS = {"m": (65_536, 262_144), "t": (3, 20), "p": (1, 16)}
SALT_BYTES = 32


def legacy_params(iterations: int = PBKDF2_ITERATIONS) -> dict:
    return {
        "alg": V1_ALG,
        "hash": "SHA-256",
        "iterations": iterations,
        "dk_len": 64,
        "salt_bytes": SALT_BYTES,
        "email_mix": "sha256(salt||email)",
    }


def default_params() -> dict:
    return {
        "alg": V2_ALG,
        "version": 2,
        **ARGON2_DEFAULTS,
        "salt_bytes": SALT_BYTES,
        "email_mix": "sha256(salt||email)",
        "key_split": "hkdf-sha256",
    }


def _bounded_int(params: Mapping[str, Any], key: str, lo: int, hi: int, default: Optional[int] = None) -> int:
    raw = params.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise ValueError(f"kdf {key} must be an integer")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"kdf {key} must be an integer") from exc
    if value < lo:
        raise ValueError(f"kdf {key} must be at least {lo}")
    if value > hi:
        raise ValueError(f"kdf {key} must be at most {hi}")
    return value


def canonical(params: Any) -> dict:
    """Validate client-supplied params; return the canonical form or raise ValueError.

    Unknown keys are dropped, never stored and echoed back. A missing ``alg``
    means v1, which is what clients before 3.3 sent.
    """
    if params is None:
        return default_params()
    if not isinstance(params, Mapping):
        raise ValueError("kdf_params must be an object")
    alg = str(params.get("alg") or params.get("name") or V1_ALG).strip().lower()
    if alg == V2_ALG:
        out = default_params()
        for key, (lo, hi) in ARGON2_LIMITS.items():
            out[key] = _bounded_int(params, key, lo, hi)
        return out
    if alg in {"pbkdf2", V1_ALG.lower()}:
        return legacy_params(
            _bounded_int(params, "iterations", PBKDF2_ITERATIONS, PBKDF2_ITERATIONS_MAX, PBKDF2_ITERATIONS)
        )
    raise ValueError("kdf alg must be argon2id or PBKDF2-HMAC-SHA256")


def rank(params: Mapping[str, Any]) -> int:
    """1 = PBKDF2 (legacy), 2 = Argon2id."""
    return 2 if canonical(params)["alg"] == V2_ALG else 1
