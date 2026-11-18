"""Key derivation for the zero-knowledge cloud vault (matches web/saas/crypto.js).

v2 (default): masterKey = Argon2id(password, SHA-256(salt || email), m, t, p, 32)
              vaultKey  = HKDF-SHA256(masterKey, info="pwmanager/v2/vault-key")
              authKey   = HKDF-SHA256(masterKey, info="pwmanager/v2/auth-key")
v1 (legacy):  PBKDF2-SHA256(password, SHA-256(salt || email), 600k, 64 bytes),
              split as vaultKey = bytes 0-31, authKey = bytes 32-63.

Only authKey may ever leave this process. Parameter bounds are enforced here,
not trusted from a server, exactly as the browser does.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

V1_ALG = "PBKDF2-HMAC-SHA256"
V2_ALG = "argon2id"
PBKDF2_ITERATIONS = 600_000
ARGON2_DEFAULTS = {"m": 65_536, "t": 3, "p": 4}
ARGON2_LIMITS = {"m": (65_536, 262_144), "t": (3, 20), "p": (1, 16)}
SALT_BYTES = 32
MIN_MASTER_LENGTH = 12
_INFO_VAULT = b"pwmanager/v2/vault-key"
_INFO_AUTH = b"pwmanager/v2/auth-key"


class KdfError(ValueError):
    """Parameters this client refuses to derive with."""


def default_params() -> dict:
    return {"alg": V2_ALG, "version": 2, **ARGON2_DEFAULTS, "salt_bytes": SALT_BYTES,
            "email_mix": "sha256(salt||email)", "key_split": "hkdf-sha256"}


def legacy_params() -> dict:
    return {"alg": V1_ALG, "hash": "SHA-256", "iterations": PBKDF2_ITERATIONS, "dk_len": 64,
            "salt_bytes": SALT_BYTES, "email_mix": "sha256(salt||email)"}


def normalize(params: Any) -> dict:
    if not isinstance(params, Mapping):
        raise KdfError("kdf params must be an object")
    alg = str(params.get("alg") or params.get("name") or "").lower()
    if alg == V2_ALG:
        out = default_params()
        for key, (lo, hi) in ARGON2_LIMITS.items():
            value = params.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
                raise KdfError(f"argon2 {key} must be an integer between {lo} and {hi}")
            out[key] = value
        return out
    if alg in {"pbkdf2", V1_ALG.lower()}:
        iterations = params.get("iterations", PBKDF2_ITERATIONS)
        if isinstance(iterations, (int, float)) and iterations < PBKDF2_ITERATIONS:
            raise KdfError("kdf iterations must be at least 600000")
        return legacy_params()  # v1 always runs at 600k, as the browser does
    raise KdfError("unsupported key derivation scheme")


def rank(params: Any) -> int:
    return 2 if normalize(params)["alg"] == V2_ALG else 1


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _mixed_salt(salt: bytes, email: str) -> bytes:
    return hashlib.sha256(salt + normalize_email(email).encode("utf-8")).digest()


def _hkdf(master: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(master)


def derive_keys(password: str, email: str, salt: bytes, params: Any) -> Tuple[bytes, bytes, dict]:
    """Return (vault_key, auth_key, canonical_params)."""
    if not password or len(password) < MIN_MASTER_LENGTH:
        raise KdfError("Master password must be at least 12 characters.")
    if len(salt) != SALT_BYTES:
        raise KdfError("KDF salt must be 32 bytes.")
    canonical = normalize(params)
    mixed = _mixed_salt(salt, email)
    pw = password.encode("utf-8")
    if canonical["alg"] == V2_ALG:
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise KdfError("argon2-cffi is required: pip install 'pwmanager[full]'") from exc
        master = bytearray(hash_secret_raw(pw, mixed, time_cost=canonical["t"], memory_cost=canonical["m"],
                                           parallelism=canonical["p"], hash_len=32, type=Type.ID))
        try:
            return _hkdf(bytes(master), _INFO_VAULT), _hkdf(bytes(master), _INFO_AUTH), canonical
        finally:
            for i in range(len(master)):
                master[i] = 0
    material = hashlib.pbkdf2_hmac("sha256", pw, mixed, PBKDF2_ITERATIONS, 64)
    return material[:32], material[32:], canonical
