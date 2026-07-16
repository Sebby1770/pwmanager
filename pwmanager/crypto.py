"""Key derivation, encryption, integrity HMAC, and secure wipe."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Any, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pwmanager.constants import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    KEY_SIZE,
    PBKDF2_ITERATIONS,
    SALT_SIZE,
)

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


def secure_wipe(data: Any) -> None:
    """Best-effort overwrite of a mutable bytearray buffer in memory.

    Python strings and bytes are immutable, so true wiping is not safely
    available for them. For bytearrays we can actually zero the buffer.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_key(master_password: str, salt: bytes, kdf: str = "auto") -> Tuple[bytes, str]:
    """Derive a Fernet-compatible key. Returns (key, kdf_used)."""
    if kdf == "auto":
        kdf = "argon2id" if ARGON2_AVAILABLE else "pbkdf2"

    pw_bytes = master_password.encode("utf-8")
    if kdf == "argon2id":
        if not ARGON2_AVAILABLE:
            raise RuntimeError("argon2-cffi not installed")
        raw = hash_secret_raw(
            secret=pw_bytes,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_SIZE,
            type=Argon2Type.ID,
        )
    elif kdf == "pbkdf2":
        kdf_obj = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        raw = kdf_obj.derive(pw_bytes)
    else:
        raise ValueError(f"Unknown KDF: {kdf}")

    return base64.urlsafe_b64encode(raw), kdf


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)


def file_hmac(payload: dict, key: bytes) -> str:
    """HMAC over the salt+vault fields for tamper detection."""
    msg = (payload["salt"] + "|" + payload["vault"]).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
