"""Key derivation, encryption, integrity HMAC, and secure wipe."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Any, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pwmanager.constants import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    CIPHER_AESGCM,
    CIPHER_FERNET,
    CURRENT_CIPHER,
    GCM_NONCE_SIZE,
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


def _raw_key(key: bytes) -> bytes:
    """32-byte key inside the Fernet-compatible urlsafe-b64 wrapper."""
    return base64.urlsafe_b64decode(key)


def encrypt_bytes(data: bytes, key: bytes, cipher: str = CURRENT_CIPHER) -> bytes:
    if cipher == CIPHER_FERNET:
        return Fernet(key).encrypt(data)
    if cipher == CIPHER_AESGCM:
        nonce = os.urandom(GCM_NONCE_SIZE)
        ct = AESGCM(_raw_key(key)).encrypt(nonce, data, None)
        return base64.urlsafe_b64encode(nonce + ct)
    raise ValueError(f"Unknown cipher: {cipher}")


def decrypt_bytes(token: bytes, key: bytes, cipher: str = CURRENT_CIPHER) -> bytes:
    try:
        if cipher == CIPHER_FERNET:
            return Fernet(key).decrypt(token)
        if cipher == CIPHER_AESGCM:
            blob = base64.urlsafe_b64decode(token)
            if len(blob) < GCM_NONCE_SIZE + 16:
                raise InvalidToken("ciphertext too short")
            nonce, ct = blob[:GCM_NONCE_SIZE], blob[GCM_NONCE_SIZE:]
            return AESGCM(_raw_key(key)).decrypt(nonce, ct, None)
        raise ValueError(f"Unknown cipher: {cipher}")
    except (InvalidToken, InvalidTag, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("Unknown cipher"):
            raise
        raise InvalidToken("Decryption failed") from exc


def _signed_message(tag: str, parts: list[str]) -> bytes:
    return "|".join(f"{len(p)}:{p}" for p in [tag, *parts]).encode("utf-8")


def file_hmac(payload: dict, key: bytes) -> str:
    """HMAC over every unencrypted vault field, for tamper detection.

    Domain-separated with a version tag and length prefixes so no two distinct
    payloads can produce the same signed message. v3 also authenticates cipher.
    """
    parts = [
        str(payload.get("version", "")),
        str(payload.get("kdf", "")),
        str(payload.get("cipher", CIPHER_FERNET)),
        payload["salt"],
        payload["vault"],
    ]
    msg = _signed_message("pwmanager-vault-hmac-v3", parts)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def file_hmac_v2(payload: dict, key: bytes) -> str:
    """2.4 MAC: version, kdf, salt, vault. No cipher field yet."""
    parts = [
        str(payload.get("version", "")),
        str(payload.get("kdf", "")),
        payload["salt"],
        payload["vault"],
    ]
    msg = _signed_message("pwmanager-vault-hmac-v2", parts)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def legacy_file_hmac(payload: dict, key: bytes) -> str:
    """The pre-2.4 HMAC, which covered only salt and ciphertext.

    Kept so vaults written by earlier versions still open. They are upgraded to
    the wider MAC the next time the vault is saved.
    """
    msg = (payload["salt"] + "|" + payload["vault"]).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_file_hmac(payload: dict, key: bytes) -> bool:
    """Constant-time check of a stored HMAC against current, 2.4, or legacy form."""
    stored = payload.get("hmac")
    if not isinstance(stored, str):
        return False
    # compare_digest refuses non-ASCII str, so a tampered MAC like "é…" used
    # to crash unlock with TypeError instead of reporting tampering. Compare
    # bytes instead. All three forms always run so timing does not reveal
    # which one matched.
    stored_b = stored.encode("utf-8", "surrogatepass")
    try:
        current = hmac.compare_digest(file_hmac(payload, key).encode(), stored_b)
        v2 = hmac.compare_digest(file_hmac_v2(payload, key).encode(), stored_b)
        legacy = hmac.compare_digest(legacy_file_hmac(payload, key).encode(), stored_b)
    except (KeyError, TypeError):
        return False
    return current or v2 or legacy
