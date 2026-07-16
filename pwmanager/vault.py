"""Encrypted vault storage, lock/unlock, and entry operations."""

from __future__ import annotations

import base64
import hmac
import json
import os
import time
from typing import Dict, List, Optional

from cryptography.fernet import InvalidToken

from pwmanager.constants import AUTOLOCK_SECONDS, DEFAULT_VAULT_PATH, VAULT_VERSION
from pwmanager.crypto import (
    decrypt_bytes,
    derive_key,
    encrypt_bytes,
    file_hmac,
    generate_salt,
    secure_wipe,
)
from pwmanager.models import Entry


class Vault:
    def __init__(self, path: str = DEFAULT_VAULT_PATH):
        self.path = path
        self.key: Optional[bytes] = None
        self.entries: Dict[str, Entry] = {}
        self.kdf_used: str = ""
        self.last_activity: float = time.time()

    # ---- file IO ----

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def create(self, master_password: str, kdf: str = "auto") -> None:
        salt = generate_salt()
        key, kdf_used = derive_key(master_password, salt, kdf)
        ciphertext = encrypt_bytes(json.dumps({}).encode("utf-8"), key)
        payload = {
            "version": VAULT_VERSION,
            "kdf": kdf_used,
            "salt": base64.b64encode(salt).decode("ascii"),
            "vault": ciphertext.decode("ascii"),
        }
        payload["hmac"] = file_hmac(payload, key)
        self._write(payload)
        self.key = key
        self.kdf_used = kdf_used
        self.entries = {}
        self.last_activity = time.time()

    def unlock(self, master_password: str) -> None:
        if not self.exists():
            raise FileNotFoundError(self.path)
        with open(self.path, "r", encoding="utf-8") as f:
            try:
                payload = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Vault file is not valid JSON: {e}") from e

        try:
            salt = base64.b64decode(payload["salt"])
            token = payload["vault"].encode("ascii")
            kdf = payload.get("kdf", "pbkdf2")
        except KeyError as e:
            raise ValueError(f"Vault file missing field: {e}") from e

        key, _ = derive_key(master_password, salt, kdf)

        # Integrity check (only if hmac field is present — keeps backwards compat)
        if "hmac" in payload:
            expected = file_hmac(payload, key)
            if not hmac.compare_digest(expected, payload["hmac"]):
                # Could be wrong password OR tampering — Fernet will tell us which
                pass

        plaintext = decrypt_bytes(token, key)  # raises InvalidToken on bad password
        raw = json.loads(plaintext.decode("utf-8"))
        self.entries = {name: Entry.from_dict(d) for name, d in raw.items()}
        self.key = key
        self.kdf_used = kdf
        self.last_activity = time.time()

    def save(self) -> None:
        if self.key is None:
            raise RuntimeError("Vault is locked")
        with open(self.path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        raw = {name: e.to_dict() for name, e in self.entries.items()}
        ciphertext = encrypt_bytes(json.dumps(raw).encode("utf-8"), self.key)
        payload["vault"] = ciphertext.decode("ascii")
        payload["version"] = VAULT_VERSION
        payload["hmac"] = file_hmac(payload, self.key)
        self._write(payload)
        self.last_activity = time.time()

    def lock(self) -> None:
        self.entries.clear()
        if isinstance(self.key, (bytes, bytearray)):
            secure_wipe(self.key)
        self.key = None

    def _write(self, payload: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, self.path)

    # ---- entry ops ----

    def touch(self) -> None:
        self.last_activity = time.time()

    def is_idle(self) -> bool:
        return (time.time() - self.last_activity) > AUTOLOCK_SECONDS

    def add(self, name: str, entry: Entry) -> None:
        self.entries[name] = entry
        self.save()

    def delete(self, name: str) -> None:
        del self.entries[name]
        self.save()

    def search(self, query: str, tag: Optional[str] = None) -> List[str]:
        q = query.lower() if query else ""
        tag_q = tag.lower() if tag else None
        results = []
        for name, e in self.entries.items():
            if tag_q is not None:
                entry_tags = [t.lower() for t in e.tags]
                if tag_q not in entry_tags:
                    continue
            if q:
                haystack = " ".join(
                    [name, e.username, e.url, e.notes, " ".join(e.tags)]
                ).lower()
                if q not in haystack:
                    continue
            results.append(name)
        return sorted(results)

    # ---- export / import ----

    def export_encrypted(self, out_path: str, password: str) -> None:
        salt = generate_salt()
        key, kdf_used = derive_key(password, salt)
        raw = {name: e.to_dict() for name, e in self.entries.items()}
        ct = encrypt_bytes(json.dumps(raw).encode("utf-8"), key)
        payload = {
            "version": VAULT_VERSION,
            "kdf": kdf_used,
            "salt": base64.b64encode(salt).decode("ascii"),
            "vault": ct.decode("ascii"),
            "exported_at": time.time(),
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def import_encrypted(self, in_path: str, password: str, merge: bool = True) -> int:
        with open(in_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        salt = base64.b64decode(payload["salt"])
        key, _ = derive_key(password, salt, payload.get("kdf", "pbkdf2"))
        plaintext = decrypt_bytes(payload["vault"].encode("ascii"), key)
        raw = json.loads(plaintext.decode("utf-8"))
        if not merge:
            self.entries.clear()
        added = 0
        for name, d in raw.items():
            self.entries[name] = Entry.from_dict(d)
            added += 1
        self.save()
        return added


# Re-export InvalidToken for callers that catch unlock failures
__all__ = ["Vault", "InvalidToken"]
