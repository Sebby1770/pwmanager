"""Build real zero-knowledge accounts and envelopes in Python, as the browser would."""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pwmanager import cloudkdf

AAD = b"pwmanager-vault-v1"
PASSWORD = "correct horse battery staple 42"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class Keys:
    def __init__(self, password: str, email: str, params: dict, salt: bytes = None):
        self.salt = salt or os.urandom(32)
        self.vault_key, self.auth_key, self.params = cloudkdf.derive_keys(password, email, self.salt, params)

    @property
    def auth_b64(self) -> str:
        return b64(self.auth_key)

    @property
    def salt_b64(self) -> str:
        return b64(self.salt)

    def seal(self, data: dict) -> dict:
        nonce = os.urandom(12)
        ct = AESGCM(self.vault_key).encrypt(nonce, json.dumps(data).encode(), AAD)
        return {"v": 1, "nonce": b64(nonce), "ct": b64(ct), "kdf": {**self.params, "salt": self.salt_b64}}

    def open(self, envelope: dict) -> dict:
        nonce, ct = base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"])
        return json.loads(AESGCM(self.vault_key).decrypt(nonce, ct, AAD))


def v1(email: str, password: str = PASSWORD) -> Keys:
    return Keys(password, email, cloudkdf.legacy_params())


def v2(email: str, password: str = PASSWORD) -> Keys:
    return Keys(password, email, cloudkdf.default_params())


def register(api, email: str, keys: Keys):
    return api.request(
        "POST", "/api/register",
        {"email": email, "auth_key": keys.auth_b64, "kdf_salt": keys.salt_b64, "kdf_params": keys.params},
    )


def vault_doc(*names: str, saved_at: int = 1) -> dict:
    return {"version": 1, "saved_at": saved_at,
            "entries": [{"id": n, "name": n, "password": "pw-" + n} for n in names]}
