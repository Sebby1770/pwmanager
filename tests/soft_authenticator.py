"""A minimal software WebAuthn authenticator (ES256, "none" attestation) for tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.sign_count = 0

    def _cose(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def _client_data(self, kind: str, challenge: str, origin=None) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}
        ).encode()

    def create(self, options: dict, origin=None, rp_id=None) -> dict:
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        auth_data = (
            rp_hash + bytes([0x45]) + self.sign_count.to_bytes(4, "big") + bytes(16)
            + len(self.credential_id).to_bytes(2, "big") + self.credential_id + self._cose()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": b64u(self.credential_id),
            "rawId": b64u(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client_data),
                "attestationObject": b64u(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    def get(self, options: dict, origin=None, rp_id=None, challenge=None, advance=True) -> dict:
        if advance:
            self.sign_count += 1
        client_data = self._client_data("webauthn.get", challenge or options["challenge"], origin)
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        auth_data = rp_hash + bytes([0x05]) + self.sign_count.to_bytes(4, "big")
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": b64u(self.credential_id),
            "rawId": b64u(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client_data),
                "authenticatorData": b64u(auth_data),
                "signature": b64u(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
