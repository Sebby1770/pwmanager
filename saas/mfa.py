"""Passkey (WebAuthn) second factor for cloud sign-in, plus one-time recovery codes.

The second factor gates the *server session* only. It never touches vault
keys: the vault is still decrypted locally from the master password, so the
zero-knowledge design is unchanged. What it adds is that a phished or leaked
master password (hence authKey) is no longer enough to download the
ciphertext or overwrite the cloud copy.

Ceremonies are single-use: each options call stores a random challenge under
a random ceremony token (hashed at rest) that expires after CEREMONY_SECONDS
and is deleted on the first verification attempt, successful or not.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from saas.auth import isoformat, new_id

try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        AuthenticatorTransport,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    WEBAUTHN_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    WEBAUTHN_AVAILABLE = False

CEREMONY_SECONDS = 300
MAX_CREDENTIALS = 10
MAX_OPEN_CEREMONIES = 5
RECOVERY_CODE_COUNT = 10
RP_NAME = "pwmanager"
PURPOSE_REGISTER = "register"
PURPOSE_LOGIN = "login"


class MfaError(Exception):
    """A second-factor step failed. ``code`` is safe to show to the client."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def rp_for(public_url: str, override_rp_id: str = "", override_origins: Optional[List[str]] = None) -> Tuple[str, List[str]]:
    """Relying-party id and allowed origins for this deployment.

    Browsers refuse IP-literal RP ids, so a bare-IP public URL maps to
    ``localhost`` (serve the app from http://localhost:<port> to use passkeys
    locally).
    """
    parsed = urlparse(public_url)
    host = parsed.hostname or "localhost"
    try:
        ipaddress.ip_address(host)
        host = "localhost"
    except ValueError:
        pass
    rp_id = override_rp_id or host
    origin = f"{parsed.scheme or 'http'}://{parsed.netloc or host}"
    origins = list(override_origins or [])
    if origin not in origins:
        origins.append(origin)
    return rp_id, origins


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()


def normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def _new_recovery_code() -> str:
    raw = base64.b32encode(secrets.token_bytes(10)).decode("ascii").rstrip("=")  # 80 bits
    return "-".join(raw[i : i + 4] for i in range(0, 16, 4))


class Mfa:
    """Persistence and verification. ``db`` is a saas.db.Database."""

    def __init__(self, db, rp_id: str, origins: List[str]):
        self.db = db
        self.rp_id = rp_id
        self.origins = origins

    # ------------------------------------------------------------ storage

    def credentials(self, account_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM webauthn_credentials WHERE account_id = ? ORDER BY created_at", (account_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def enabled(self, account_id: str) -> bool:
        row = self.db.execute(
            "SELECT 1 FROM webauthn_credentials WHERE account_id = ? LIMIT 1", (account_id,)
        ).fetchone()
        return row is not None

    def public_credentials(self, account_id: str) -> List[Dict[str, Any]]:
        return [
            {"id": c["id"], "name": c["name"], "created_at": c["created_at"], "last_used_at": c["last_used_at"]}
            for c in self.credentials(account_id)
        ]

    def delete_credential(self, account_id: str, credential_row_id: str) -> bool:
        cur = self.db.execute(
            "DELETE FROM webauthn_credentials WHERE id = ? AND account_id = ?", (credential_row_id, account_id)
        )
        if cur.rowcount and not self.enabled(account_id):
            # Last passkey gone: 2FA is off, so the recovery codes are meaningless.
            self.db.execute("DELETE FROM recovery_codes WHERE account_id = ?", (account_id,))
        return bool(cur.rowcount)

    def delete_all(self, account_id: str) -> None:
        self.db.execute("DELETE FROM webauthn_credentials WHERE account_id = ?", (account_id,))
        self.db.execute("DELETE FROM recovery_codes WHERE account_id = ?", (account_id,))
        self.db.execute("DELETE FROM mfa_ceremonies WHERE account_id = ?", (account_id,))

    def _store_ceremony(self, account_id: str, purpose: str, challenge: bytes) -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        self.db.execute("DELETE FROM mfa_ceremonies WHERE expires_at < ?", (now,))
        # Bound outstanding ceremonies per account and purpose so repeated
        # options calls cannot grow the table; the oldest are cancelled.
        self.db.execute(
            "DELETE FROM mfa_ceremonies WHERE id IN (SELECT id FROM mfa_ceremonies"
            " WHERE account_id = ? AND purpose = ? ORDER BY expires_at DESC LIMIT -1 OFFSET ?)",
            (account_id, purpose, MAX_OPEN_CEREMONIES - 1),
        )
        self.db.execute(
            "INSERT INTO mfa_ceremonies (id, token_hash, account_id, purpose, challenge, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (new_id(), _hash(token), account_id, purpose, _b64u(challenge), now + CEREMONY_SECONDS),
        )
        return token

    def _take_ceremony(self, token: str, purpose: str, account_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Consume a ceremony. Returns (account_id, challenge). Single use."""
        if not isinstance(token, str) or not token:
            raise MfaError("mfa_ceremony_invalid", "Sign-in step expired. Start again.", 401)
        with self.db._lock:
            row = self.db.execute(
                "SELECT * FROM mfa_ceremonies WHERE token_hash = ? AND purpose = ?", (_hash(token), purpose)
            ).fetchone()
            if row is not None:
                self.db.execute("DELETE FROM mfa_ceremonies WHERE id = ?", (row["id"],))
        if row is None or int(row["expires_at"]) < int(time.time()):
            raise MfaError("mfa_ceremony_invalid", "Sign-in step expired. Start again.", 401)
        if account_id is not None and row["account_id"] != account_id:
            raise MfaError("mfa_ceremony_invalid", "Sign-in step expired. Start again.", 401)
        pad = "=" * (-len(row["challenge"]) % 4)
        return row["account_id"], base64.urlsafe_b64decode(row["challenge"] + pad)

    def pending_account(self, token: str, purpose: str = PURPOSE_LOGIN) -> Optional[str]:
        row = self.db.execute(
            "SELECT account_id, expires_at FROM mfa_ceremonies WHERE token_hash = ? AND purpose = ?",
            (_hash(token or ""), purpose),
        ).fetchone()
        if row is None or int(row["expires_at"]) < int(time.time()):
            return None
        return row["account_id"]

    # ------------------------------------------------------------ registration

    def _require_lib(self) -> None:
        if not WEBAUTHN_AVAILABLE:
            raise MfaError("webauthn_unavailable", "Passkeys are not available on this server.", 503)

    def registration_options(self, account) -> Dict[str, Any]:
        self._require_lib()
        existing = self.credentials(account["id"])
        if len(existing) >= MAX_CREDENTIALS:
            raise MfaError("too_many_passkeys", f"At most {MAX_CREDENTIALS} passkeys per account.")
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=RP_NAME,
            user_name=account["email"],
            user_id=account["id"].encode("ascii"),
            user_display_name=account["email"],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])) for c in existing
            ],
        )
        token = self._store_ceremony(account["id"], PURPOSE_REGISTER, options.challenge)
        return {"ceremony": token, "publicKey": json.loads(options_to_json(options))}

    def register(self, account, ceremony: str, credential: Any, name: str) -> Dict[str, Any]:
        self._require_lib()
        _, challenge = self._take_ceremony(ceremony, PURPOSE_REGISTER, account_id=account["id"])
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origins,
            )
        except (InvalidRegistrationResponse, ValueError, TypeError, KeyError) as exc:
            raise MfaError("passkey_invalid", f"Passkey registration failed: {exc}") from exc
        credential_id = bytes_to_base64url(verified.credential_id)
        if self.db.execute(
            "SELECT 1 FROM webauthn_credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone():
            raise MfaError("passkey_exists", "That passkey is already registered.", 409)
        first = not self.enabled(account["id"])
        transports = []
        if isinstance(credential, dict):
            raw = (credential.get("response") or {}).get("transports") or []
            transports = [t for t in raw if isinstance(t, str)][:8]
        row_id = new_id()
        label = (name or "").strip()[:64] or "Passkey"
        self.db.execute(
            "INSERT INTO webauthn_credentials (id, account_id, credential_id, public_key, sign_count,"
            " transports, name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (row_id, account["id"], credential_id, bytes_to_base64url(verified.credential_public_key),
             int(verified.sign_count), json.dumps(transports), label, isoformat()),
        )
        result: Dict[str, Any] = {"credential": {"id": row_id, "name": label}}
        if first:
            result["recovery_codes"] = self.new_recovery_codes(account["id"])
        return result

    # ------------------------------------------------------------ login

    def login_options(self, account_id: str) -> Dict[str, Any]:
        """Second step after a correct authKey. Fails closed without the library."""
        self._require_lib()
        creds = self.credentials(account_id)
        options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(c["credential_id"]),
                    transports=[AuthenticatorTransport(t) for t in json.loads(c["transports"] or "[]")
                                if t in {x.value for x in AuthenticatorTransport}] or None,
                )
                for c in creds
            ],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        token = self._store_ceremony(account_id, PURPOSE_LOGIN, options.challenge)
        return {"mfa_required": True, "ceremony": token, "publicKey": json.loads(options_to_json(options))}

    def verify_login(self, ceremony: str, credential: Any) -> str:
        """Returns the account id on success. The ceremony is consumed either way."""
        self._require_lib()
        account_id, challenge = self._take_ceremony(ceremony, PURPOSE_LOGIN)
        raw_id = credential.get("id") if isinstance(credential, dict) else None
        if not isinstance(raw_id, str):
            raise MfaError("passkey_invalid", "Passkey response is malformed.", 401)
        # Scoped to the account the ceremony was issued for: another user's
        # passkey never satisfies this account's second factor.
        row = self.db.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ? AND account_id = ?", (raw_id, account_id)
        ).fetchone()
        if row is None:
            raise MfaError("passkey_invalid", "That passkey is not registered to this account.", 401)
        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origins,
                credential_public_key=base64url_to_bytes(row["public_key"]),
                credential_current_sign_count=int(row["sign_count"]),
            )
        except (InvalidAuthenticationResponse, ValueError, TypeError, KeyError) as exc:
            # Includes a sign counter that did not advance: a cloned authenticator.
            raise MfaError("passkey_invalid", f"Passkey check failed: {exc}", 401) from exc
        self.db.execute(
            "UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?",
            (int(verified.new_sign_count), isoformat(), row["id"]),
        )
        return account_id

    # ------------------------------------------------------------ recovery codes

    def _code_hash(self, code: str) -> str:
        return hmac.new(self.db.pepper, ("recovery|" + normalize_recovery_code(code)).encode(), hashlib.sha256).hexdigest()

    def new_recovery_codes(self, account_id: str) -> List[str]:
        codes = [_new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        self.db.execute("DELETE FROM recovery_codes WHERE account_id = ?", (account_id,))
        for code in codes:
            self.db.execute(
                "INSERT INTO recovery_codes (id, account_id, code_hash, created_at) VALUES (?, ?, ?, ?)",
                (new_id(), account_id, self._code_hash(code), isoformat()),
            )
        return codes

    def remaining_recovery_codes(self, account_id: str) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) AS n FROM recovery_codes WHERE account_id = ? AND used_at IS NULL", (account_id,)
        ).fetchone()
        return int(row["n"])

    def verify_recovery(self, ceremony: str, code: str) -> str:
        account_id, _ = self._take_ceremony(ceremony, PURPOSE_LOGIN)
        with self.db._lock:
            cur = self.db.execute(
                "UPDATE recovery_codes SET used_at = ? WHERE account_id = ? AND code_hash = ? AND used_at IS NULL",
                (isoformat(), account_id, self._code_hash(code)),
            )
        if not cur.rowcount:
            raise MfaError("recovery_invalid", "That recovery code is wrong or already used.", 401)
        return account_id
