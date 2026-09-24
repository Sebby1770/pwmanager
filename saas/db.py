"""SQLite persistence for accounts, opaque vault blobs, sessions, and audit."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from saas.auth import (
    default_kdf_params,
    dummy_kdf_salt,
    hash_auth_key,
    hash_ip,
    hash_token,
    isoformat,
    new_id,
    new_session_token,
    normalize_email,
    parse_iso,
    rate_limited,
    session_expiry,
    utcnow,
    verify_auth_key,
)
from saas.config import FREE_VAULT_MAX_BYTES, PRO_VAULT_MAX_BYTES, REVISION_CAP, SCHEMA_PATH


class Database:
    def __init__(self, path: str):
        self.path = path
        parent = Path(path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self.init_schema()
        self._pepper = self._load_or_create_pepper()

    @property
    def pepper(self) -> bytes:
        return self._pepper

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def init_schema(self) -> None:
        sql = SCHEMA_PATH.read_text(encoding="utf-8")
        with self._lock:
            self._conn.executescript(sql)
            # Additive migrations for databases created by earlier releases.
            columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(accounts)")}
            if "plan_event_at" not in columns:
                self._conn.execute("ALTER TABLE accounts ADD COLUMN plan_event_at INTEGER")

    def _load_or_create_pepper(self) -> bytes:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'pepper'").fetchone()
            if row:
                return bytes.fromhex(row["value"])
            pepper = __import__("os").urandom(32)
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('pepper', ?)",
                (pepper.hex(),),
            )
            return pepper

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def ip_hash(self, ip: str) -> str:
        return hash_ip(ip or "", self._pepper)

    def limited(self, key: str, limit: int = 5, window: int = 60) -> bool:
        with self._lock:
            return rate_limited(self._conn, key, limit=limit, window=window)

    # ------------------------------------------------------------------ accounts

    def get_account_by_email(self, email: str) -> Optional[sqlite3.Row]:
        email = normalize_email(email)
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM accounts WHERE email = ? AND deleted_at IS NULL",
                (email,),
            ).fetchone()

    def get_account_by_id(self, account_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM accounts WHERE id = ? AND deleted_at IS NULL",
                (account_id,),
            ).fetchone()

    def create_account(self, email: str, auth_key: bytes, kdf_salt: str, kdf_params: dict) -> sqlite3.Row:
        email = normalize_email(email)
        account_id = new_id()
        verifier = hash_auth_key(auth_key)
        now = isoformat()
        params_json = json.dumps(kdf_params or default_kdf_params(), separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO accounts (
                    id, email, auth_verifier, kdf_salt, kdf_params,
                    created_at, plan
                ) VALUES (?, ?, ?, ?, ?, ?, 'free')
                """,
                (account_id, email, verifier, kdf_salt, params_json, now),
            )
        return self.get_account_by_id(account_id)

    def touch_login(self, account_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE accounts SET last_login_at = ? WHERE id = ?",
                (isoformat(), account_id),
            )

    def prelogin(self, email: str) -> Dict[str, Any]:
        account = self.get_account_by_email(email)
        if account is None:
            return {
                "kdf_salt": dummy_kdf_salt(email, self._pepper),
                "kdf_params": default_kdf_params(),
            }
        try:
            params = json.loads(account["kdf_params"])
        except (TypeError, json.JSONDecodeError):
            params = default_kdf_params()
        return {"kdf_salt": account["kdf_salt"], "kdf_params": params}

    def verify_login(self, email: str, auth_key: bytes) -> Optional[sqlite3.Row]:
        account = self.get_account_by_email(email)
        if account is None:
            verify_auth_key("", auth_key)
            return None
        if not verify_auth_key(account["auth_verifier"], auth_key):
            return None
        return account

    def set_plan(
        self,
        account_id: str,
        plan: str,
        status: Optional[str] = None,
        period_end: Optional[str] = None,
        stripe_customer_id: Optional[str] = None,
        event_at: Optional[int] = None,
    ) -> None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                return
            customer = stripe_customer_id if stripe_customer_id is not None else row["stripe_customer_id"]
            stamp = event_at if event_at is not None else row["plan_event_at"]
            self._conn.execute(
                """
                UPDATE accounts
                SET plan = ?, plan_status = ?, plan_period_end = ?, stripe_customer_id = ?,
                    plan_event_at = ?
                WHERE id = ?
                """,
                (plan, status, period_end, customer, stamp, account_id),
            )

    def set_stripe_customer(self, account_id: str, customer_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE accounts SET stripe_customer_id = ? WHERE id = ?",
                (customer_id, account_id),
            )

    def get_account_by_stripe_customer(self, customer_id: str) -> Optional[sqlite3.Row]:
        if not customer_id:
            return None
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM accounts WHERE stripe_customer_id = ? AND deleted_at IS NULL",
                (customer_id,),
            ).fetchone()

    def delete_account(self, account_id: str) -> None:
        account = self.get_account_by_id(account_id)
        if account is None:
            return
        import hashlib

        digest = hashlib.sha256(account["email"].encode("utf-8")).hexdigest()[:24]
        tombstone = f"deleted+{digest}@invalid.invalid"
        now = isoformat()
        with self._lock:
            self._conn.execute("DELETE FROM vault_blobs WHERE account_id = ?", (account_id,))
            self._conn.execute("DELETE FROM vault_revisions WHERE account_id = ?", (account_id,))
            self._conn.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))
            self._conn.execute(
                """
                UPDATE accounts
                SET email = ?, auth_verifier = 'deleted', kdf_salt = 'deleted',
                    kdf_params = '{}', stripe_customer_id = NULL, deleted_at = ?,
                    plan = 'free', plan_status = 'deleted'
                WHERE id = ?
                """,
                (tombstone, now, account_id),
            )

    # ------------------------------------------------------------------ sessions

    def create_session(self, account_id: str, user_agent: str) -> str:
        token, token_hash = new_session_token()
        from saas.auth import hash_user_agent

        sid = new_id()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO sessions (id, account_id, token_hash, expires_at, created_at, user_agent_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sid,
                    account_id,
                    token_hash,
                    session_expiry(),
                    isoformat(),
                    hash_user_agent(user_agent or "", self._pepper),
                ),
            )
        return token

    def session_account(self, token: str) -> Optional[sqlite3.Row]:
        if not token:
            return None
        token_hash = hash_token(token)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT a.*, s.id AS session_id, s.expires_at AS session_expires
                FROM sessions s
                JOIN accounts a ON a.id = s.account_id
                WHERE s.token_hash = ? AND a.deleted_at IS NULL
                """,
                (token_hash,),
            ).fetchone()
        if row is None:
            return None
        try:
            expires = parse_iso(row["session_expires"])
        except Exception:
            return None
        if expires < utcnow():
            self.revoke_session_token(token)
            return None
        return row

    def revoke_session_token(self, token: str) -> None:
        token_hash = hash_token(token)
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def revoke_session_id(self, session_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    # ------------------------------------------------------------------ vault

    def get_vault(self, account_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM vault_blobs WHERE account_id = ?",
                (account_id,),
            ).fetchone()

    def put_vault(
        self,
        account_id: str,
        ciphertext: str,
        nonce: str,
        aad_version: int,
        byte_size: int,
        pro: bool,
    ) -> None:
        limit = PRO_VAULT_MAX_BYTES if pro else FREE_VAULT_MAX_BYTES
        if byte_size > limit:
            raise ValueError("vault_too_large")
        now = isoformat()
        with self._lock:
            current = self._conn.execute(
                "SELECT * FROM vault_blobs WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            if current is not None and pro:
                self._conn.execute(
                    """
                    INSERT INTO vault_revisions (
                        id, account_id, ciphertext, nonce, aad_version, byte_size, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_id(),
                        account_id,
                        current["ciphertext"],
                        current["nonce"],
                        current["aad_version"],
                        current["byte_size"],
                        current["updated_at"],
                    ),
                )
                extra = self._conn.execute(
                    """
                    SELECT id FROM vault_revisions
                    WHERE account_id = ?
                    ORDER BY updated_at DESC
                    """,
                    (account_id,),
                ).fetchall()
                for stale in extra[REVISION_CAP:]:
                    self._conn.execute("DELETE FROM vault_revisions WHERE id = ?", (stale["id"],))
            if current is None:
                self._conn.execute(
                    """
                    INSERT INTO vault_blobs (
                        id, account_id, ciphertext, nonce, aad_version, byte_size, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (new_id(), account_id, ciphertext, nonce, aad_version, byte_size, now),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE vault_blobs
                    SET ciphertext = ?, nonce = ?, aad_version = ?, byte_size = ?, updated_at = ?
                    WHERE account_id = ?
                    """,
                    (ciphertext, nonce, aad_version, byte_size, now, account_id),
                )

    def list_revisions(self, account_id: str) -> List[sqlite3.Row]:
        with self._lock:
            current = self._conn.execute(
                "SELECT * FROM vault_blobs WHERE account_id = ?",
                (account_id,),
            ).fetchall()
            past = self._conn.execute(
                """
                SELECT * FROM vault_revisions
                WHERE account_id = ?
                ORDER BY updated_at DESC
                """,
                (account_id,),
            ).fetchall()
        return list(current) + list(past)

    # ------------------------------------------------------------------ payments / audit

    def payment_event_seen(self, stripe_event_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM payment_events WHERE stripe_event_id = ?",
                (stripe_event_id,),
            ).fetchone()
            return row is not None

    def record_payment_event(
        self,
        stripe_event_id: str,
        event_type: str,
        account_id: Optional[str],
        payload_type: Optional[str],
    ) -> bool:
        """Insert an idempotency row. Returns False if the event was already stored."""
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO payment_events (id, stripe_event_id, type, account_id, payload_type, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (new_id(), stripe_event_id, event_type, account_id, payload_type, isoformat()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def audit(self, account_id: Optional[str], event: str, ip: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_events (id, account_id, event, at, ip_hash)
                VALUES (?, ?, ?, ?, ?)
                """,
                (new_id(), account_id, event, isoformat(), self.ip_hash(ip)),
            )


def is_pro(account: Optional[sqlite3.Row]) -> bool:
    if account is None:
        return False
    if account["plan"] != "pro":
        return False
    status = (account["plan_status"] or "").lower()
    if status in {"canceled", "unpaid", "incomplete_expired", "deleted"}:
        return False
    period_end = account["plan_period_end"]
    if period_end:
        try:
            if parse_iso(period_end) < utcnow() and status in {"canceled", "unpaid"}:
                return False
        except Exception:
            pass
    return True


def account_public(account: sqlite3.Row) -> Dict[str, Any]:
    try:
        kdf_params = json.loads(account["kdf_params"])
    except (TypeError, json.JSONDecodeError):
        kdf_params = default_kdf_params()
    return {
        "id": account["id"],
        "email": account["email"],
        "plan": account["plan"],
        "plan_status": account["plan_status"],
        "plan_period_end": account["plan_period_end"],
        "kdf_salt": account["kdf_salt"],
        "kdf_params": kdf_params,
        "created_at": account["created_at"],
        "last_login_at": account["last_login_at"],
        "email_verified_at": account["email_verified_at"],
        "pro": is_pro(account),
    }


def blob_to_envelope(row: sqlite3.Row, kdf_salt: str, kdf_params: dict) -> Dict[str, Any]:
    envelope = {
        "v": int(row["aad_version"]),
        "nonce": row["nonce"],
        "ct": row["ciphertext"],
        "kdf": {
            "alg": (kdf_params or {}).get("alg", "PBKDF2-HMAC-SHA256"),
            "hash": (kdf_params or {}).get("hash", "SHA-256"),
            "iterations": (kdf_params or {}).get("iterations", 600000),
            "dk_len": (kdf_params or {}).get("dk_len", 64),
            "salt": kdf_salt,
            "email_mix": (kdf_params or {}).get("email_mix", "sha256(salt||email)"),
        },
        "byte_size": row["byte_size"],
        "updated_at": row["updated_at"],
        "id": row["id"],
    }
    return envelope
