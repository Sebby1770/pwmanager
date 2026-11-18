"""SQLite persistence for accounts, opaque vault blobs, sessions, and audit."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from saas.auth import (
    default_kdf_params,
    legacy_kdf_params,
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
            session_columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(sessions)")}
            for column in ("device_label", "last_used_at"):
                if column not in session_columns:
                    self._conn.execute(f"ALTER TABLE sessions ADD COLUMN {column} TEXT")

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
            params = legacy_kdf_params()
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

    def _insert_session(self, account_id: str, user_agent: str) -> str:
        """Caller holds self._lock. Returns the raw token (only its hash is stored)."""
        from saas.auth import device_label, hash_user_agent

        token, token_hash = new_session_token()
        now = isoformat()
        self._conn.execute(
            """
            INSERT INTO sessions (id, account_id, token_hash, expires_at, created_at, user_agent_hash,
                                  device_label, last_used_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id(),
                account_id,
                token_hash,
                session_expiry(),
                now,
                hash_user_agent(user_agent or "", self._pepper),
                device_label(user_agent or ""),
                now,
            ),
        )
        return token

    def create_session(self, account_id: str, user_agent: str) -> str:
        with self._lock:
            return self._insert_session(account_id, user_agent)

    def rekey_account(
        self,
        account_id: str,
        new_auth_key: bytes,
        kdf_salt: str,
        kdf_params: dict,
        blob: Optional[Dict[str, Any]],
        user_agent: str,
    ) -> str:
        """Swap the account to a new master key in one transaction.

        Replaces the verifier, salt and KDF params; replaces the vault blob when
        one is given; deletes every revision (they are sealed with the old key,
        which is exactly what a password change after a leak must retire);
        revokes every session and mints one new one. Returns its token.
        """
        verifier = hash_auth_key(new_auth_key)
        params_json = json.dumps(kdf_params, separators=(",", ":"))
        now = isoformat()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "UPDATE accounts SET auth_verifier = ?, kdf_salt = ?, kdf_params = ? WHERE id = ?",
                    (verifier, kdf_salt, params_json, account_id),
                )
                self._conn.execute("DELETE FROM vault_revisions WHERE account_id = ?", (account_id,))
                if blob is not None:
                    updated = self._conn.execute(
                        "UPDATE vault_blobs SET ciphertext = ?, nonce = ?, aad_version = ?, byte_size = ?,"
                        " updated_at = ? WHERE account_id = ?",
                        (blob["ct"], blob["nonce"], blob["v"], blob["size"], now, account_id),
                    )
                    if not updated.rowcount:
                        self._conn.execute(
                            "INSERT INTO vault_blobs (id, account_id, ciphertext, nonce, aad_version, byte_size,"
                            " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (new_id(), account_id, blob["ct"], blob["nonce"], blob["v"], blob["size"], now),
                        )
                self._conn.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))
                token = self._insert_session(account_id, user_agent)
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return token

    def session_account(self, token: str) -> Optional[sqlite3.Row]:
        if not token:
            return None
        token_hash = hash_token(token)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT a.*, s.id AS session_id, s.expires_at AS session_expires,
                       s.last_used_at AS session_last_used
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
        self._touch_session(row)
        return row

    def _touch_session(self, row: sqlite3.Row) -> None:
        """Record last use, at most once a minute per session (it is a write)."""
        try:
            last = parse_iso(row["session_last_used"]) if row["session_last_used"] else None
        except Exception:
            last = None
        if last is not None and (utcnow() - last).total_seconds() < 60:
            return
        with self._lock:
            self._conn.execute("UPDATE sessions SET last_used_at = ? WHERE id = ?", (isoformat(), row["session_id"]))

    def list_sessions(self, account_id: str) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT id, device_label, created_at, last_used_at, expires_at FROM sessions"
                " WHERE account_id = ? ORDER BY COALESCE(last_used_at, created_at) DESC",
                (account_id,),
            ).fetchall()

    def revoke_account_session(self, account_id: str, session_id: str) -> bool:
        """Revoke one of *this account's* sessions. False if it is not theirs."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM sessions WHERE id = ? AND account_id = ?", (session_id, account_id)
            )
        return bool(cur.rowcount)

    def revoke_other_sessions(self, account_id: str, keep_session_id: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM sessions WHERE account_id = ? AND id != ?", (account_id, keep_session_id)
            )
        return cur.rowcount

    def security_events(self, account_id: str, limit: int = 50) -> List[sqlite3.Row]:
        # vault_put fires on every save; it would drown out what matters here.
        with self._lock:
            return self._conn.execute(
                "SELECT event, at FROM audit_events WHERE account_id = ? AND event != 'vault_put'"
                " ORDER BY at DESC, rowid DESC LIMIT ?",
                (account_id, limit),
            ).fetchall()

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
        kdf_params = legacy_kdf_params()
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
        # The account's current params, so the envelope always says how to
        # derive the key that opens it.
        "kdf": {**(kdf_params or legacy_kdf_params()), "salt": kdf_salt},
        "byte_size": row["byte_size"],
        "updated_at": row["updated_at"],
        "id": row["id"],
    }
    return envelope
