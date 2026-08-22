"""Encrypted vault storage, lock/unlock, and entry operations."""

from __future__ import annotations

import base64
import csv
import json
import os
import time
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import InvalidToken

from pwmanager.constants import AUTOLOCK_SECONDS, DEFAULT_VAULT_PATH, VAULT_VERSION
from pwmanager.crypto import (
    decrypt_bytes,
    derive_key,
    encrypt_bytes,
    file_hmac,
    generate_salt,
    secure_wipe,
    verify_file_hmac,
)
from pwmanager.models import Entry

# Owner read/write only. The vault holds ciphertext, but the salt, KDF choice
# and file size are still worth keeping away from other local accounts.
VAULT_FILE_MODE = 0o600


class VaultIntegrityError(Exception):
    """The vault decrypted, but its file-level HMAC does not match.

    Raised only when the master password is provably correct — meaning the
    mismatch is tampering with an authenticated-but-unencrypted field (the
    salt, the KDF name, the version) rather than a typo.
    """


class Vault:
    def __init__(self, path: str = DEFAULT_VAULT_PATH, lock_timeout: Optional[int] = None):
        self.path = path
        self.key: Optional[bytes] = None
        self.entries: Dict[str, Entry] = {}
        self.kdf_used: str = ""
        self.last_activity: float = time.time()
        self.lock_timeout: int = (
            int(lock_timeout) if lock_timeout is not None else AUTOLOCK_SECONDS
        )

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

        # Decrypt first. A failure here means the password was wrong, which is
        # by far the common case and must not be reported as tampering.
        plaintext = decrypt_bytes(token, key)  # raises InvalidToken on bad password

        # The password is now known to be correct, so a bad HMAC can only mean
        # the file was edited. Fernet authenticates the ciphertext but not the
        # surrounding JSON, so without this check an attacker with write access
        # could alter the version or KDF fields undetected.
        if "hmac" in payload:
            if not verify_file_hmac(payload, key):
                secure_wipe(bytearray(key))
                raise VaultIntegrityError(
                    f"Vault integrity check failed for {self.path}. The password is "
                    "correct but the file has been modified outside pwmanager. "
                    "Restore from a backup, or run `pwmanager verify` for detail."
                )

        raw = json.loads(plaintext.decode("utf-8"))
        self.entries = {name: Entry.from_dict(d) for name, d in raw.items()}
        self.key = key
        self.kdf_used = kdf
        self.last_activity = time.time()

    def save(self) -> None:
        if self.key is None:
            raise RuntimeError("Vault is locked")
        # The salt lives only in the file, so it has to be read back rather
        # than regenerated — re-deriving would orphan every existing entry.
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except FileNotFoundError as e:
            raise RuntimeError(
                f"Vault file disappeared while unlocked: {self.path}. "
                "Nothing was written; restore the file and unlock again."
            ) from e
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Vault file became unreadable while unlocked: {self.path} ({e}). "
                "Refusing to overwrite it — restore from a backup."
            ) from e
        if "salt" not in payload:
            raise RuntimeError(
                f"Vault file is missing its salt: {self.path}. Refusing to overwrite."
            )
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
        """Write the vault atomically, owner-only, and durably.

        The temp file is created with 0600 from the start (rather than being
        chmod-ed afterwards) so there is no window where another local user can
        open it. fsync before the rename, and fsync of the directory after,
        keep a power loss from leaving a truncated or missing vault.
        """
        tmp = self.path + ".tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp, flags, VAULT_FILE_MODE)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            # Never leave a half-written temp file behind for a later run to find.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        os.replace(tmp, self.path)

        # Best effort: not every platform or filesystem allows opening a
        # directory for fsync, and failing to do so should not fail the save.
        try:
            dir_fd = os.open(os.path.dirname(os.path.abspath(self.path)) or ".", os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass

    def file_mode(self) -> Optional[int]:
        """Permission bits of the vault file, or None if it does not exist."""
        try:
            return os.stat(self.path).st_mode & 0o777
        except OSError:
            return None

    def tighten_permissions(self) -> bool:
        """Reduce an existing vault to owner-only. True if anything changed.

        Vaults created before 2.4 were written with the process umask, which on
        most systems means group- and world-readable.
        """
        mode = self.file_mode()
        if mode is None or mode == VAULT_FILE_MODE:
            return False
        try:
            os.chmod(self.path, VAULT_FILE_MODE)
        except OSError:
            return False
        return True

    # ---- entry ops ----

    def touch(self) -> None:
        self.last_activity = time.time()

    def is_idle(self) -> bool:
        return (time.time() - self.last_activity) > self.lock_timeout

    def add(self, name: str, entry: Entry) -> None:
        self.entries[name] = entry
        self.save()

    def delete(self, name: str) -> None:
        del self.entries[name]
        self.save()

    def pin(self, name: str) -> None:
        if name not in self.entries:
            raise KeyError(name)
        self.entries[name].favorite = True
        self.entries[name].updated_at = time.time()
        self.save()

    def unpin(self, name: str) -> None:
        if name not in self.entries:
            raise KeyError(name)
        self.entries[name].favorite = False
        self.entries[name].updated_at = time.time()
        self.save()

    def touch_entry(self, name: str) -> None:
        """Mark entry as rotated: update ``updated_at`` without changing password."""
        if name not in self.entries:
            raise KeyError(name)
        self.entries[name].updated_at = time.time()
        self.save()

    def mark_accessed(self, name: str) -> None:
        """Record last_accessed for recent list (view / get / copy)."""
        if name not in self.entries:
            raise KeyError(name)
        self.entries[name].last_accessed = time.time()
        self.save()

    def recent(self, limit: int = 10) -> List[str]:
        """Return entry names ordered by last_accessed descending (accessed only)."""
        accessed = [
            (n, e.last_accessed)
            for n, e in self.entries.items()
            if (e.last_accessed or 0) > 0
        ]
        accessed.sort(key=lambda t: (-t[1], t[0].lower()))
        return [n for n, _ in accessed[: max(0, int(limit))]]

    def verify_integrity(self) -> Tuple[bool, str]:
        """Recompute file HMAC and report OK/fail. Does not list entries.

        Requires an unlocked vault (key present). Returns (ok, message).
        """
        if self.key is None:
            return False, "Vault is locked"
        if not self.exists():
            return False, f"Vault file not found: {self.path}"
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            return False, f"Cannot read vault: {e}"

        if "hmac" not in payload:
            return False, "Vault has no HMAC field (legacy or incomplete file)"
        if "salt" not in payload or "vault" not in payload:
            return False, "Vault missing salt or ciphertext"

        if not verify_file_hmac(payload, self.key):
            return False, "HMAC mismatch — vault may be tampered or key wrong"

        # Also confirm ciphertext still decrypts with current key
        try:
            decrypt_bytes(payload["vault"].encode("ascii"), self.key)
        except InvalidToken:
            return False, "Ciphertext failed to decrypt"

        return True, "OK — integrity verified"

    def favorites(self) -> List[str]:
        return sorted(n for n, e in self.entries.items() if e.favorite)

    def sorted_entry_names(self) -> List[str]:
        """Favorites first (alpha), then the rest (alpha)."""
        favs = sorted(n for n, e in self.entries.items() if e.favorite)
        rest = sorted(n for n, e in self.entries.items() if not e.favorite)
        return favs + rest

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
        # Favorites first among exact matches
        return sorted(results, key=lambda n: (not self.entries[n].favorite, n.lower()))

    def fuzzy_search(
        self,
        query: str,
        tag: Optional[str] = None,
        limit: int = 10,
        cutoff: float = 0.4,
        exclude: Optional[List[str]] = None,
    ) -> List[Tuple[str, float]]:
        """Rank entries by fuzzy similarity when exact search misses (or to supplement).

        Returns list of (name, score) sorted by score descending, favorites boosted.
        """
        q = (query or "").lower().strip()
        if not q:
            return []
        tag_q = tag.lower() if tag else None
        excluded = set(exclude or [])
        scored: List[Tuple[str, float]] = []

        for name, e in self.entries.items():
            if name in excluded:
                continue
            if tag_q is not None:
                entry_tags = [t.lower() for t in e.tags]
                if tag_q not in entry_tags:
                    continue
            fields = [name, e.username, e.url, e.notes] + list(e.tags)
            best = 0.0
            for field in fields:
                if not field:
                    continue
                fl = field.lower()
                # SequenceMatcher ratio against full field and against query-length windows
                best = max(best, SequenceMatcher(None, q, fl).ratio())
                if q in fl:
                    best = max(best, 0.95)
                # Token-wise best
                for token in fl.replace("/", " ").replace(".", " ").split():
                    best = max(best, SequenceMatcher(None, q, token).ratio())
            if e.favorite:
                best = min(1.0, best + 0.05)
            if best >= cutoff:
                scored.append((name, round(best, 4)))

        scored.sort(key=lambda t: (-t[1], t[0].lower()))
        return scored[:limit]

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

    def export_csv(self, out_path: str) -> int:
        """Export all entries as plaintext CSV. Returns number of rows written.

        WARNING: output is unencrypted. Caller must obtain explicit confirmation.
        """
        fieldnames = [
            "name",
            "username",
            "password",
            "url",
            "notes",
            "tags",
            "totp_secret",
            "favorite",
            "kind",
        ]
        count = 0
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for name in self.sorted_entry_names():
                e = self.entries[name]
                writer.writerow(
                    {
                        "name": name,
                        "username": e.username,
                        "password": e.password,
                        "url": e.url,
                        "notes": e.notes,
                        "tags": ",".join(e.tags),
                        "totp_secret": e.totp_secret,
                        "favorite": "true" if e.favorite else "false",
                        "kind": getattr(e, "kind", "login") or "login",
                    }
                )
                count += 1
        return count

    def export_json(self, out_path: str) -> int:
        """Export all entries as plaintext JSON. Returns number of entries written.

        WARNING: output is unencrypted (passwords, TOTP secrets in cleartext).
        Caller must obtain explicit confirmation (e.g. --i-understand).
        """
        payload: Dict[str, Any] = {
            "exported_at": time.time(),
            "version": VAULT_VERSION,
            "entries": {},
        }
        for name in self.sorted_entry_names():
            payload["entries"][name] = self.entries[name].to_dict()
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return len(payload["entries"])

    def stats(self) -> Dict[str, Any]:
        """Aggregate vault statistics for the `stats` command."""
        from collections import Counter

        from pwmanager.audit import audit_vault

        total = len(self.entries)
        tags_counter: Counter = Counter()
        with_totp = 0
        favorites = 0
        notes = 0
        logins = 0
        oldest_updated: Optional[Tuple[str, float]] = None
        newest_updated: Optional[Tuple[str, float]] = None

        for name, e in self.entries.items():
            for t in e.tags:
                tags_counter[t] += 1
            if e.totp_secret:
                with_totp += 1
            if e.favorite:
                favorites += 1
            if getattr(e, "kind", "login") == "note":
                notes += 1
            else:
                logins += 1
            ts = e.updated_at or e.created_at or 0.0
            if oldest_updated is None or ts < oldest_updated[1]:
                oldest_updated = (name, ts)
            if newest_updated is None or ts > newest_updated[1]:
                newest_updated = (name, ts)

        report = audit_vault(self)
        return {
            "total_entries": total,
            "logins": logins,
            "notes": notes,
            "favorites": favorites,
            "with_totp": with_totp,
            "without_totp": total - with_totp,
            "tags": dict(sorted(tags_counter.items(), key=lambda x: (-x[1], x[0]))),
            "oldest_updated": (
                {"name": oldest_updated[0], "updated_at": oldest_updated[1]}
                if oldest_updated
                else None
            ),
            "newest_updated": (
                {"name": newest_updated[0], "updated_at": newest_updated[1]}
                if newest_updated
                else None
            ),
            "health_score": report.health_score,
        }


# Re-export InvalidToken for callers that catch unlock failures
__all__ = ["Vault", "InvalidToken"]
