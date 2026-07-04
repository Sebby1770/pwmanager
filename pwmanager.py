"""Advanced local password manager (single-file edition).

Features
--------
- Master password unlocks an encrypted JSON vault
- Argon2id key derivation (falls back to PBKDF2 if argon2-cffi missing)
- Fernet (AES-128-CBC + HMAC-SHA256) for entry encryption
- Add / view / search / edit / delete entries
- Tags/categories per entry
- Password history (previous passwords kept on edit)
- Secure password generator (length + character class options)
- Diceware-style passphrase generator
- Password strength meter (Shannon entropy)
- TOTP (RFC 6238) secret storage and live code generation
- Clipboard copy with auto-clear after N seconds
- Auto-lock after inactivity timeout
- Failed-unlock lockout with exponential backoff — persisted across restarts
- Vault audit: reused / weak / stale passwords, plus an opt-in HaveIBeenPwned
  breach check via the k-anonymity API (only 5-char hash prefixes leave)
- Encrypted export / import for backups
- CSV import from Chrome / Bitwarden / generic exports (import-csv --format)
- Enforced HMAC integrity check (unlock is refused if the file was tampered with)
- Pluggable storage: a JSON file or an embedded SQLite database (--backend sqlite)
- Optional audit log of events (never secrets) via --log-file
- Vault files written with owner-only (0600) permissions
- Interactive menu OR one-shot CLI subcommands
- Best-effort secure wipe of sensitive strings in memory

Usage
-----
    python pwmanager.py                    # interactive menu
    python pwmanager.py add github         # one-shot add
    python pwmanager.py gen --length 24    # generate a password
    python pwmanager.py audit --hibp       # password health + breach check
    python pwmanager.py --backend sqlite   # use the embedded SQLite backend
    python pwmanager.py --log-file audit.log view   # with an audit trail
    python pwmanager.py --help             # full help

Vault file lives next to this script as `vault.json` (or `vault.db` for the
SQLite backend) unless --vault is given.
"""

from __future__ import annotations

import argparse
import base64
import csv
import ctypes
import getpass
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import stat
import string
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ----- Optional dependencies (graceful fallback) -----
try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

VAULT_VERSION = 2
DEFAULT_VAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "vault.json"
)

# Argon2id parameters (sensible defaults — adjust higher for slower/stronger)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4

# PBKDF2 fallback
PBKDF2_ITERATIONS = 600_000

SALT_SIZE = 16
KEY_SIZE = 32

AUTOLOCK_SECONDS = 300       # 5 minutes idle
CLIPBOARD_CLEAR_SECONDS = 20
MAX_UNLOCK_ATTEMPTS = 5

# ----- Audit logging -----
# The audit log records *events* (unlock, add, delete, tamper) with entry
# names and timestamps. It NEVER records passwords, secrets, or vault contents.
LOG = logging.getLogger("pwmanager")


def setup_logging(log_file: Optional[str] = None, verbose: bool = False) -> None:
    """Configure the audit logger. Off by default; opt in with --log-file."""
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)
    handlers: List[logging.Handler] = []
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        handlers.append(fh)
        # Keep the audit log owner-only.
        try:
            os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    if verbose:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        handlers.append(sh)
    if not handlers:
        handlers.append(logging.NullHandler())
    LOG.handlers = handlers


class IntegrityError(Exception):
    """Raised when a vault's authentication tag does not match its contents."""


# =============================================================================
# Persistent unlock throttle
# =============================================================================

LOCKOUT_BASE_SECONDS = 30
LOCKOUT_MAX_SECONDS = 3600


class Throttle:
    """Persist failed-unlock state in a sidecar file next to the vault.

    Pre-2.1 the failed-attempt counter lived in process memory, so an attacker
    could dodge the lockout by simply restarting the program. This records
    failures on disk (owner-only) and enforces an exponential cooldown that
    survives restarts: 30s after the 5th failure, doubling per failure, capped
    at an hour. A successful unlock clears it.
    """

    def __init__(self, vault_path: str):
        self.path = vault_path + ".throttle"

    def _read(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return {"fails": 0, "last_fail": 0.0}
            return data
        except (OSError, ValueError):
            return {"fails": 0, "last_fail": 0.0}

    def seconds_remaining(self) -> int:
        """Seconds of cooldown left, or 0 if unlocking is currently allowed."""
        state = self._read()
        fails = int(state.get("fails", 0))
        if fails < MAX_UNLOCK_ATTEMPTS:
            return 0
        wait = min(
            LOCKOUT_BASE_SECONDS * (2 ** (fails - MAX_UNLOCK_ATTEMPTS)),
            LOCKOUT_MAX_SECONDS,
        )
        remaining = float(state.get("last_fail", 0.0)) + wait - time.time()
        if remaining <= 0:
            return 0
        return int(remaining) + 1  # ceil, so we never report 0 while locked

    def record_failure(self) -> int:
        """Record one failed unlock; returns the cumulative failure count."""
        state = self._read()
        state["fails"] = int(state.get("fails", 0)) + 1
        state["last_fail"] = time.time()
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return int(state["fails"])

    def reset(self) -> None:
        try:
            os.remove(self.path)
        except OSError:
            pass

# ANSI colors (auto-disabled if not a TTY)
class C:
    USE = sys.stdout.isatty()
    @classmethod
    def w(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.USE else text
    @classmethod
    def bold(cls, t): return cls.w("1", t)
    @classmethod
    def dim(cls, t): return cls.w("2", t)
    @classmethod
    def red(cls, t): return cls.w("31", t)
    @classmethod
    def green(cls, t): return cls.w("32", t)
    @classmethod
    def yellow(cls, t): return cls.w("33", t)
    @classmethod
    def blue(cls, t): return cls.w("34", t)
    @classmethod
    def cyan(cls, t): return cls.w("36", t)


# =============================================================================
# Secure memory wipe (best-effort)
# =============================================================================

def secure_wipe(data: Any) -> None:
    """Best-effort overwrite of a bytes/bytearray buffer in memory.

    Python strings are immutable so true wiping is impossible — for sensitive
    values we accept this and rely on the OS process boundary. For bytearrays
    we can actually zero the buffer.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        # Try to zero via ctypes — works on CPython but is unsafe in general.
        try:
            buf = (ctypes.c_char * len(data)).from_address(id(data) + bytes.__basicsize__ - 1)
            ctypes.memset(ctypes.addressof(buf), 0, len(data))
        except Exception:
            pass


# =============================================================================
# Crypto
# =============================================================================

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


# =============================================================================
# Password generation
# =============================================================================

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    if length < 4:
        raise ValueError("Length must be at least 4.")

    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    syms = SYMBOLS

    if avoid_ambiguous:
        ambiguous = set("Il1O0o`'\"|")
        lower = "".join(c for c in lower if c not in ambiguous)
        upper = "".join(c for c in upper if c not in ambiguous)
        digits = "".join(c for c in digits if c not in ambiguous)
        syms = "".join(c for c in syms if c not in ambiguous)

    pools = [lower]
    required = [secrets.choice(lower)]
    if use_upper:
        pools.append(upper); required.append(secrets.choice(upper))
    if use_digits:
        pools.append(digits); required.append(secrets.choice(digits))
    if use_symbols:
        pools.append(syms); required.append(secrets.choice(syms))

    all_chars = "".join(pools)
    chars = required + [secrets.choice(all_chars) for _ in range(length - len(required))]
    # Fisher-Yates with secrets
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


# Small embedded EFF-style wordlist (300 words). For real diceware use the
# full 7776-word EFF list — this is a compact subset for zero-dependency use.
_WORDLIST = """\
abandon ability able about above absent absorb abstract absurd abuse access accident
account accuse achieve acid acoustic acquire across action actor actress actual adapt
add addict address adjust admit adult advance advice aerobic affair afford afraid again
age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley
allow almost alone alpha already also alter always amateur amazing among amount amused
analyst anchor ancient anger angle angry animal ankle announce annual another answer
antenna antique anxiety any apart apology appear apple approve april arch arctic area
arena argue arm armed armor army around arrange arrest arrive arrow art artist artwork
ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract
auction audit august aunt author auto autumn average avocado avoid awake aware away
awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo
banana banner bargain barrel basic basket battle beach bean beauty because become beef
before begin behave behind believe below belt bench benefit best betray better between
beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast
bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone
bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand
brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze
broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle
""".split()

def generate_passphrase(words: int = 5, separator: str = "-", capitalize: bool = False) -> str:
    if words < 3:
        raise ValueError("Use at least 3 words.")
    chosen = [secrets.choice(_WORDLIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


def password_entropy_bits(password: str) -> float:
    """Estimate Shannon entropy of a password based on the character pool used."""
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in SYMBOLS for c in password): pool += len(SYMBOLS)
    if any(c not in string.ascii_letters + string.digits + SYMBOLS for c in password):
        pool += 32  # rough other-chars allowance
    if pool == 0:
        return 0.0
    import math
    return len(password) * math.log2(pool)


def strength_label(bits: float) -> str:
    if bits < 28: return C.red("Very weak")
    if bits < 50: return C.yellow("Weak")
    if bits < 70: return C.yellow("Reasonable")
    if bits < 90: return C.green("Strong")
    return C.green(C.bold("Very strong"))


# =============================================================================
# Vault audit (password health)
# =============================================================================

WEAK_BITS_THRESHOLD = 50
STALE_AFTER_DAYS = 365


def analyze_entries(entries: Dict[str, "Entry"]) -> Dict[str, Any]:
    """Pure audit pass over the decrypted entries (no network, no mutation).

    Returns {"reused": [[names sharing a password], ...],
             "weak":   [names with < WEAK_BITS_THRESHOLD bits of entropy],
             "stale":  [names not updated in STALE_AFTER_DAYS days]}.
    """
    by_password: Dict[str, List[str]] = {}
    weak: List[str] = []
    stale: List[str] = []
    now = time.time()
    for name, e in entries.items():
        if e.password:
            by_password.setdefault(e.password, []).append(name)
            if password_entropy_bits(e.password) < WEAK_BITS_THRESHOLD:
                weak.append(name)
        if now - e.updated_at > STALE_AFTER_DAYS * 86400:
            stale.append(name)
    reused = sorted(sorted(names) for names in by_password.values() if len(names) > 1)
    return {"reused": reused, "weak": sorted(weak), "stale": sorted(stale)}


def _hibp_fetch(prefix: str) -> str:
    """Fetch one k-anonymity range from HaveIBeenPwned (network)."""
    import urllib.request

    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "pwmanager-audit"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8", "replace")


def hibp_breach_count(
    password: str, fetch: Optional[Callable[[str], str]] = None
) -> int:
    """How many breaches this password appears in, via HIBP's k-anonymity API.

    Privacy property: only the first 5 hex chars of the password's SHA-1 ever
    leave the machine; the full hash is matched locally against the returned
    suffix list. Returns 0 when not found. `fetch` is injectable for tests.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    body = (fetch or _hibp_fetch)(prefix)
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            try:
                return int(count.strip() or 0)
            except ValueError:
                return 1
    return 0


# =============================================================================
# TOTP (RFC 6238)
# =============================================================================

def totp_now(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    """Generate the current TOTP code from a base32 secret."""
    try:
        key = base64.b32decode(secret_b32.upper().replace(" ", ""), casefold=True)
    except Exception as e:
        raise ValueError(f"Invalid TOTP secret: {e}")
    counter = int(time.time() // period)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = ((h[offset] & 0x7F) << 24
            | (h[offset + 1] & 0xFF) << 16
            | (h[offset + 2] & 0xFF) << 8
            | (h[offset + 3] & 0xFF))
    return str(code % (10 ** digits)).zfill(digits)


def totp_seconds_remaining(period: int = 30) -> int:
    return period - int(time.time() % period)


# =============================================================================
# Vault data model
# =============================================================================

@dataclass
class Entry:
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    totp_secret: str = ""
    history: List[Dict[str, Any]] = field(default_factory=list)  # [{password, changed_at}]
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        return cls(
            username=d.get("username", ""),
            password=d.get("password", ""),
            url=d.get("url", ""),
            notes=d.get("notes", ""),
            tags=list(d.get("tags", [])),
            totp_secret=d.get("totp_secret", ""),
            history=list(d.get("history", [])),
            created_at=d.get("created_at", time.time()),
            updated_at=d.get("updated_at", time.time()),
        )


# =============================================================================
# Storage backends
# =============================================================================
#
# Both backends persist the *same* encrypted payload (a dict of
# version/kdf/salt/vault/hmac). The cryptography is identical — only the
# container differs: a JSON file, or a single row in an embedded SQLite
# database. This is what the `--backend sqlite` flag switches between.

class StorageBackend:
    """Abstract store for the encrypted vault payload."""

    path: str

    def exists(self) -> bool:
        raise NotImplementedError

    def read_payload(self) -> dict:
        raise NotImplementedError

    def write_payload(self, payload: dict) -> None:
        raise NotImplementedError

    def remove(self) -> None:
        raise NotImplementedError

    def warn_if_insecure(self) -> None:
        """Log a warning if the store is readable by other users."""
        try:
            mode = os.stat(self.path).st_mode
        except OSError:
            return
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            LOG.warning("vault file %s is accessible by other users", self.path)


class JSONStorage(StorageBackend):
    """Default backend: an indented JSON file, written atomically, mode 0600."""

    def __init__(self, path: str):
        self.path = path

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def read_payload(self) -> dict:
        if not os.path.exists(self.path):
            raise FileNotFoundError(self.path)
        with open(self.path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Vault file is not valid JSON: {e}")

    def write_payload(self, payload: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # owner read/write only
        os.replace(tmp, self.path)

    def remove(self) -> None:
        if os.path.exists(self.path):
            os.remove(self.path)


class SQLiteStorage(StorageBackend):
    """Embedded-database backend: the encrypted blob lives in a one-row SQLite
    table. Same ciphertext as the JSON backend, different container — handy for
    atomic writes and as a stepping stone to a server-backed store."""

    def __init__(self, path: str):
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vault ("
            "  id INTEGER PRIMARY KEY CHECK (id = 1),"
            "  version INTEGER, kdf TEXT, salt TEXT, vault TEXT, hmac TEXT)"
        )
        return conn

    def exists(self) -> bool:
        if not os.path.exists(self.path):
            return False
        try:
            conn = self._connect()
        except sqlite3.DatabaseError:
            return False
        try:
            row = conn.execute("SELECT 1 FROM vault WHERE id = 1").fetchone()
            return row is not None
        finally:
            conn.close()

    def read_payload(self) -> dict:
        if not os.path.exists(self.path):
            raise FileNotFoundError(self.path)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT version, kdf, salt, vault, hmac FROM vault WHERE id = 1"
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise FileNotFoundError(self.path)
        payload = {"version": row[0], "kdf": row[1], "salt": row[2], "vault": row[3]}
        if row[4] is not None:
            payload["hmac"] = row[4]
        return payload

    def write_payload(self, payload: dict) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO vault (id, version, kdf, salt, vault, hmac) "
                "VALUES (1, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "  version=excluded.version, kdf=excluded.kdf, salt=excluded.salt,"
                "  vault=excluded.vault, hmac=excluded.hmac",
                (
                    payload.get("version", VAULT_VERSION),
                    payload["kdf"],
                    payload["salt"],
                    payload["vault"],
                    payload.get("hmac"),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        try:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def remove(self) -> None:
        if os.path.exists(self.path):
            os.remove(self.path)


def make_storage(path: str, backend: str = "json") -> StorageBackend:
    if backend == "sqlite":
        return SQLiteStorage(path)
    if backend == "json":
        return JSONStorage(path)
    raise ValueError(f"Unknown backend: {backend}")


# =============================================================================
# Vault
# =============================================================================

class Vault:
    def __init__(self, path: str = DEFAULT_VAULT_PATH, backend: str = "json"):
        self.path = path
        self.backend = backend
        self.storage = make_storage(path, backend)
        self.key: Optional[bytes] = None
        self.entries: Dict[str, Entry] = {}
        self.kdf_used: str = ""
        self.last_activity: float = time.time()

    # ---- persistence ----

    def exists(self) -> bool:
        return self.storage.exists()

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
        self.storage.write_payload(payload)
        self.key = key
        self.kdf_used = kdf_used
        self.entries = {}
        self.last_activity = time.time()
        LOG.info("vault created (backend=%s, kdf=%s)", self.backend, kdf_used)

    def unlock(self, master_password: str) -> None:
        payload = self.storage.read_payload()  # FileNotFoundError if absent
        self.storage.warn_if_insecure()

        try:
            salt = base64.b64decode(payload["salt"])
            token = payload["vault"].encode("ascii")
            kdf = payload.get("kdf", "pbkdf2")
        except KeyError as e:
            raise ValueError(f"Vault file missing field: {e}")

        key, _ = derive_key(master_password, salt, kdf)

        # Fernet raises InvalidToken on a wrong password. A successful decrypt
        # proves the key is correct — so if an HMAC is present and *still*
        # mismatches, the surrounding envelope (salt/version) was tampered with.
        plaintext = decrypt_bytes(token, key)

        if "hmac" in payload:
            expected = file_hmac(payload, key)
            if not hmac.compare_digest(expected, str(payload["hmac"])):
                LOG.error("integrity check FAILED for %s", self.path)
                raise IntegrityError(
                    "vault integrity check failed — the file may be corrupt or tampered with"
                )

        raw = json.loads(plaintext.decode("utf-8"))
        self.entries = {name: Entry.from_dict(d) for name, d in raw.items()}
        self.key = key
        self.kdf_used = kdf
        self.last_activity = time.time()
        LOG.info("vault unlocked (%d entries)", len(self.entries))

    def save(self) -> None:
        if self.key is None:
            raise RuntimeError("Vault is locked")
        payload = self.storage.read_payload()
        raw = {name: e.to_dict() for name, e in self.entries.items()}
        ciphertext = encrypt_bytes(json.dumps(raw).encode("utf-8"), self.key)
        payload["vault"] = ciphertext.decode("ascii")
        payload["version"] = VAULT_VERSION
        payload["hmac"] = file_hmac(payload, self.key)
        self.storage.write_payload(payload)
        self.last_activity = time.time()

    def lock(self) -> None:
        self.entries.clear()
        if isinstance(self.key, (bytes, bytearray)):
            secure_wipe(self.key)
        self.key = None

    # ---- entry ops ----

    def touch(self) -> None:
        self.last_activity = time.time()

    def is_idle(self) -> bool:
        return (time.time() - self.last_activity) > AUTOLOCK_SECONDS

    def add(self, name: str, entry: Entry) -> None:
        self.entries[name] = entry
        self.save()
        LOG.info("entry added/updated: %s", name)

    def delete(self, name: str) -> None:
        del self.entries[name]
        self.save()
        LOG.info("entry deleted: %s", name)

    def search(self, query: str) -> List[str]:
        q = query.lower()
        results = []
        for name, e in self.entries.items():
            haystack = " ".join([
                name, e.username, e.url, e.notes, " ".join(e.tags)
            ]).lower()
            if q in haystack:
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
        try:
            os.chmod(out_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        LOG.info("exported %d entries to %s", len(self.entries), out_path)

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


# =============================================================================
# CSV import (browser / password-manager exports)
# =============================================================================

# Column mappings per export format. An empty column name means "not present
# in this format". Headers are matched case-insensitively.
CSV_COLUMN_MAPS: Dict[str, Dict[str, str]] = {
    "chrome": {
        "name": "name", "username": "username", "password": "password",
        "url": "url", "notes": "note", "totp": "",
    },
    "bitwarden": {
        "name": "name", "username": "login_username", "password": "login_password",
        "url": "login_uri", "notes": "notes", "totp": "login_totp",
    },
    "generic": {
        "name": "name", "username": "username", "password": "password",
        "url": "url", "notes": "notes", "totp": "totp",
    },
}


def _domain_of(url: str) -> str:
    """Best-effort hostname for naming an entry when the export has no name."""
    if not url:
        return ""
    from urllib.parse import urlparse

    netloc = urlparse(url if "//" in url else "//" + url).netloc
    return netloc[4:] if netloc.startswith("www.") else netloc


def import_csv_entries(path: str, fmt: str = "generic") -> Dict[str, Entry]:
    """Parse a password-manager CSV export into Entry objects.

    Pure (no vault mutation) so it is testable offline. Supported formats:
    chrome, bitwarden, generic. Rows with neither a username nor a password
    are skipped; unnamed rows are named after their URL's domain; duplicate
    names get a " (2)"-style suffix.
    """
    cols = CSV_COLUMN_MAPS.get(fmt)
    if cols is None:
        raise ValueError(f"Unknown CSV format: {fmt} (use {', '.join(sorted(CSV_COLUMN_MAPS))})")

    entries: Dict[str, Entry] = {}
    # utf-8-sig: browsers commonly prepend a BOM to CSV exports.
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("CSV file has no header row")
        for i, raw_row in enumerate(reader, start=1):
            row = {
                (k or "").strip().lower(): (v or "").strip()
                for k, v in raw_row.items()
            }

            def get(key: str) -> str:
                col = cols[key]
                return row.get(col, "") if col else ""

            username, password = get("username"), get("password")
            if not username and not password:
                continue
            name = get("name") or _domain_of(get("url")) or f"import-{i}"
            base, n = name, 2
            while name in entries:
                name = f"{base} ({n})"
                n += 1
            entries[name] = Entry(
                username=username,
                password=password,
                url=get("url"),
                notes=get("notes"),
                totp_secret=get("totp"),
            )
    return entries


def cmd_import_csv(vault: Vault, path: str, fmt: str, tag: str) -> None:
    if not os.path.exists(path):
        print(C.red("File not found.\n"))
        return
    try:
        imported = import_csv_entries(path, fmt)
    except (ValueError, csv.Error, OSError) as e:
        print(C.red(f"Import failed: {e}\n"))
        return
    if not imported:
        print(C.yellow("No importable rows found.\n"))
        return

    added = 0
    for name, entry in imported.items():
        final, n = name, 2
        while final in vault.entries:
            final = f"{name} ({n})"
            n += 1
        if tag:
            entry.tags = [tag]
        vault.entries[final] = entry
        added += 1
    vault.save()
    LOG.info("csv import: %d entries from %s (%s format)", added, os.path.basename(path), fmt)
    print(C.green(f"Imported {added} entries from {path} ({fmt} format).\n"))
    print(C.yellow("The CSV still holds your passwords in plaintext — delete it securely."))


# =============================================================================
# Clipboard with auto-clear
# =============================================================================

_clipboard_timer: Optional[threading.Timer] = None

def copy_with_autoclear(text: str, seconds: int = CLIPBOARD_CLEAR_SECONDS) -> bool:
    global _clipboard_timer
    if not CLIPBOARD_AVAILABLE:
        return False
    try:
        pyperclip.copy(text)
    except Exception:
        return False

    if _clipboard_timer:
        _clipboard_timer.cancel()

    def clear():
        try:
            current = pyperclip.paste()
            if current == text:
                pyperclip.copy("")
        except Exception:
            pass

    _clipboard_timer = threading.Timer(seconds, clear)
    _clipboard_timer.daemon = True
    _clipboard_timer.start()
    return True


# =============================================================================
# CLI helpers
# =============================================================================

def prompt(text: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        result = input(f"{text}{suffix}: ").strip()
        return result or default
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def prompt_secret(text: str) -> str:
    try:
        return getpass.getpass(f"{text}: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def prompt_yn(text: str, default: bool = False) -> bool:
    suffix = "(Y/n)" if default else "(y/N)"
    try:
        ans = input(f"{text} {suffix}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not ans:
        return default
    return ans.startswith("y")


def prompt_int(text: str, default: int) -> int:
    raw = prompt(text, str(default))
    try:
        return int(raw)
    except ValueError:
        print(C.yellow(f"Not a number, using {default}."))
        return default


def print_entry(name: str, e: Entry, show_password: bool = True) -> None:
    print()
    print(C.bold(C.cyan(f"  {name}")))
    print(f"  {C.dim('Username:')} {e.username}")
    if show_password:
        bits = password_entropy_bits(e.password)
        print(f"  {C.dim('Password:')} {e.password}  "
              f"{C.dim(f'({bits:.0f} bits — {strength_label(bits)})')}")
    else:
        print(f"  {C.dim('Password:')} {'•' * 12}")
    if e.url:    print(f"  {C.dim('URL:     ')} {e.url}")
    if e.tags:   print(f"  {C.dim('Tags:    ')} {', '.join(e.tags)}")
    if e.notes:  print(f"  {C.dim('Notes:   ')} {e.notes}")
    if e.totp_secret:
        try:
            code = totp_now(e.totp_secret)
            remaining = totp_seconds_remaining()
            print(f"  {C.dim('TOTP:    ')} {C.green(code)} {C.dim(f'({remaining}s left)')}")
        except ValueError as err:
            print(f"  {C.dim('TOTP:    ')} {C.red(str(err))}")
    if e.history:
        print(f"  {C.dim('History: ')} {len(e.history)} previous password(s)")
    print(f"  {C.dim(f'Created: {time.ctime(e.created_at)}')}")
    print(f"  {C.dim(f'Updated: {time.ctime(e.updated_at)}')}")
    print()


# =============================================================================
# Unlock flow with lockout
# =============================================================================

def unlock_or_create(vault: Vault) -> bool:
    if not vault.exists():
        print(C.cyan("No vault found. Let's create one."))
        if ARGON2_AVAILABLE:
            print(C.dim("Using Argon2id for key derivation."))
        else:
            print(C.dim("Using PBKDF2 (install argon2-cffi for stronger Argon2id)."))
        while True:
            pw1 = prompt_secret("Choose a master password")
            if not pw1:
                return False
            if len(pw1) < 10:
                print(C.yellow("At least 10 characters please."))
                continue
            bits = password_entropy_bits(pw1)
            print(C.dim(f"  Strength: {bits:.0f} bits — {strength_label(bits)}"))
            if bits < 50 and not prompt_yn("That's not very strong. Use it anyway?"):
                continue
            pw2 = prompt_secret("Confirm master password")
            if pw1 != pw2:
                print(C.red("Passwords don't match."))
                continue
            break
        vault.create(pw1)
        print(C.green("Vault created.\n"))
        return True

    # Persistent lockout: failures are recorded on disk, so restarting the
    # program does not reset the cooldown.
    throttle = Throttle(vault.path)
    wait = throttle.seconds_remaining()
    if wait > 0:
        LOG.error("unlock refused: lockout active (%ds remaining)", wait)
        print(C.red(f"Locked out after too many failed attempts. Try again in {wait}s."))
        return False

    backoff = 1.0
    for attempt in range(1, MAX_UNLOCK_ATTEMPTS + 1):
        pw = prompt_secret("Master password")
        if not pw:
            return False
        try:
            vault.unlock(pw)
            throttle.reset()
            print(C.green(f"Vault unlocked. {len(vault.entries)} entries.") +
                  C.dim(f" (KDF: {vault.kdf_used})\n"))
            return True
        except IntegrityError as e:
            print(C.red(f"Refusing to unlock: {e}\n"))
            return False
        except InvalidToken:
            fails = throttle.record_failure()
            remaining = MAX_UNLOCK_ATTEMPTS - attempt
            LOG.warning("failed unlock attempt %d/%d (%d on record)",
                        attempt, MAX_UNLOCK_ATTEMPTS, fails)
            print(C.red(f"Wrong password. {remaining} attempt(s) left."))
            if remaining > 0:
                time.sleep(backoff)
                backoff *= 2
        except (ValueError, FileNotFoundError) as e:
            print(C.red(f"Error: {e}"))
            return False
    wait = throttle.seconds_remaining()
    LOG.error("locked out after %d failed attempts", MAX_UNLOCK_ATTEMPTS)
    print(C.red(f"Too many failed attempts. Locked out for {wait}s (persists across restarts)."))
    return False


# =============================================================================
# Commands
# =============================================================================

def cmd_add(vault: Vault, name: Optional[str] = None) -> None:
    if not name:
        name = prompt("Entry name (e.g. github)")
    if not name:
        return
    if name in vault.entries:
        if not prompt_yn(f"'{name}' exists. Overwrite?"):
            return

    e = Entry()
    e.username = prompt("Username/email")
    e.url = prompt("URL")

    if prompt_yn("Generate a password?", default=True):
        length = prompt_int("Length", 20)
        symbols = prompt_yn("Include symbols?", default=True)
        avoid = prompt_yn("Avoid ambiguous chars (Il1O0)?", default=False)
        try:
            e.password = generate_password(
                length=length, use_symbols=symbols, avoid_ambiguous=avoid
            )
            print(C.green(f"  Generated: {e.password}"))
        except ValueError as err:
            print(C.red(f"Error: {err}"))
            return
    else:
        e.password = prompt_secret("Password")
        if not e.password:
            return

    bits = password_entropy_bits(e.password)
    print(C.dim(f"  Strength: {bits:.0f} bits — {strength_label(bits)}"))

    tags_raw = prompt("Tags (comma-separated)")
    e.tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    e.notes = prompt("Notes")

    if prompt_yn("Add a TOTP secret (2FA)?"):
        e.totp_secret = prompt("Base32 secret")

    vault.add(name, e)
    print(C.green(f"Saved '{name}'.\n"))


def cmd_view(vault: Vault, name: Optional[str] = None) -> None:
    if not vault.entries:
        print(C.dim("Vault is empty.\n"))
        return
    if not name:
        name = prompt("Entry name (blank to list all)")
    if not name:
        print(C.bold("\nAll entries:"))
        # Group by tag if any
        by_tag: Dict[str, List[str]] = {}
        untagged = []
        for n, e in vault.entries.items():
            if e.tags:
                for t in e.tags:
                    by_tag.setdefault(t, []).append(n)
            else:
                untagged.append(n)
        for tag in sorted(by_tag):
            print(f"  {C.cyan(tag)}")
            for n in sorted(by_tag[tag]):
                print(f"    • {n}")
        if untagged:
            print(f"  {C.dim('(no tag)')}")
            for n in sorted(untagged):
                print(f"    • {n}")
        print()
        return
    e = vault.entries.get(name)
    if not e:
        print(C.red(f"No entry named '{name}'.\n"))
        return
    print_entry(name, e)
    if CLIPBOARD_AVAILABLE and prompt_yn("Copy password to clipboard?"):
        if copy_with_autoclear(e.password):
            print(C.green(f"Copied. Will clear in {CLIPBOARD_CLEAR_SECONDS}s.\n"))
        else:
            print(C.red("Clipboard copy failed.\n"))


def cmd_search(vault: Vault) -> None:
    if not vault.entries:
        print(C.dim("Vault is empty.\n"))
        return
    query = prompt("Search")
    if not query:
        return
    matches = vault.search(query)
    if not matches:
        print(C.dim("No matches.\n"))
        return
    print(C.bold(f"\n{len(matches)} match(es):"))
    for n in matches:
        e = vault.entries[n]
        tag_str = f" {C.dim('[' + ','.join(e.tags) + ']')}" if e.tags else ""
        print(f"  • {n}{tag_str}")
    print()


def cmd_edit(vault: Vault, name: Optional[str] = None) -> None:
    if not name:
        name = prompt("Entry to edit")
    if not name:
        return
    e = vault.entries.get(name)
    if not e:
        print(C.red(f"No entry named '{name}'.\n"))
        return

    print(C.dim("Press Enter to keep current value."))
    e.username = prompt("Username", e.username)
    e.url = prompt("URL", e.url)

    if prompt_yn("Change password?"):
        # Save the old one to history
        e.history.append({"password": e.password, "changed_at": time.time()})
        # Cap history at 10
        e.history = e.history[-10:]
        if prompt_yn("Generate new?", default=True):
            length = prompt_int("Length", 20)
            try:
                e.password = generate_password(length=length)
                print(C.green(f"  New password: {e.password}"))
            except ValueError as err:
                print(C.red(f"Error: {err}"))
                return
        else:
            new_pw = prompt_secret("New password")
            if new_pw:
                e.password = new_pw

    new_tags = prompt("Tags", ", ".join(e.tags))
    e.tags = [t.strip() for t in new_tags.split(",") if t.strip()]
    e.notes = prompt("Notes", e.notes)
    e.totp_secret = prompt("TOTP secret", e.totp_secret)
    e.updated_at = time.time()

    vault.entries[name] = e
    vault.save()
    print(C.green(f"Updated '{name}'.\n"))


def cmd_delete(vault: Vault, name: Optional[str] = None) -> None:
    if not name:
        name = prompt("Entry to delete")
    if not name or name not in vault.entries:
        print(C.red("No such entry.\n"))
        return
    if not prompt_yn(f"Really delete '{name}'?"):
        return
    vault.delete(name)
    print(C.green(f"Deleted '{name}'.\n"))


def cmd_generate() -> None:
    print(C.bold("Generator:"))
    print("  1) Random password")
    print("  2) Diceware passphrase")
    choice = prompt("Choose", "1")
    if choice == "2":
        words = prompt_int("Number of words", 5)
        sep = prompt("Separator", "-")
        cap = prompt_yn("Capitalize?")
        try:
            pw = generate_passphrase(words=words, separator=sep, capitalize=cap)
        except ValueError as e:
            print(C.red(str(e))); return
    else:
        length = prompt_int("Length", 20)
        symbols = prompt_yn("Include symbols?", default=True)
        avoid = prompt_yn("Avoid ambiguous chars?")
        try:
            pw = generate_password(length=length, use_symbols=symbols, avoid_ambiguous=avoid)
        except ValueError as e:
            print(C.red(str(e))); return

    bits = password_entropy_bits(pw)
    print(C.green(f"\n  {pw}"))
    print(C.dim(f"  Strength: {bits:.0f} bits — {strength_label(bits)}\n"))
    if CLIPBOARD_AVAILABLE and prompt_yn("Copy to clipboard?"):
        if copy_with_autoclear(pw):
            print(C.green(f"Copied. Auto-clear in {CLIPBOARD_CLEAR_SECONDS}s.\n"))


def cmd_audit(vault: Vault, hibp: Optional[bool] = None) -> None:
    """Password health report: reuse, weak, stale — and optional breach check."""
    if not vault.entries:
        print(C.dim("Vault is empty.\n"))
        return

    findings = analyze_entries(vault.entries)
    print(C.bold(f"\nAudit — {len(vault.entries)} entries"))

    if findings["reused"]:
        print(C.red(f"\n  Reused passwords ({len(findings['reused'])} group(s)):"))
        for group in findings["reused"]:
            print(f"    • {', '.join(group)}")
    else:
        print(C.green("\n  ✓ No reused passwords"))

    if findings["weak"]:
        print(C.yellow(f"\n  Weak passwords (< {WEAK_BITS_THRESHOLD} bits):"))
        for name in findings["weak"]:
            bits = password_entropy_bits(vault.entries[name].password)
            print(f"    • {name} ({bits:.0f} bits)")
    else:
        print(C.green("  ✓ No weak passwords"))

    if findings["stale"]:
        print(C.yellow("\n  Not rotated in over a year:"))
        for name in findings["stale"]:
            print(f"    • {name}")
    else:
        print(C.green("  ✓ No stale passwords"))

    # Breach check is opt-in: it sends 5-char SHA-1 prefixes to HIBP (never the
    # password or full hash). Interactive callers get asked; one-shot callers
    # pass --hibp explicitly.
    if hibp is None:
        hibp = prompt_yn(
            "\nCheck against HaveIBeenPwned? (sends only 5-char hash prefixes)"
        )
    if hibp:
        breached: List[Tuple[str, int]] = []
        checked: Dict[str, int] = {}
        for name, e in sorted(vault.entries.items()):
            if not e.password:
                continue
            try:
                if e.password not in checked:
                    checked[e.password] = hibp_breach_count(e.password)
            except Exception as err:
                print(C.red(f"\n  Breach check failed: {err}"))
                break
            if checked[e.password] > 0:
                breached.append((name, checked[e.password]))
        else:
            if breached:
                print(C.red("\n  ⚠ Found in known breaches:"))
                for name, count in breached:
                    print(f"    • {name} — seen {count:,} times")
            else:
                print(C.green("\n  ✓ No passwords found in known breaches"))

    LOG.info("audit run (%d entries)", len(vault.entries))
    print()


def cmd_export(vault: Vault) -> None:
    out = prompt("Export file path", "vault_export.json")
    if not out:
        return
    pw1 = prompt_secret("Export password")
    pw2 = prompt_secret("Confirm")
    if pw1 != pw2 or not pw1:
        print(C.red("Passwords don't match.\n")); return
    vault.export_encrypted(out, pw1)
    print(C.green(f"Exported {len(vault.entries)} entries to {out}\n"))


def cmd_import(vault: Vault) -> None:
    path = prompt("Import file path")
    if not path or not os.path.exists(path):
        print(C.red("File not found.\n")); return
    pw = prompt_secret("Import password")
    merge = prompt_yn("Merge with existing entries?", default=True)
    try:
        n = vault.import_encrypted(path, pw, merge=merge)
        print(C.green(f"Imported {n} entries.\n"))
    except (InvalidToken, ValueError) as e:
        print(C.red(f"Import failed: {e}\n"))


def cmd_change_master(vault: Vault) -> None:
    print(C.yellow("Changing master password will re-encrypt the vault."))
    current = prompt_secret("Current master password")
    try:
        # Verify by re-deriving
        payload = vault.storage.read_payload()
        salt = base64.b64decode(payload["salt"])
        key, _ = derive_key(current, salt, payload.get("kdf", "pbkdf2"))
        decrypt_bytes(payload["vault"].encode("ascii"), key)
    except (InvalidToken, ValueError, FileNotFoundError):
        print(C.red("Wrong password.\n")); return

    new1 = prompt_secret("New master password")
    if len(new1) < 10:
        print(C.yellow("At least 10 characters.\n")); return
    new2 = prompt_secret("Confirm new password")
    if new1 != new2:
        print(C.red("Passwords don't match.\n")); return

    # Re-create vault with new password but same entries
    entries_backup = vault.entries.copy()
    vault.storage.remove()
    vault.create(new1)
    vault.entries = entries_backup
    vault.save()
    LOG.info("master password changed")
    print(C.green("Master password changed.\n"))


# =============================================================================
# Interactive menu
# =============================================================================

MENU = f"""
{C.bold('Commands')}
  {C.cyan('1')}  add         add entry
  {C.cyan('2')}  view        view / list entries
  {C.cyan('3')}  search      search entries
  {C.cyan('4')}  edit        edit entry
  {C.cyan('5')}  delete      delete entry
  {C.cyan('6')}  generate    generate password / passphrase
  {C.cyan('a')}  audit       password health report (reuse / weak / stale / breaches)
  {C.cyan('7')}  export      encrypted export
  {C.cyan('8')}  import      encrypted import
  {C.cyan('9')}  master      change master password
  {C.cyan('l')}  lock        lock vault
  {C.cyan('q')}  quit
"""


def interactive(vault: Vault) -> None:
    while True:
        if vault.is_idle():
            print(C.yellow("\nAuto-locked due to inactivity."))
            vault.lock()
            if not unlock_or_create(vault):
                return

        print(MENU)
        choice = prompt("Choose").lower()
        vault.touch()

        try:
            if choice in ("1", "add"):       cmd_add(vault)
            elif choice in ("2", "view"):    cmd_view(vault)
            elif choice in ("3", "search"):  cmd_search(vault)
            elif choice in ("4", "edit"):    cmd_edit(vault)
            elif choice in ("5", "delete"):  cmd_delete(vault)
            elif choice in ("6", "gen", "generate"): cmd_generate()
            elif choice in ("a", "audit"):   cmd_audit(vault)
            elif choice in ("7", "export"):  cmd_export(vault)
            elif choice in ("8", "import"):  cmd_import(vault)
            elif choice in ("9", "master"):  cmd_change_master(vault)
            elif choice in ("l", "lock"):
                vault.lock()
                print(C.yellow("Locked."))
                if not unlock_or_create(vault):
                    return
            elif choice in ("q", "quit", "exit"):
                vault.lock()
                print("Goodbye.")
                return
            else:
                print(C.red("Unknown command."))
        except Exception as e:
            print(C.red(f"Error: {e}"))


# =============================================================================
# Argument parsing for one-shot commands
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwmanager",
        description="Advanced local password manager",
    )
    p.add_argument("--vault", default=DEFAULT_VAULT_PATH, help="Path to vault file")
    p.add_argument(
        "--backend",
        choices=["json", "sqlite"],
        default="json",
        help="Storage backend: a JSON file (default) or an embedded SQLite DB",
    )
    p.add_argument(
        "--log-file",
        help="Write an audit log (events only, never secrets) to this file",
    )
    p.add_argument(
        "--verbose", action="store_true", help="Also print audit events to stderr"
    )
    sub = p.add_subparsers(dest="command")

    sub.add_parser("add").add_argument("name", nargs="?")
    sub.add_parser("view").add_argument("name", nargs="?")
    sub.add_parser("edit").add_argument("name", nargs="?")
    sub.add_parser("delete").add_argument("name", nargs="?")
    sub.add_parser("search")

    g = sub.add_parser("gen", help="Generate password (no vault needed)")
    g.add_argument("--length", type=int, default=20)
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("--avoid-ambiguous", action="store_true")
    g.add_argument("--passphrase", action="store_true")
    g.add_argument("--words", type=int, default=5)

    audit = sub.add_parser("audit", help="Password health report")
    audit.add_argument(
        "--hibp",
        action="store_true",
        help="Also check passwords against HaveIBeenPwned "
        "(k-anonymity: only 5-char SHA-1 prefixes are sent)",
    )

    icsv = sub.add_parser(
        "import-csv", help="Import a browser/password-manager CSV export"
    )
    icsv.add_argument("path", help="Path to the CSV file")
    icsv.add_argument(
        "--format",
        dest="csv_format",
        choices=sorted(CSV_COLUMN_MAPS),
        default="generic",
        help="Export format (default: generic name/username/password/url/notes)",
    )
    icsv.add_argument(
        "--tag",
        default="imported",
        help="Tag applied to imported entries (use '' for none)",
    )

    sub.add_parser("export")
    sub.add_parser("import")
    sub.add_parser("master")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(getattr(args, "log_file", None), getattr(args, "verbose", False))

    # `gen` is the only command that doesn't need the vault
    if args.command == "gen":
        try:
            if args.passphrase:
                pw = generate_passphrase(words=args.words)
            else:
                pw = generate_password(
                    length=args.length,
                    use_symbols=not args.no_symbols,
                    avoid_ambiguous=args.avoid_ambiguous,
                )
        except ValueError as e:
            print(C.red(str(e)), file=sys.stderr)
            return 1
        print(pw)
        return 0

    print(C.bold(C.cyan("=== Local Password Manager ===")))
    if not CLIPBOARD_AVAILABLE:
        print(C.dim("(install pyperclip for clipboard support)"))
    if not ARGON2_AVAILABLE:
        print(C.dim("(install argon2-cffi for stronger key derivation)"))
    print()

    vault_path = args.vault
    if args.backend == "sqlite" and vault_path == DEFAULT_VAULT_PATH:
        vault_path = os.path.join(os.path.dirname(DEFAULT_VAULT_PATH), "vault.db")

    vault = Vault(vault_path, backend=args.backend)
    if not unlock_or_create(vault):
        return 1

    try:
        if args.command is None:
            interactive(vault)
        elif args.command == "add":      cmd_add(vault, getattr(args, "name", None))
        elif args.command == "view":     cmd_view(vault, getattr(args, "name", None))
        elif args.command == "edit":     cmd_edit(vault, getattr(args, "name", None))
        elif args.command == "delete":   cmd_delete(vault, getattr(args, "name", None))
        elif args.command == "search":   cmd_search(vault)
        elif args.command == "audit":    cmd_audit(vault, getattr(args, "hibp", False))
        elif args.command == "import-csv":
            cmd_import_csv(vault, args.path, args.csv_format, args.tag)
        elif args.command == "export":   cmd_export(vault)
        elif args.command == "import":   cmd_import(vault)
        elif args.command == "master":   cmd_change_master(vault)
    finally:
        vault.lock()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nGoodbye.")
        sys.exit(0)
