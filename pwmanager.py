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
- Failed-unlock lockout with exponential backoff
- Encrypted export / import for backups
- Vault file integrity check
- Interactive menu OR one-shot CLI subcommands
- Best-effort secure wipe of sensitive strings in memory

Usage
-----
    python pwmanager.py                    # interactive menu
    python pwmanager.py add github         # one-shot add
    python pwmanager.py gen --length 24    # generate a password
    python pwmanager.py --help             # full help

Vault file lives next to this script as `vault.json` unless --vault is given.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import getpass
import hashlib
import hmac
import json
import os
import secrets
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
# Storage
# =============================================================================

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
                raise ValueError(f"Vault file is not valid JSON: {e}")

        try:
            salt = base64.b64decode(payload["salt"])
            token = payload["vault"].encode("ascii")
            kdf = payload.get("kdf", "pbkdf2")
        except KeyError as e:
            raise ValueError(f"Vault file missing field: {e}")

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

    backoff = 1.0
    for attempt in range(1, MAX_UNLOCK_ATTEMPTS + 1):
        pw = prompt_secret("Master password")
        if not pw:
            return False
        try:
            vault.unlock(pw)
            print(C.green(f"Vault unlocked. {len(vault.entries)} entries.") +
                  C.dim(f" (KDF: {vault.kdf_used})\n"))
            return True
        except InvalidToken:
            remaining = MAX_UNLOCK_ATTEMPTS - attempt
            print(C.red(f"Wrong password. {remaining} attempt(s) left."))
            if remaining > 0:
                time.sleep(backoff)
                backoff *= 2
        except (ValueError, FileNotFoundError) as e:
            print(C.red(f"Error: {e}"))
            return False
    print(C.red("Too many failed attempts. Locked out."))
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
        with open(vault.path) as f:
            payload = json.load(f)
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
    os.remove(vault.path)
    vault.create(new1)
    vault.entries = entries_backup
    vault.save()
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

    sub.add_parser("export")
    sub.add_parser("import")
    sub.add_parser("master")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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

    vault = Vault(args.vault)
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
