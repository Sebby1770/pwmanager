"""Interactive menu and argparse CLI for pwmanager."""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import json
import os
import sys
import threading
import time
from typing import List, Optional

from cryptography.fernet import InvalidToken

from pwmanager import __version__
from pwmanager.audit import audit_vault, health_score_color, print_audit_report
from pwmanager.colors import C
from pwmanager.constants import (
    AUTOLOCK_SECONDS,
    CLIPBOARD_CLEAR_SECONDS,
    MAX_UNLOCK_ATTEMPTS,
)
from pwmanager.crypto import ARGON2_AVAILABLE, decrypt_bytes, derive_key
from pwmanager.generators import (
    generate_passphrase,
    generate_password,
    password_entropy_bits,
    strength_label,
)
from pwmanager.importers import import_csv_file, merge_entries
from pwmanager.models import KIND_NOTE, Entry
from pwmanager.profiles import resolve_vault_path
from pwmanager.totp import (
    format_otpauth_box,
    format_totp_line,
    totp_now,
    totp_seconds_remaining,
    totp_uri,
    try_print_qr,
    watch_totp,
)
from pwmanager.vault import Vault

try:
    import pyperclip

    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False


# =============================================================================
# Clipboard with auto-clear
# =============================================================================

_clipboard_timer: Optional[threading.Timer] = None
_clipboard_timeout: int = CLIPBOARD_CLEAR_SECONDS


def set_clipboard_timeout(seconds: int) -> None:
    global _clipboard_timeout
    _clipboard_timeout = max(1, int(seconds))


def copy_with_autoclear(text: str, seconds: Optional[int] = None) -> bool:
    global _clipboard_timer
    if not CLIPBOARD_AVAILABLE:
        return False
    clear_after = _clipboard_timeout if seconds is None else seconds
    try:
        pyperclip.copy(text)
    except Exception:
        return False

    if _clipboard_timer:
        _clipboard_timer.cancel()

    def clear() -> None:
        try:
            current = pyperclip.paste()
            if current == text:
                pyperclip.copy("")
        except Exception:
            pass

    _clipboard_timer = threading.Timer(clear_after, clear)
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
    star = C.yellow("★ ") if e.favorite else ""
    kind_tag = C.dim(" [note]") if e.is_note() else ""
    print(C.bold(C.cyan(f"  {star}{name}{kind_tag}")))
    if e.is_note():
        print(f"  {C.dim('Kind:    ')} note")
        if e.notes:
            print(f"  {C.dim('Notes:   ')}")
            for line in e.notes.splitlines() or [e.notes]:
                print(f"    {line}")
        else:
            print(f"  {C.dim('Notes:   ')} {C.dim('(empty)')}")
        if e.username:
            print(f"  {C.dim('Username:')} {e.username}")
        if e.password and show_password:
            print(f"  {C.dim('Password:')} {e.password}")
        elif e.password:
            print(f"  {C.dim('Password:')} {'•' * 12}")
    else:
        print(f"  {C.dim('Username:')} {e.username}")
        if show_password and e.password:
            bits = password_entropy_bits(e.password)
            print(
                f"  {C.dim('Password:')} {e.password}  "
                f"{C.dim(f'({bits:.0f} bits — {strength_label(bits)})')}"
            )
        elif e.password:
            print(f"  {C.dim('Password:')} {'•' * 12}")
        else:
            print(f"  {C.dim('Password:')} {C.dim('(empty)')}")
        if e.notes:
            print(f"  {C.dim('Notes:   ')} {e.notes}")
    if e.url:
        print(f"  {C.dim('URL:     ')} {e.url}")
    if e.tags:
        print(f"  {C.dim('Tags:    ')} {', '.join(e.tags)}")
    if e.favorite:
        print(f"  {C.dim('Favorite:')} {C.yellow('yes')}")
    if e.totp_secret:
        try:
            code = totp_now(e.totp_secret)
            remaining = totp_seconds_remaining()
            print(
                f"  {C.dim('TOTP:    ')} {C.green(format_totp_line(code, remaining))}"
            )
            uri = totp_uri(e.totp_secret, name)
            print(f"  {C.dim('otpauth: ')} {uri}")
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
            print(
                C.green(f"Vault unlocked. {len(vault.entries)} entries.")
                + C.dim(f" (KDF: {vault.kdf_used})\n")
            )
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


def cmd_add(
    vault: Vault,
    name: Optional[str] = None,
    *,
    as_note: bool = False,
    gen: bool = False,
    length: int = 20,
    no_symbols: bool = False,
    avoid_ambiguous: bool = False,
    username: Optional[str] = None,
    url: Optional[str] = None,
    notes: Optional[str] = None,
    password: Optional[str] = None,
    non_interactive: bool = False,
) -> None:
    if as_note:
        cmd_add_note(vault, name, notes=notes, non_interactive=non_interactive)
        return

    if not name:
        name = prompt("Entry name (e.g. github)")
    if not name:
        return
    if name in vault.entries:
        if non_interactive:
            print(C.red(f"'{name}' already exists.\n"))
            return
        if not prompt_yn(f"'{name}' exists. Overwrite?"):
            return

    e = Entry(kind="login")

    if non_interactive or gen or username is not None or password is not None:
        # Non-interactive / flag-driven path
        e.username = username or ""
        e.url = url or ""
        e.notes = notes or ""
        if gen or not password:
            try:
                e.password = generate_password(
                    length=length,
                    use_symbols=not no_symbols,
                    avoid_ambiguous=avoid_ambiguous,
                )
            except ValueError as err:
                print(C.red(f"Error: {err}"))
                return
            print(C.green(f"  Generated: {e.password}"))
        else:
            e.password = password
        bits = password_entropy_bits(e.password)
        print(C.dim(f"  Strength: {bits:.0f} bits — {strength_label(bits)}"))
        vault.add(name, e)
        print(C.green(f"Saved '{name}'.\n"))
        return

    e.username = prompt("Username/email")
    e.url = prompt("URL")

    if prompt_yn("Generate a password?", default=True):
        length = prompt_int("Length", length)
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

    if prompt_yn("Pin as favorite?"):
        e.favorite = True

    vault.add(name, e)
    print(C.green(f"Saved '{name}'.\n"))


def cmd_add_note(
    vault: Vault,
    name: Optional[str] = None,
    *,
    notes: Optional[str] = None,
    non_interactive: bool = False,
) -> None:
    """Add a secure note entry (notes field primary; username/password optional)."""
    if not name:
        name = prompt("Note name")
    if not name:
        return
    if name in vault.entries:
        if non_interactive:
            print(C.red(f"'{name}' already exists.\n"))
            return
        if not prompt_yn(f"'{name}' exists. Overwrite?"):
            return

    e = Entry(kind=KIND_NOTE)
    if notes is not None and non_interactive:
        e.notes = notes
    else:
        if notes:
            e.notes = notes
        else:
            print(C.dim("Enter note text (end with a single '.' on its own line):"))
            lines: List[str] = []
            try:
                while True:
                    line = input()
                    if line.strip() == ".":
                        break
                    lines.append(line)
            except (EOFError, KeyboardInterrupt):
                print()
            e.notes = "\n".join(lines)
        if not non_interactive:
            if prompt_yn("Add optional username?"):
                e.username = prompt("Username")
            if prompt_yn("Add optional password?"):
                e.password = prompt_secret("Password")
            tags_raw = prompt("Tags (comma-separated)")
            e.tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
            if prompt_yn("Pin as favorite?"):
                e.favorite = True

    vault.add(name, e)
    print(C.green(f"Saved note '{name}'.\n"))


def cmd_view(vault: Vault, name: Optional[str] = None) -> None:
    if not vault.entries:
        print(C.dim("Vault is empty.\n"))
        return
    if not name:
        name = prompt("Entry name (blank to list all)")
    if not name:
        print(C.bold("\nAll entries:"))
        favs = vault.favorites()
        if favs:
            print(f"  {C.yellow('★ favorites')}")
            for n in favs:
                e = vault.entries[n]
                tag = C.dim(" [note]") if e.is_note() else ""
                print(f"    • {C.yellow(n)}{tag}")
        notes = sorted(n for n, e in vault.entries.items() if e.is_note() and not e.favorite)
        if notes:
            print(f"  {C.cyan('notes')}")
            for n in notes:
                print(f"    • {n} {C.dim('[note]')}")
        by_tag: dict = {}
        untagged = []
        for n, e in vault.entries.items():
            if e.favorite or e.is_note():
                continue  # already listed
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
        # Try fuzzy suggestion
        fuzzy = vault.fuzzy_search(name, limit=5, cutoff=0.45)
        print(C.red(f"No entry named '{name}'."))
        if fuzzy:
            print(C.dim("Did you mean:"))
            for n, score in fuzzy:
                print(f"  • {n} {C.dim(f'({score:.0%})')}")
        print()
        return
    print_entry(name, e)
    if e.password and CLIPBOARD_AVAILABLE and prompt_yn("Copy password to clipboard?"):
        if copy_with_autoclear(e.password):
            print(C.green(f"Copied. Will clear in {_clipboard_timeout}s.\n"))
        else:
            print(C.red("Clipboard copy failed.\n"))


def cmd_search(
    vault: Vault,
    query: Optional[str] = None,
    tag: Optional[str] = None,
    fuzzy: bool = True,
) -> None:
    if not vault.entries:
        print(C.dim("Vault is empty.\n"))
        return
    if query is None and tag is None:
        query = prompt("Search")
        if not query:
            tag_prompt = prompt("Filter by tag (optional)")
            tag = tag_prompt or None
            if not tag:
                return
    if not query and not tag:
        print(C.dim("Provide a search query and/or --tag.\n"))
        return

    matches = vault.search(query or "", tag=tag)
    if matches:
        print(C.bold(f"\n{len(matches)} exact match(es):"))
        for n in matches:
            e = vault.entries[n]
            star = C.yellow("★ ") if e.favorite else ""
            kind = C.dim(" [note]") if e.is_note() else ""
            tag_str = f" {C.dim('[' + ','.join(e.tags) + ']')}" if e.tags else ""
            print(f"  • {star}{n}{kind}{tag_str}")
    else:
        print(C.dim("\nNo exact matches."))

    # Fuzzy secondary section when query present and fuzzy enabled
    if fuzzy and query:
        fuzzy_hits = vault.fuzzy_search(
            query, tag=tag, limit=10, cutoff=0.4, exclude=matches
        )
        if fuzzy_hits:
            print(C.bold(f"\nFuzzy matches (ranked):"))
            for n, score in fuzzy_hits:
                e = vault.entries[n]
                star = C.yellow("★ ") if e.favorite else ""
                kind = C.dim(" [note]") if e.is_note() else ""
                tag_str = f" {C.dim('[' + ','.join(e.tags) + ']')}" if e.tags else ""
                print(f"  • {star}{n}{kind}{tag_str}  {C.dim(f'score={score:.2f}')}")
        elif not matches:
            print(C.dim("No fuzzy matches either."))
    print()


def cmd_pin(vault: Vault, name: Optional[str] = None) -> None:
    if not name:
        name = prompt("Entry to pin")
    if not name:
        return
    if name not in vault.entries:
        print(C.red(f"No entry named '{name}'.\n"))
        return
    vault.pin(name)
    print(C.green(f"Pinned '{name}' as favorite.\n"))


def cmd_unpin(vault: Vault, name: Optional[str] = None) -> None:
    if not name:
        name = prompt("Entry to unpin")
    if not name:
        return
    if name not in vault.entries:
        print(C.red(f"No entry named '{name}'.\n"))
        return
    vault.unpin(name)
    print(C.green(f"Unpinned '{name}'.\n"))


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
        e.history.append({"password": e.password, "changed_at": time.time()})
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
    if prompt_yn("Favorite / pinned?", default=e.favorite):
        e.favorite = True
    else:
        e.favorite = False
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
            print(C.red(str(e)))
            return
    else:
        length = prompt_int("Length", 20)
        symbols = prompt_yn("Include symbols?", default=True)
        avoid = prompt_yn("Avoid ambiguous chars?")
        try:
            pw = generate_password(
                length=length, use_symbols=symbols, avoid_ambiguous=avoid
            )
        except ValueError as e:
            print(C.red(str(e)))
            return

    bits = password_entropy_bits(pw)
    print(C.green(f"\n  {pw}"))
    print(C.dim(f"  Strength: {bits:.0f} bits — {strength_label(bits)}\n"))
    if CLIPBOARD_AVAILABLE and prompt_yn("Copy to clipboard?"):
        if copy_with_autoclear(pw):
            print(C.green(f"Copied. Auto-clear in {_clipboard_timeout}s.\n"))


def cmd_export(vault: Vault) -> None:
    out = prompt("Export file path", "vault_export.json")
    if not out:
        return
    pw1 = prompt_secret("Export password")
    pw2 = prompt_secret("Confirm")
    if pw1 != pw2 or not pw1:
        print(C.red("Passwords don't match.\n"))
        return
    vault.export_encrypted(out, pw1)
    print(C.green(f"Exported {len(vault.entries)} entries to {out}\n"))


def cmd_export_csv(
    vault: Vault,
    path: Optional[str] = None,
    i_understand: bool = False,
) -> None:
    print(C.red(C.bold("WARNING: CSV export writes passwords and TOTP secrets in PLAINTEXT.")))
    print(C.yellow("Anyone with the file can read all credentials. Prefer encrypted export."))
    if not i_understand:
        confirm = prompt('Type YES (all caps) to confirm plaintext export')
        if confirm != "YES":
            print(C.dim("Export cancelled.\n"))
            return
    if not path:
        path = prompt("CSV file path", "vault_export.csv")
    if not path:
        return
    try:
        n = vault.export_csv(path)
    except OSError as e:
        print(C.red(f"Export failed: {e}\n"))
        return
    print(C.green(f"Wrote {n} entries to {path}"))
    print(C.red("Remember: this file is unencrypted. Delete it when done.\n"))


def cmd_import(vault: Vault) -> None:
    path = prompt("Import file path")
    if not path or not os.path.exists(path):
        print(C.red("File not found.\n"))
        return
    pw = prompt_secret("Import password")
    merge = prompt_yn("Merge with existing entries?", default=True)
    try:
        n = vault.import_encrypted(path, pw, merge=merge)
        print(C.green(f"Imported {n} entries.\n"))
    except (InvalidToken, ValueError) as e:
        print(C.red(f"Import failed: {e}\n"))


def cmd_import_csv(
    vault: Vault,
    path: Optional[str] = None,
    fmt: str = "auto",
    on_conflict: str = "skip",
) -> None:
    if not path:
        path = prompt("CSV file path")
    if not path or not os.path.exists(path):
        print(C.red("File not found.\n"))
        return
    try:
        imported = import_csv_file(path, fmt=fmt)
    except (OSError, ValueError, csv.Error) as e:
        print(C.red(f"CSV import failed: {e}\n"))
        return

    if not imported:
        print(C.dim("No entries found in CSV.\n"))
        return

    added, overwritten, skipped = merge_entries(
        vault.entries, imported, on_conflict=on_conflict
    )
    vault.save()
    print(
        C.green(
            f"CSV import complete: {added} added, {overwritten} overwritten, "
            f"{skipped} skipped ({len(imported)} rows parsed).\n"
        )
    )


def cmd_change_master(vault: Vault) -> None:
    print(C.yellow("Changing master password will re-encrypt the vault."))
    current = prompt_secret("Current master password")
    try:
        with open(vault.path) as f:
            payload = json.load(f)
        salt = base64.b64decode(payload["salt"])
        key, _ = derive_key(current, salt, payload.get("kdf", "pbkdf2"))
        decrypt_bytes(payload["vault"].encode("ascii"), key)
    except (InvalidToken, ValueError, FileNotFoundError, KeyError):
        print(C.red("Wrong password.\n"))
        return

    new1 = prompt_secret("New master password")
    if len(new1) < 10:
        print(C.yellow("At least 10 characters.\n"))
        return
    new2 = prompt_secret("Confirm new password")
    if new1 != new2:
        print(C.red("Passwords don't match.\n"))
        return

    entries_backup = vault.entries.copy()
    os.remove(vault.path)
    vault.create(new1)
    vault.entries = entries_backup
    vault.save()
    print(C.green("Master password changed.\n"))


def cmd_audit(vault: Vault, *, check_hibp: bool = False) -> None:
    if check_hibp:
        print(C.dim("Running HIBP k-anonymity check (only SHA-1 hash prefix is sent)..."))
    report = audit_vault(vault, check_hibp=check_hibp)
    print_audit_report(report)


def cmd_history(vault: Vault, name: Optional[str] = None) -> None:
    """Show password history for an entry; optionally restore a previous password."""
    if not name:
        name = prompt("Entry name")
    if not name:
        return
    e = vault.entries.get(name)
    if not e:
        print(C.red(f"No entry named '{name}'.\n"))
        return
    if not e.history:
        print(C.dim(f"No password history for '{name}'.\n"))
        return

    print()
    print(C.bold(C.cyan(f"=== Password history: {name} ===")))
    print(C.dim(f"Current password: {'•' * min(12, max(4, len(e.password) or 4))}"))
    print()
    for i, item in enumerate(e.history, start=1):
        pw = item.get("password", "")
        ts = item.get("changed_at", 0)
        when = time.ctime(ts) if ts else "unknown"
        # Reveal previous passwords only in the history browser (unlocked vault)
        print(f"  {C.cyan(str(i))}) {C.dim(when)}")
        print(f"     {pw}")
    print()

    if not prompt_yn("Restore a previous password?"):
        return
    idx_raw = prompt("History number to restore")
    try:
        idx = int(idx_raw)
    except (TypeError, ValueError):
        print(C.red("Invalid number.\n"))
        return
    if idx < 1 or idx > len(e.history):
        print(C.red("Out of range.\n"))
        return
    old = e.history[idx - 1]
    old_pw = old.get("password", "")
    if not old_pw:
        print(C.red("That history entry has no password.\n"))
        return
    if not prompt_yn(f"Replace current password with history #{idx}?"):
        return
    # Push current into history before restore
    if e.password:
        e.history.append({"password": e.password, "changed_at": time.time()})
        e.history = e.history[-10:]
    e.password = old_pw
    e.updated_at = time.time()
    vault.entries[name] = e
    vault.save()
    print(C.green(f"Restored password from history #{idx} for '{name}'.\n"))


def cmd_totp(
    vault: Vault,
    name: Optional[str] = None,
    *,
    watch: bool = False,
    show_uri: bool = True,
) -> None:
    """Show current TOTP code, optional live --watch mode, and otpauth URI."""
    if not name:
        name = prompt("Entry name")
    if not name:
        return
    e = vault.entries.get(name)
    if not e:
        print(C.red(f"No entry named '{name}'.\n"))
        return
    if not e.totp_secret:
        print(C.red(f"'{name}' has no TOTP secret.\n"))
        return
    try:
        if watch:
            print(C.dim(f"Live TOTP for '{name}' (Ctrl+C to stop)"))
            watch_totp(e.totp_secret)
            return
        code = totp_now(e.totp_secret)
        rem = totp_seconds_remaining()
        print()
        print(C.bold(C.cyan(f"  TOTP — {name}")))
        print(f"  {C.green(format_totp_line(code, rem))}")
        if show_uri:
            uri = totp_uri(e.totp_secret, name)
            print()
            print(format_otpauth_box(uri))
            try_print_qr(uri)
        print()
    except ValueError as err:
        print(C.red(f"TOTP error: {err}\n"))


def cmd_stats(vault: Vault) -> None:
    s = vault.stats()
    print()
    print(C.bold(C.cyan("=== Vault Stats ===")))
    print(f"  Entries:     {s['total_entries']}")
    print(f"  Logins:      {s.get('logins', s['total_entries'])}")
    print(f"  Notes:       {s.get('notes', 0)}")
    print(f"  Favorites:   {s['favorites']}")
    print(f"  With TOTP:   {s['with_totp']}")
    print(f"  Without TOTP:{s['without_totp']}")
    print(f"  Health score:{health_score_color(s['health_score'])}")
    if s["tags"]:
        print(C.bold("  Tags:"))
        for tag, count in s["tags"].items():
            print(f"    • {tag}: {count}")
    else:
        print(f"  Tags:        {C.dim('(none)')}")
    if s["oldest_updated"]:
        o = s["oldest_updated"]
        print(f"  Oldest update: {o['name']} ({time.ctime(o['updated_at'])})")
    if s["newest_updated"]:
        n = s["newest_updated"]
        print(f"  Newest update: {n['name']} ({time.ctime(n['updated_at'])})")
    print()


def cmd_completions(shell: str) -> int:
    """Print a shell completion script for bash or zsh."""
    commands = [
        "add",
        "add-note",
        "view",
        "search",
        "edit",
        "delete",
        "pin",
        "unpin",
        "gen",
        "export",
        "export-csv",
        "import",
        "import-csv",
        "master",
        "audit",
        "history",
        "totp",
        "stats",
        "completions",
    ]
    if shell == "bash":
        script = f"""# pwmanager bash completion — eval "$(pwmanager completions bash)"
_pwmanager_completions() {{
  local cur prev
  COMPREPLY=()
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"
  local cmds="{' '.join(commands)}"
  local opts="--vault --profile --version --clipboard-timeout --lock-timeout --help"

  if [[ ${{COMP_CWORD}} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${{cmds}} ${{opts}}" -- "${{cur}}") )
    return 0
  fi
  case "${{prev}}" in
    completions)
      COMPREPLY=( $(compgen -W "bash zsh" -- "${{cur}}") )
      ;;
    --vault|export-csv|import-csv)
      COMPREPLY=( $(compgen -f -- "${{cur}}") )
      ;;
    search)
      COMPREPLY=( $(compgen -W "--tag --fuzzy --no-fuzzy" -- "${{cur}}") )
      ;;
    audit)
      COMPREPLY=( $(compgen -W "--hibp" -- "${{cur}}") )
      ;;
    totp)
      COMPREPLY=( $(compgen -W "--watch" -- "${{cur}}") )
      ;;
    add)
      COMPREPLY=( $(compgen -W "--gen --note --length --no-symbols" -- "${{cur}}") )
      ;;
    *)
      COMPREPLY=()
      ;;
  esac
}}
complete -F _pwmanager_completions pwmanager
"""
        print(script)
        return 0
    if shell == "zsh":
        script = f"""#compdef pwmanager
# pwmanager zsh completion — eval "$(pwmanager completions zsh)"
_pwmanager() {{
  local -a cmds
  cmds=(
    'add:add entry'
    'add-note:add secure note'
    'view:view / list entries'
    'search:search entries (exact + fuzzy)'
    'edit:edit entry'
    'delete:delete entry'
    'pin:pin entry as favorite'
    'unpin:unpin favorite'
    'gen:generate password / passphrase'
    'export:encrypted export'
    'export-csv:plaintext CSV export (dangerous)'
    'import:encrypted import'
    'import-csv:import from CSV'
    'master:change master password'
    'audit:security audit'
    'history:password history browser'
    'totp:show / watch TOTP code'
    'stats:vault statistics'
    'completions:print shell completions'
  )
  _arguments \\
    '--vault[Path to vault file]:file:_files' \\
    '--profile[Named vault profile]:profile:' \\
    '--clipboard-timeout[Clipboard clear seconds]:seconds:' \\
    '--lock-timeout[Idle lock seconds]:seconds:' \\
    '--version[Show version]' \\
    '--help[Show help]' \\
    '1:command:->cmds' \\
    '*::arg:->args'

  case $state in
    cmds)
      _describe 'command' cmds
      ;;
    args)
      case $words[1] in
        completions)
          _values 'shell' bash zsh
          ;;
        export-csv|import-csv)
          _files
          ;;
        search)
          _arguments '--tag[Filter by tag]:tag:' '--fuzzy' '--no-fuzzy'
          ;;
        audit)
          _arguments '--hibp[Check passwords against Have I Been Pwned]'
          ;;
        totp)
          _arguments '--watch[Live refresh until Ctrl+C]'
          ;;
        add)
          _arguments '--gen[Generate password]' '--note[Create secure note]' \\
            '--length[Password length]:len:' '--no-symbols'
          ;;
      esac
      ;;
  esac
}}
_pwmanager
"""
        print(script)
        return 0
    print(C.red(f"Unknown shell: {shell}. Use bash or zsh."), file=sys.stderr)
    return 1


# =============================================================================
# Interactive menu
# =============================================================================

MENU = f"""
{C.bold('Commands')}
  {C.cyan('1')}  add         add entry
  {C.cyan('2')}  view        view / list entries
  {C.cyan('3')}  search      search entries (exact + fuzzy)
  {C.cyan('4')}  edit        edit entry
  {C.cyan('5')}  delete      delete entry
  {C.cyan('6')}  generate    generate password / passphrase
  {C.cyan('7')}  export      encrypted export
  {C.cyan('8')}  import      encrypted import
  {C.cyan('9')}  master      change master password
  {C.cyan('a')}  audit       security audit & health score
  {C.cyan('h')}  hibp        audit + HIBP breach check (network)
  {C.cyan('n')}  add-note    add secure note
  {C.cyan('y')}  history     password history browser
  {C.cyan('t')}  totp        show / watch TOTP code
  {C.cyan('c')}  import-csv  import from Bitwarden/Chrome CSV
  {C.cyan('e')}  export-csv  plaintext CSV export (dangerous)
  {C.cyan('p')}  pin         pin entry as favorite
  {C.cyan('u')}  unpin       unpin favorite
  {C.cyan('s')}  stats       vault statistics
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

        # Health score banner
        if vault.entries:
            report = audit_vault(vault)
            fav_n = sum(1 for e in vault.entries.values() if e.favorite)
            fav_str = f", {fav_n} ★" if fav_n else ""
            print(
                f"\n{C.dim('Password health:')} "
                f"{health_score_color(report.health_score)}"
                f"{C.dim(f'  ({report.total_entries} entries{fav_str})')}"
            )
        else:
            print(f"\n{C.dim('Password health:')} {C.green('100/100')} {C.dim('(empty)')}")

        print(MENU)
        choice = prompt("Choose").lower()
        vault.touch()

        try:
            if choice in ("1", "add"):
                cmd_add(vault)
            elif choice in ("2", "view"):
                cmd_view(vault)
            elif choice in ("3", "search"):
                cmd_search(vault)
            elif choice in ("4", "edit"):
                cmd_edit(vault)
            elif choice in ("5", "delete"):
                cmd_delete(vault)
            elif choice in ("6", "gen", "generate"):
                cmd_generate()
            elif choice in ("7", "export"):
                cmd_export(vault)
            elif choice in ("8", "import"):
                cmd_import(vault)
            elif choice in ("9", "master"):
                cmd_change_master(vault)
            elif choice in ("a", "audit"):
                cmd_audit(vault, check_hibp=False)
            elif choice in ("h", "hibp"):
                cmd_audit(vault, check_hibp=True)
            elif choice in ("n", "add-note", "note"):
                cmd_add_note(vault)
            elif choice in ("y", "history"):
                cmd_history(vault)
            elif choice in ("t", "totp"):
                name = prompt("Entry name")
                watch = prompt_yn("Live watch mode?")
                cmd_totp(vault, name or None, watch=watch)
            elif choice in ("c", "import-csv", "csv"):
                cmd_import_csv(vault)
            elif choice in ("e", "export-csv"):
                cmd_export_csv(vault)
            elif choice in ("p", "pin"):
                cmd_pin(vault)
            elif choice in ("u", "unpin"):
                cmd_unpin(vault)
            elif choice in ("s", "stats"):
                cmd_stats(vault)
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
# Argument parsing
# =============================================================================


def default_vault_path(
    vault_arg: Optional[str] = None,
    profile_arg: Optional[str] = None,
) -> str:
    """Resolve vault path from --vault, --profile / PWMANAGER_PROFILE, or env."""
    return resolve_vault_path(vault_arg=vault_arg, profile_arg=profile_arg)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwmanager",
        description="Advanced local password manager (v2.2)",
    )
    p.add_argument(
        "--vault",
        default=None,
        help="Path to vault file (default: $PWMANAGER_VAULT or ./vault.json)",
    )
    p.add_argument(
        "--profile",
        default=None,
        metavar="NAME",
        help=(
            "Named vault profile (loads ~/.config/pwmanager/NAME.vault.json "
            "or path from profiles.json). Also: $PWMANAGER_PROFILE"
        ),
    )
    p.add_argument("--version", action="version", version=f"pwmanager {__version__}")
    p.add_argument(
        "--clipboard-timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help=f"Clipboard auto-clear seconds (default: {CLIPBOARD_CLEAR_SECONDS})",
    )
    p.add_argument(
        "--lock-timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help=f"Idle auto-lock seconds (default: {AUTOLOCK_SECONDS})",
    )
    sub = p.add_subparsers(dest="command")

    add_p = sub.add_parser("add", help="Add a login entry")
    add_p.add_argument("name", nargs="?")
    add_p.add_argument(
        "--note",
        action="store_true",
        help="Create a secure note instead of a login",
    )
    add_p.add_argument(
        "--gen",
        action="store_true",
        help="Auto-generate password (non-interactive)",
    )
    add_p.add_argument("--length", type=int, default=20, help="Generated password length")
    add_p.add_argument("--no-symbols", action="store_true")
    add_p.add_argument("--avoid-ambiguous", action="store_true")
    add_p.add_argument("--username", default=None, help="Username (with --gen)")
    add_p.add_argument("--url", default=None, help="URL (with --gen)")
    add_p.add_argument("--notes", default=None, help="Notes text")
    add_p.add_argument(
        "--password",
        default=None,
        help="Set password explicitly (prefer --gen)",
    )

    an = sub.add_parser("add-note", help="Add a secure note entry")
    an.add_argument("name", nargs="?")
    an.add_argument("--notes", default=None, help="Note body (non-interactive)")

    sub.add_parser("view").add_argument("name", nargs="?")
    sub.add_parser("edit").add_argument("name", nargs="?")
    sub.add_parser("delete").add_argument("name", nargs="?")

    pin_p = sub.add_parser("pin", help="Pin entry as favorite")
    pin_p.add_argument("name", nargs="?")
    unpin_p = sub.add_parser("unpin", help="Unpin favorite entry")
    unpin_p.add_argument("name", nargs="?")

    s = sub.add_parser("search", help="Search entries (exact + fuzzy)")
    s.add_argument("query", nargs="?", default=None, help="Search query")
    s.add_argument("--tag", default=None, help="Filter by tag")
    s.add_argument(
        "--fuzzy",
        dest="fuzzy",
        action="store_true",
        default=True,
        help="Include fuzzy secondary results (default)",
    )
    s.add_argument(
        "--no-fuzzy",
        dest="fuzzy",
        action="store_false",
        help="Disable fuzzy matches",
    )

    g = sub.add_parser("gen", help="Generate password (no vault needed)")
    g.add_argument("--length", type=int, default=20)
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("--avoid-ambiguous", action="store_true")
    g.add_argument("--passphrase", action="store_true")
    g.add_argument("--words", type=int, default=5)

    sub.add_parser("export")
    ec = sub.add_parser(
        "export-csv",
        help="Export vault as PLAINTEXT CSV (dangerous — requires confirmation)",
    )
    ec.add_argument("path", nargs="?", default=None, help="Output CSV path")
    ec.add_argument(
        "--i-understand",
        action="store_true",
        help="Skip interactive YES confirmation (for scripts)",
    )

    sub.add_parser("import")
    sub.add_parser("master")

    audit_p = sub.add_parser("audit", help="Run vault security audit")
    audit_p.add_argument(
        "--hibp",
        action="store_true",
        help=(
            "Optional: check passwords via Have I Been Pwned k-anonymity API "
            "(sends only first 5 hex chars of SHA-1; never the full password)"
        ),
    )

    hist_p = sub.add_parser("history", help="Browse / restore password history")
    hist_p.add_argument("name", nargs="?")

    totp_p = sub.add_parser("totp", help="Show TOTP code (optionally live watch)")
    totp_p.add_argument("name", nargs="?")
    totp_p.add_argument(
        "--watch",
        action="store_true",
        help="Refresh code every second until Ctrl+C",
    )

    sub.add_parser("stats", help="Show vault statistics")

    ic = sub.add_parser("import-csv", help="Import entries from CSV")
    ic.add_argument("file", help="Path to CSV file")
    ic.add_argument(
        "--format",
        choices=["auto", "bitwarden", "chrome", "generic"],
        default="auto",
        dest="csv_format",
        help="CSV format (default: auto-detect)",
    )
    ic.add_argument(
        "--on-conflict",
        choices=["skip", "overwrite"],
        default="skip",
        help="What to do when entry name already exists",
    )

    comp = sub.add_parser("completions", help="Print shell completion script")
    comp.add_argument(
        "shell",
        choices=["bash", "zsh"],
        help="Shell to generate completions for",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.clipboard_timeout is not None:
        set_clipboard_timeout(args.clipboard_timeout)

    # Completions and gen don't need the vault
    if args.command == "completions":
        return cmd_completions(args.shell)

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

    print(C.bold(C.cyan(f"=== Local Password Manager v{__version__} ===")))
    if not CLIPBOARD_AVAILABLE:
        print(C.dim("(install pyperclip for clipboard support)"))
    if not ARGON2_AVAILABLE:
        print(C.dim("(install argon2-cffi for stronger key derivation)"))
    print()

    vault_path = default_vault_path(
        vault_arg=getattr(args, "vault", None),
        profile_arg=getattr(args, "profile", None),
    )
    lock_timeout = args.lock_timeout if args.lock_timeout is not None else AUTOLOCK_SECONDS
    vault = Vault(vault_path, lock_timeout=lock_timeout)
    if not unlock_or_create(vault):
        return 1

    try:
        if args.command is None:
            interactive(vault)
        elif args.command == "add":
            gen = bool(getattr(args, "gen", False))
            non_interactive = gen or bool(getattr(args, "password", None))
            cmd_add(
                vault,
                getattr(args, "name", None),
                as_note=bool(getattr(args, "note", False)),
                gen=gen,
                length=int(getattr(args, "length", 20) or 20),
                no_symbols=bool(getattr(args, "no_symbols", False)),
                avoid_ambiguous=bool(getattr(args, "avoid_ambiguous", False)),
                username=getattr(args, "username", None),
                url=getattr(args, "url", None),
                notes=getattr(args, "notes", None),
                password=getattr(args, "password", None),
                non_interactive=non_interactive,
            )
        elif args.command == "add-note":
            notes = getattr(args, "notes", None)
            cmd_add_note(
                vault,
                getattr(args, "name", None),
                notes=notes,
                non_interactive=notes is not None,
            )
        elif args.command == "view":
            cmd_view(vault, getattr(args, "name", None))
        elif args.command == "edit":
            cmd_edit(vault, getattr(args, "name", None))
        elif args.command == "delete":
            cmd_delete(vault, getattr(args, "name", None))
        elif args.command == "pin":
            cmd_pin(vault, getattr(args, "name", None))
        elif args.command == "unpin":
            cmd_unpin(vault, getattr(args, "name", None))
        elif args.command == "search":
            cmd_search(
                vault,
                query=getattr(args, "query", None),
                tag=getattr(args, "tag", None),
                fuzzy=getattr(args, "fuzzy", True),
            )
        elif args.command == "export":
            cmd_export(vault)
        elif args.command == "export-csv":
            cmd_export_csv(
                vault,
                path=getattr(args, "path", None),
                i_understand=getattr(args, "i_understand", False),
            )
        elif args.command == "import":
            cmd_import(vault)
        elif args.command == "master":
            cmd_change_master(vault)
        elif args.command == "audit":
            cmd_audit(vault, check_hibp=bool(getattr(args, "hibp", False)))
        elif args.command == "history":
            cmd_history(vault, getattr(args, "name", None))
        elif args.command == "totp":
            cmd_totp(
                vault,
                getattr(args, "name", None),
                watch=bool(getattr(args, "watch", False)),
            )
        elif args.command == "stats":
            cmd_stats(vault)
        elif args.command == "import-csv":
            cmd_import_csv(
                vault,
                path=args.file,
                fmt=args.csv_format,
                on_conflict=args.on_conflict,
            )
    finally:
        vault.lock()

    return 0

