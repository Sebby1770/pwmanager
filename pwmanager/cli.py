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
    CLIPBOARD_CLEAR_SECONDS,
    DEFAULT_VAULT_PATH,
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
from pwmanager.models import Entry
from pwmanager.totp import totp_now, totp_seconds_remaining
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

    def clear() -> None:
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
        print(
            f"  {C.dim('Password:')} {e.password}  "
            f"{C.dim(f'({bits:.0f} bits — {strength_label(bits)})')}"
        )
    else:
        print(f"  {C.dim('Password:')} {'•' * 12}")
    if e.url:
        print(f"  {C.dim('URL:     ')} {e.url}")
    if e.tags:
        print(f"  {C.dim('Tags:    ')} {', '.join(e.tags)}")
    if e.notes:
        print(f"  {C.dim('Notes:   ')} {e.notes}")
    if e.totp_secret:
        try:
            code = totp_now(e.totp_secret)
            remaining = totp_seconds_remaining()
            print(
                f"  {C.dim('TOTP:    ')} {C.green(code)} "
                f"{C.dim(f'({remaining}s left)')}"
            )
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
        by_tag: dict = {}
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


def cmd_search(
    vault: Vault,
    query: Optional[str] = None,
    tag: Optional[str] = None,
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
            print(C.green(f"Copied. Auto-clear in {CLIPBOARD_CLEAR_SECONDS}s.\n"))


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


def cmd_audit(vault: Vault) -> None:
    report = audit_vault(vault)
    print_audit_report(report)


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
  {C.cyan('a')}  audit       security audit & health score
  {C.cyan('c')}  import-csv  import from Bitwarden/Chrome CSV
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
            print(
                f"\n{C.dim('Password health:')} "
                f"{health_score_color(report.health_score)}"
                f"{C.dim(f'  ({report.total_entries} entries)')}"
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
                cmd_audit(vault)
            elif choice in ("c", "import-csv", "csv"):
                cmd_import_csv(vault)
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwmanager",
        description="Advanced local password manager (v2)",
    )
    p.add_argument("--vault", default=DEFAULT_VAULT_PATH, help="Path to vault file")
    p.add_argument("--version", action="version", version=f"pwmanager {__version__}")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("add").add_argument("name", nargs="?")
    sub.add_parser("view").add_argument("name", nargs="?")
    sub.add_parser("edit").add_argument("name", nargs="?")
    sub.add_parser("delete").add_argument("name", nargs="?")

    s = sub.add_parser("search", help="Search entries (case-insensitive substring)")
    s.add_argument("query", nargs="?", default=None, help="Search query")
    s.add_argument("--tag", default=None, help="Filter by tag")

    g = sub.add_parser("gen", help="Generate password (no vault needed)")
    g.add_argument("--length", type=int, default=20)
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("--avoid-ambiguous", action="store_true")
    g.add_argument("--passphrase", action="store_true")
    g.add_argument("--words", type=int, default=5)

    sub.add_parser("export")
    sub.add_parser("import")
    sub.add_parser("master")
    sub.add_parser("audit", help="Run vault security audit")

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

    print(C.bold(C.cyan(f"=== Local Password Manager v{__version__} ===")))
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
        elif args.command == "add":
            cmd_add(vault, getattr(args, "name", None))
        elif args.command == "view":
            cmd_view(vault, getattr(args, "name", None))
        elif args.command == "edit":
            cmd_edit(vault, getattr(args, "name", None))
        elif args.command == "delete":
            cmd_delete(vault, getattr(args, "name", None))
        elif args.command == "search":
            cmd_search(
                vault,
                query=getattr(args, "query", None),
                tag=getattr(args, "tag", None),
            )
        elif args.command == "export":
            cmd_export(vault)
        elif args.command == "import":
            cmd_import(vault)
        elif args.command == "master":
            cmd_change_master(vault)
        elif args.command == "audit":
            cmd_audit(vault)
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
