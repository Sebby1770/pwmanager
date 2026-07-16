"""CSV importers for Bitwarden, Chrome, Firefox-ish, and generic formats."""

from __future__ import annotations

import csv
import io
import time
from typing import Dict, List, Optional, Tuple

from pwmanager.models import Entry


# Column aliases mapped to canonical fields
_NAME_COLS = ("name", "title", "account", "entry")
_USER_COLS = ("login_username", "username", "user", "login", "email")
_PASS_COLS = ("login_password", "password", "pass", "passwd")
_URL_COLS = ("login_uri", "url", "uri", "hostname", "website")
_NOTES_COLS = ("notes", "note", "extra", "comments")
_TOTP_COLS = ("login_totp", "totp", "otp", "otpauth", "two_factor_secret")


def _norm_header(h: str) -> str:
    return (h or "").strip().lower().replace(" ", "_")


def _pick(row: Dict[str, str], candidates: tuple) -> str:
    for c in candidates:
        if c in row and row[c]:
            return row[c].strip()
    return ""


def detect_format(headers: List[str]) -> str:
    """Detect CSV format from header names."""
    hset = {_norm_header(h) for h in headers}
    if "login_username" in hset or "login_password" in hset or "login_uri" in hset:
        return "bitwarden"
    # Chrome: name, url, username, password (often no notes/totp)
    if "url" in hset and "username" in hset and "password" in hset and "name" in hset:
        if "login_uri" not in hset:
            return "chrome"
    return "generic"


def parse_csv_rows(
    text: str,
    fmt: str = "auto",
) -> List[Tuple[str, Entry]]:
    """Parse CSV text into (name, Entry) pairs.

    Formats: auto | bitwarden | chrome | generic
    """
    # Handle BOM
    if text.startswith("\ufeff"):
        text = text[1:]

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV has no header row")

    headers = list(reader.fieldnames)
    if fmt == "auto":
        fmt = detect_format(headers)

    # Normalize keys on each row
    results: List[Tuple[str, Entry]] = []
    seen_names: Dict[str, int] = {}

    for raw in reader:
        row = {_norm_header(k): (v or "").strip() for k, v in raw.items() if k is not None}

        name = _pick(row, _NAME_COLS)
        username = _pick(row, _USER_COLS)
        password = _pick(row, _PASS_COLS)
        url = _pick(row, _URL_COLS)
        notes = _pick(row, _NOTES_COLS)
        totp = _pick(row, _TOTP_COLS)

        # Firefox-ish sometimes uses "httpRealm" / "formSubmitURL" — already covered by url
        if not name:
            # Fall back to url or username as name
            name = url or username or "imported"
            if name.startswith("http"):
                # shorten url for name
                name = name.replace("https://", "").replace("http://", "").split("/")[0]

        if not name and not password and not username:
            continue  # skip empty rows

        # Unique names within this import batch
        base = name
        if name in seen_names:
            seen_names[name] += 1
            name = f"{base} ({seen_names[base]})"
        else:
            seen_names[name] = 1

        now = time.time()
        entry = Entry(
            username=username,
            password=password,
            url=url,
            notes=notes,
            totp_secret=totp,
            tags=["imported", fmt],
            created_at=now,
            updated_at=now,
        )
        results.append((name, entry))

    return results


def import_csv_file(
    path: str,
    fmt: str = "auto",
) -> List[Tuple[str, Entry]]:
    """Load and parse a CSV file from disk."""
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        text = f.read()
    return parse_csv_rows(text, fmt=fmt)


def merge_entries(
    vault_entries: Dict[str, Entry],
    imported: List[Tuple[str, Entry]],
    on_conflict: str = "skip",
) -> Tuple[int, int, int]:
    """Merge imported entries into vault_entries dict in place.

    on_conflict: skip | overwrite

    Returns (added, overwritten, skipped).
    """
    if on_conflict not in ("skip", "overwrite"):
        raise ValueError("on_conflict must be 'skip' or 'overwrite'")

    added = overwritten = skipped = 0
    for name, entry in imported:
        if name in vault_entries:
            if on_conflict == "overwrite":
                vault_entries[name] = entry
                overwritten += 1
            else:
                skipped += 1
        else:
            vault_entries[name] = entry
            added += 1
    return added, overwritten, skipped
