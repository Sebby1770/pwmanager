"""CSV and JSON importers for Bitwarden, 1Password, Chrome, Firefox-ish, and generic formats."""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Dict, List, Optional, Tuple

from pwmanager.models import Entry


# Column aliases mapped to canonical fields
_NAME_COLS = ("name", "title", "account", "entry")
_USER_COLS = ("login_username", "username", "user", "login", "email")
_PASS_COLS = ("login_password", "password", "pass", "passwd")
_URL_COLS = ("login_uri", "url", "uri", "hostname", "website")
_NOTES_COLS = ("notes", "note", "extra", "comments")
_TOTP_COLS = ("login_totp", "totp_secret", "totp", "otp", "otpauth", "two_factor_secret")


def _norm_header(h: str) -> str:
    return (h or "").strip().lower().replace(" ", "_")


def _pick(row: Dict[str, str], candidates: tuple, strip: bool = True) -> str:
    for c in candidates:
        value = row.get(c) or ""
        if strip:
            value = value.strip()
        if value:
            return value
    return ""


def _fallback_name(url: str, username: str) -> str:
    name = url or username or ""
    if name.startswith("http"):
        name = name.replace("https://", "").replace("http://", "").split("/")[0]
    return name.strip()


def _unique_names(rows: List[Tuple[str, Entry]]) -> List[Tuple[str, Entry]]:
    """Make names unique within one import, never colliding with a literal name.

    The old scheme only remembered base names, so rows "a", "a", "a (2)" came
    out as "a", "a (2)", "a (2)" and the merge silently dropped one entry.
    """
    taken = set()
    out: List[Tuple[str, Entry]] = []
    for name, entry in rows:
        candidate, n = name, 1
        while candidate in taken:
            n += 1
            candidate = f"{name} ({n})"
        taken.add(candidate)
        out.append((candidate, entry))
    return out


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

    rows: List[Tuple[str, Entry]] = []
    for raw in reader:
        # Values are kept verbatim: leading/trailing spaces can be part of a
        # password or a note. Only identifier-like fields are stripped below.
        row = {_norm_header(k): v if isinstance(v, str) else "" for k, v in raw.items() if k is not None}

        username = _pick(row, _USER_COLS)
        password = _pick(row, _PASS_COLS, strip=False)
        url = _pick(row, _URL_COLS)
        notes = _pick(row, _NOTES_COLS, strip=False)
        totp = _pick(row, _TOTP_COLS)
        # Firefox-ish sometimes uses "httpRealm" / "formSubmitURL" — already covered by url
        name = _pick(row, _NAME_COLS) or _fallback_name(url, username) or "imported"

        tags = ["imported", fmt]
        extra_tags = [t.strip() for t in (row.get("tags") or "").split(",") if t.strip()]
        tags.extend(t for t in extra_tags if t not in tags)

        now = time.time()
        entry = Entry(
            username=username,
            password=password,
            url=url,
            notes=notes,
            totp_secret=totp,
            tags=tags,
            favorite=(row.get("favorite") or "").strip().lower() in {"1", "true", "yes"},
            kind="note" if (row.get("kind") or "").strip().lower() == "note" else "login",
            created_at=now,
            updated_at=now,
        )
        rows.append((name, entry))

    return _unique_names(rows)


def import_csv_file(
    path: str,
    fmt: str = "auto",
) -> List[Tuple[str, Entry]]:
    """Load and parse a CSV (or unencrypted Bitwarden JSON) export from disk."""
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        text = f.read()
    return parse_import_text(text, fmt=fmt)


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


def _as_text(value) -> str:
    return value if isinstance(value, str) else ""


def parse_bitwarden_json(text: str) -> List[Tuple[str, Entry]]:
    """Parse an *unencrypted* Bitwarden JSON export into (name, Entry) pairs.

    Only well-typed fields are used; anything else in the document is ignored
    rather than trusted. Raises ValueError for anything that is not a usable
    export (including password-protected "encrypted": true exports).
    """
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("items"), list):
        raise ValueError("not a Bitwarden JSON export (no items list)")
    if doc.get("encrypted") is True:
        raise ValueError("this Bitwarden export is encrypted; export as unencrypted JSON or CSV")

    rows: List[Tuple[str, Entry]] = []
    now = time.time()
    for item in doc["items"]:
        if not isinstance(item, dict):
            continue
        login = item.get("login") if isinstance(item.get("login"), dict) else {}
        uris = login.get("uris") if isinstance(login.get("uris"), list) else []
        url = next((_as_text(u.get("uri")) for u in uris if isinstance(u, dict) and _as_text(u.get("uri"))), "")
        username = _as_text(login.get("username"))
        password = _as_text(login.get("password"))
        notes = _as_text(item.get("notes"))
        is_note = str(item.get("type")) == "2"
        name = _as_text(item.get("name")).strip() or _fallback_name(url, username)
        if not (name or password or username or notes):
            continue
        entry = Entry(
            username=username.strip(),
            password=password,
            url=url.strip(),
            notes=notes,
            totp_secret=_as_text(login.get("totp")).strip(),
            tags=["imported", "bitwarden"],
            favorite=item.get("favorite") is True,
            kind="note" if is_note else "login",
            created_at=now,
            updated_at=now,
        )
        rows.append((name or "imported", entry))
    return _unique_names(rows)


def parse_import_text(text: str, fmt: str = "auto") -> List[Tuple[str, Entry]]:
    """CSV or Bitwarden JSON, chosen by format or by sniffing the first character."""
    if fmt == "bitwarden-json" or (fmt == "auto" and text.lstrip("﻿ \t\r\n").startswith("{")):
        return parse_bitwarden_json(text.lstrip("﻿"))
    return parse_csv_rows(text, fmt=fmt)
